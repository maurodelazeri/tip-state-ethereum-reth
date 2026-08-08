//! Mandatory local-fanout Unix-socket transport and fsynced producer outbox.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Serialize;
use tip_state_wire::{
    bootstrap::{
        decode_message, encode_message, message_digest, SeedAck, SeedRequest, SeedResponse,
        DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES,
    },
    DecodeLimits, Hash32, TransitionAck,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

/// One mandatory local fanout connection. Transport loss is always returned as an error.
#[derive(Debug)]
pub struct ReplicaConnection {
    stream: UnixStream,
    io_timeout: Duration,
    limits: DecodeLimits,
}

impl ReplicaConnection {
    /// Connects to the mandatory local fanout, sends the exact seed request, and awaits its
    /// completed-generation cohort ACK. The fanout compares generation IDs across every active
    /// destination before returning it.
    pub async fn connect_and_seed(
        socket: &Path,
        request: &SeedRequest,
        seed_timeout: Duration,
        live_io_timeout: Duration,
    ) -> eyre::Result<(Self, SeedAck)> {
        eyre::ensure!(!seed_timeout.is_zero(), "seed timeout must be nonzero");
        eyre::ensure!(!live_io_timeout.is_zero(), "live I/O timeout must be nonzero");
        let request_bytes = encode_message(request, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES)?;
        let request_digest = message_digest(&request_bytes);
        let mut stream = timeout(seed_timeout, UnixStream::connect(socket))
            .await
            .map_err(|_| eyre::eyre!("timed out connecting to replica {}", socket.display()))??;
        write_frame(&mut stream, &request_bytes, seed_timeout).await?;
        let response =
            read_frame(&mut stream, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES, seed_timeout).await?;
        let response: SeedResponse =
            decode_message(&response, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES)?;
        let ack = match response {
            SeedResponse::Ack(ack) => ack,
            SeedResponse::Nack(nack) => {
                eyre::bail!("replica rejected seed: {}", nack.reason);
            }
        };
        ack.validate_for_request(request_digest)?;
        Ok((Self { stream, io_timeout: live_io_timeout, limits: DecodeLimits::default() }, ack))
    }

    /// Sends one already-durable transition and waits for the replica's exact durable ACK.
    pub async fn send_transition(&mut self, frame: &[u8]) -> eyre::Result<TransitionAck> {
        eyre::ensure!(
            frame.len() <= self.limits.max_frame_bytes,
            "transition frame exceeds configured maximum"
        );
        write_frame(&mut self.stream, frame, self.io_timeout).await?;
        let response =
            read_frame(&mut self.stream, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES, self.io_timeout)
                .await?;
        decode_message(&response, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES).map_err(Into::into)
    }
}

/// Append-only, fsynced evidence/outbox for one seed generation.
///
/// Frames are retained for the complete seed generation. A process restart performs a full gated
/// reseed; generation retention can therefore be bounded independently of current recovery.
#[derive(Debug)]
pub struct DurableOutbox {
    directory: PathBuf,
}

impl DurableOutbox {
    /// Opens the append-only directory for one nonzero seed generation.
    pub fn open(root: &Path, generation_id: Hash32) -> eyre::Result<Self> {
        eyre::ensure!(generation_id.iter().any(|byte| *byte != 0), "zero generation ID");
        let directory = root.join(alloy_primitives::hex::encode(generation_id));
        fs::create_dir_all(&directory)?;
        File::open(&directory)?.sync_all()?;
        Ok(Self { directory })
    }

    /// Persists an exact frame before any sink sees it. Repeating the same sequence is allowed
    /// only when the bytes are identical.
    pub fn persist_frame(&self, sequence: u64, frame: &[u8]) -> eyre::Result<PathBuf> {
        let path = self.directory.join(format!("{sequence:020}.tipwire"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(frame)?;
                file.sync_all()?;
                File::open(&self.directory)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut existing = Vec::new();
                File::open(&path)?.read_to_end(&mut existing)?;
                eyre::ensure!(existing == frame, "outbox sequence {sequence} byte conflict");
            }
            Err(error) => return Err(error.into()),
        }
        Ok(path)
    }

    /// Atomically advances the durable ACK checkpoint after the fanout's exact cohort ACK matches.
    pub fn persist_ack(&self, ack: &TransitionAck) -> eyre::Result<()> {
        let encoded =
            serde_json::to_vec(&AckCheckpoint { format: "tip-state-producer-ack-v1", ack })?;
        let path = self.directory.join("ack.json");
        let temporary = self.directory.join(format!(".ack.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

#[derive(Serialize)]
struct AckCheckpoint<'a> {
    format: &'static str,
    ack: &'a TransitionAck,
}

async fn write_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    io_timeout: Duration,
) -> eyre::Result<()> {
    eyre::ensure!(!payload.is_empty(), "refusing to write zero-length frame");
    let length = u32::try_from(payload.len())?;
    timeout(io_timeout, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(payload).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| eyre::eyre!("timed out writing mandatory replica frame"))??;
    Ok(())
}

async fn read_frame(
    stream: &mut UnixStream,
    maximum: usize,
    io_timeout: Duration,
) -> eyre::Result<Vec<u8>> {
    timeout(io_timeout, async {
        let length = stream.read_u32().await? as usize;
        if length == 0 || length > maximum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid replica frame length {length}, maximum {maximum}"),
            ));
        }
        let mut payload = Vec::new();
        payload.try_reserve_exact(length).map_err(std::io::Error::other)?;
        payload.resize(length, 0);
        stream.read_exact(&mut payload).await?;
        Ok::<_, std::io::Error>(payload)
    })
    .await
    .map_err(|_| eyre::eyre!("timed out reading mandatory replica ACK"))?
    .map_err(Into::into)
}
