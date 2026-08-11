//! Strict, bounded bootstrap control messages.
//!
//! The transition stream cannot exist until every mandatory replica has loaded and validated the
//! same immutable base. These messages carry the exact persisted anchor into that awaited startup
//! handshake. They are intentionally separate from transition frames: a successful seed ACK does
//! not advance a canonical sequence.

use blake3::Hasher;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    is_zero, validate_block_rlp, BlockDescriptor, CanonicalBlockRlp, DecodeLimits, Hash32,
    RecentBlockHashes, WireError,
};

pub const BOOTSTRAP_SCHEMA_VERSION: u16 = 2;
pub const DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES: usize = 65 * 1024 * 1024;
const BOOTSTRAP_DIGEST_DOMAIN: &[u8] = b"tip-state-bootstrap-message-v2";

/// Exact state source pinned by the trusted Reth initializer while canonical progression is gated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedRequest {
    pub schema_version: u16,
    pub request_id: Hash32,
    pub chain_id: u64,
    pub genesis_hash: Hash32,
    pub snapshot_transaction_id: u64,
    pub anchor: BlockDescriptor,
    pub anchor_block_rlp: CanonicalBlockRlp,
    pub recent_block_hashes: RecentBlockHashes,
}

impl SeedRequest {
    pub fn validate(&self, limits: &DecodeLimits) -> Result<(), BootstrapError> {
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION {
            return Err(BootstrapError::UnsupportedSchema(self.schema_version));
        }
        if is_zero(&self.request_id) {
            return Err(BootstrapError::ZeroRequestId);
        }
        if self.chain_id == 0 {
            return Err(BootstrapError::ZeroChainId);
        }
        if is_zero(&self.genesis_hash) {
            return Err(BootstrapError::ZeroGenesisHash);
        }
        self.anchor.validate().map_err(BootstrapError::Wire)?;
        validate_block_rlp(&self.anchor_block_rlp, limits).map_err(BootstrapError::Wire)?;
        if self.anchor.identity.number == 0 && self.anchor.identity.hash != self.genesis_hash {
            return Err(BootstrapError::GenesisAnchorMismatch);
        }
        self.recent_block_hashes
            .validate_for_tip(&self.anchor.identity, limits)
            .map_err(BootstrapError::Wire)?;
        if self.recent_block_hashes.start_number == 0 &&
            !self.recent_block_hashes.hashes.is_empty() &&
            self.recent_block_hashes.hashes.first() != Some(&self.genesis_hash)
        {
            return Err(BootstrapError::GenesisWindowMismatch);
        }
        Ok(())
    }
}

/// Deterministic logical state counts included in the generation manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedCounts {
    pub accounts: u64,
    pub nonzero_storage_slots: u64,
    pub bytecodes: u64,
    pub bytecode_bytes: u64,
}

/// Positive response emitted only after the complete base is validated and durably checkpointed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedAck {
    pub schema_version: u16,
    pub request_digest: Hash32,
    pub generation_id: Hash32,
    pub counts: SeedCounts,
}

impl SeedAck {
    pub fn validate_for_request(&self, request_digest: Hash32) -> Result<(), BootstrapError> {
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION {
            return Err(BootstrapError::UnsupportedSchema(self.schema_version));
        }
        if self.request_digest != request_digest {
            return Err(BootstrapError::RequestDigestMismatch);
        }
        if is_zero(&self.generation_id) {
            return Err(BootstrapError::ZeroGenerationId);
        }
        Ok(())
    }
}

/// Fail-closed response. Diagnostics are bounded by the enclosing message size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedNack {
    pub schema_version: u16,
    pub request_digest: Hash32,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", deny_unknown_fields)]
pub enum SeedResponse {
    Ack(SeedAck),
    Nack(SeedNack),
}

pub fn encode_message<T: Serialize>(
    message: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, BootstrapError> {
    let bytes = serde_json::to_vec(message).map_err(BootstrapError::Encode)?;
    if bytes.len() > max_bytes {
        return Err(BootstrapError::MessageTooLarge { actual: bytes.len(), max: max_bytes });
    }
    Ok(bytes)
}

pub fn decode_message<T: DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, BootstrapError> {
    if bytes.len() > max_bytes {
        return Err(BootstrapError::MessageTooLarge { actual: bytes.len(), max: max_bytes });
    }
    serde_json::from_slice(bytes).map_err(BootstrapError::Decode)
}

pub fn message_digest(bytes: &[u8]) -> Hash32 {
    let mut hasher = Hasher::new();
    hasher.update(BOOTSTRAP_DIGEST_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("unsupported bootstrap schema {0}")]
    UnsupportedSchema(u16),
    #[error("bootstrap request ID must be nonzero")]
    ZeroRequestId,
    #[error("bootstrap chain ID must be nonzero")]
    ZeroChainId,
    #[error("bootstrap genesis hash must be nonzero")]
    ZeroGenesisHash,
    #[error("genesis anchor hash differs from genesis hash")]
    GenesisAnchorMismatch,
    #[error("genesis-spanning BLOCKHASH window differs from genesis hash")]
    GenesisWindowMismatch,
    #[error("seed ACK request digest mismatch")]
    RequestDigestMismatch,
    #[error("seed generation ID must be nonzero")]
    ZeroGenerationId,
    #[error("bootstrap message size {actual} exceeds maximum {max}")]
    MessageTooLarge { actual: usize, max: usize },
    #[error("bootstrap message encoding failed: {0}")]
    Encode(serde_json::Error),
    #[error("bootstrap message decoding failed: {0}")]
    Decode(serde_json::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockExecutionContext, BlockIdentity, ExecutionFork};

    fn hash(tag: u8) -> Hash32 {
        [tag; 32]
    }

    fn request() -> SeedRequest {
        SeedRequest {
            schema_version: BOOTSTRAP_SCHEMA_VERSION,
            request_id: hash(3),
            chain_id: 1,
            genesis_hash: hash(1),
            snapshot_transaction_id: 9,
            anchor: BlockDescriptor {
                identity: BlockIdentity {
                    number: 2,
                    hash: hash(4),
                    parent_hash: hash(2),
                    state_root: hash(5),
                },
                execution: BlockExecutionContext {
                    active_fork: ExecutionFork::Osaka,
                    timestamp: 24,
                    slot_number: None,
                    fee_recipient: [6; 20],
                    gas_limit: 30_000_000,
                    gas_used: 15_000_000,
                    base_fee_per_gas: hash(7),
                    prev_randao: hash(8),
                    difficulty: [0; 32],
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(1),
                    blob_base_fee: Some(hash(9)),
                    parent_beacon_block_root: Some(hash(10)),
                    withdrawals_root: Some(hash(11)),
                    requests_hash: Some(hash(12)),
                },
            },
            anchor_block_rlp: CanonicalBlockRlp::new(vec![0xc3, 0xc0, 0xc0, 0xc0]),
            recent_block_hashes: RecentBlockHashes {
                start_number: 0,
                hashes: vec![hash(1), hash(2)],
            },
        }
    }

    #[test]
    fn request_and_ack_round_trip_are_bounded_and_bound_by_digest() {
        let request = request();
        request.validate(&DecodeLimits::default()).unwrap();
        let encoded = encode_message(&request, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES).unwrap();
        assert!(String::from_utf8_lossy(&encoded).contains("\"anchor_block_rlp\":\"0xc3c0c0c0\""));
        let digest = message_digest(&encoded);
        let decoded: SeedRequest =
            decode_message(&encoded, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES).unwrap();
        assert_eq!(decoded, request);

        let ack = SeedAck {
            schema_version: BOOTSTRAP_SCHEMA_VERSION,
            request_digest: digest,
            generation_id: hash(13),
            counts: SeedCounts {
                accounts: 1,
                nonzero_storage_slots: 2,
                bytecodes: 3,
                bytecode_bytes: 4,
            },
        };
        ack.validate_for_request(digest).unwrap();
        assert_eq!(
            ack.validate_for_request(hash(99)).unwrap_err().to_string(),
            "seed ACK request digest mismatch"
        );
    }

    #[test]
    fn malformed_or_oversized_messages_fail_closed() {
        assert!(matches!(
            encode_message(&request(), 4),
            Err(BootstrapError::MessageTooLarge { .. })
        ));
        assert!(matches!(
            decode_message::<SeedRequest>(br#"{"unknown":true}"#, 1024),
            Err(BootstrapError::Decode(_))
        ));

        let mut uppercase = serde_json::to_value(request()).unwrap();
        uppercase["anchor_block_rlp"] = serde_json::Value::String("0xC3c0c0c0".to_owned());
        let uppercase = serde_json::to_vec(&uppercase).unwrap();
        assert!(matches!(
            decode_message::<SeedRequest>(&uppercase, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES),
            Err(BootstrapError::Decode(_))
        ));

        let mut missing_prefix = serde_json::to_value(request()).unwrap();
        missing_prefix["anchor_block_rlp"] = serde_json::Value::String("c3c0c0c0".to_owned());
        let missing_prefix = serde_json::to_vec(&missing_prefix).unwrap();
        assert!(matches!(
            decode_message::<SeedRequest>(&missing_prefix, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES),
            Err(BootstrapError::Decode(_))
        ));

        let mut odd_length = serde_json::to_value(request()).unwrap();
        odd_length["anchor_block_rlp"] = serde_json::Value::String("0xc3c".to_owned());
        let odd_length = serde_json::to_vec(&odd_length).unwrap();
        assert!(matches!(
            decode_message::<SeedRequest>(&odd_length, DEFAULT_MAX_BOOTSTRAP_MESSAGE_BYTES),
            Err(BootstrapError::Decode(_))
        ));
    }

    #[test]
    fn empty_or_over_limit_anchor_block_rlp_fails_closed() {
        let mut empty = request();
        empty.anchor_block_rlp = CanonicalBlockRlp::new(Vec::new());
        assert!(matches!(
            empty.validate(&DecodeLimits::default()),
            Err(BootstrapError::Wire(WireError::EmptyCanonicalBlockRlp))
        ));

        let limits = DecodeLimits { max_block_rlp_bytes: 3, ..DecodeLimits::default() };
        assert!(matches!(
            request().validate(&limits),
            Err(BootstrapError::Wire(WireError::LimitExceeded {
                field: "block_rlp_bytes",
                value: 4,
                max: 3,
            }))
        ));

        let mut old_schema = request();
        old_schema.schema_version = 1;
        assert!(matches!(
            old_schema.validate(&DecodeLimits::default()),
            Err(BootstrapError::UnsupportedSchema(1))
        ));
    }
}
