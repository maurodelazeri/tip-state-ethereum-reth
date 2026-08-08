//! Statically linked mainnet Reth with an awaited, fail-stop tip-state ExEx.

use std::{
    env,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_eips::BlockNumHash;
use alloy_primitives::{keccak256, B256};
use futures_util::TryStreamExt;
use reth_db::DatabaseEnv;
use reth_ethereum::{
    chainspec::EthChainSpec,
    exex::{ExExContext, ExExEvent, ExExNotification},
    node::{
        api::{FullNodeComponents, NodeTypes},
        builder::NodeHandleFor,
        EthereumNode,
    },
    EthPrimitives,
};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::Chain;
use tip_state_wire::{AddedBlock, BlockIdentity, DecodeLimits, StreamIdentity};

use example_tip_state_exex::{
    coordinator::{PreparedTransition, ProducerCoordinator},
    normalize_chain,
    producer_io::{DurableOutbox, ReplicaConnection},
    seed_source::capture_seed_request,
    wire::map_added_blocks,
};

#[derive(Clone, Debug)]
struct RuntimeConfig {
    replica_socket: PathBuf,
    outbox_root: PathBuf,
    seed_timeout: Duration,
    io_timeout: Duration,
}

fn main() -> eyre::Result<()> {
    let runtime_config = RuntimeConfig::from_env()?;
    reth_ethereum::cli::Cli::parse_args().run(async move |builder, _| {
        let handle: NodeHandleFor<EthereumNode> = builder
            .node(EthereumNode::default())
            .install_exex("tip-state", async move |ctx| {
                initialize_tip_state(ctx, runtime_config).await
            })
            .launch()
            .await?;
        handle.wait_for_node_exit().await
    })
}

async fn initialize_tip_state<Node>(
    ctx: ExExContext<Node>,
    config: RuntimeConfig,
) -> eyre::Result<impl Future<Output = eyre::Result<()>> + Send>
where
    Node: FullNodeComponents<
        DB = DatabaseEnv,
        Evm = EthEvmConfig,
        Types: NodeTypes<Primitives = EthPrimitives>,
    >,
{
    let chain_id = ctx.config.chain.chain().id();
    let genesis_hash = ctx.config.chain.genesis_hash();
    let request_id = seed_request_id(ctx.head)?;
    let request = capture_seed_request(
        ctx.provider(),
        ctx.evm_config(),
        ctx.head,
        request_id,
        chain_id,
        genesis_hash,
    )?;

    let (connection, seed_ack) = ReplicaConnection::connect_and_seed(
        &config.replica_socket,
        &request,
        config.seed_timeout,
        config.io_timeout,
    )
    .await?;
    let stream = StreamIdentity {
        chain_id: request.chain_id,
        genesis_hash: request.genesis_hash,
        seed_generation_id: seed_ack.generation_id,
        seed_sequence: 0,
        seed_anchor: request.anchor.clone(),
    };
    let coordinator = ProducerCoordinator::with_history_limit(
        stream,
        request.recent_block_hashes,
        vec![request.anchor],
        1_024,
    )?;
    let outbox = DurableOutbox::open(&config.outbox_root, seed_ack.generation_id)?;

    Ok(run_tip_state(ctx, coordinator, connection, outbox))
}

async fn run_tip_state<Node>(
    mut ctx: ExExContext<Node>,
    mut coordinator: ProducerCoordinator,
    mut connection: ReplicaConnection,
    outbox: DurableOutbox,
) -> eyre::Result<()>
where
    Node: FullNodeComponents<
        DB = DatabaseEnv,
        Evm = EthEvmConfig,
        Types: NodeTypes<Primitives = EthPrimitives>,
    >,
{
    while let Some(notification) = ctx.notifications.try_next().await? {
        let (removed, added) = map_notification(&notification, ctx.evm_config())?;
        if removed.is_empty() {
            for chunk in split_forward(added)? {
                deliver_transition(&mut coordinator, &mut connection, &outbox, Vec::new(), chunk)
                    .await?;
                send_finished_height(&ctx, coordinator.tip())?;
            }
        } else {
            deliver_transition(&mut coordinator, &mut connection, &outbox, removed, added).await?;
            send_finished_height(&ctx, coordinator.tip())?;
        }
    }
    eyre::bail!("tip-state ExEx notification stream closed");
}

fn map_notification(
    notification: &ExExNotification<EthPrimitives>,
    evm_config: &EthEvmConfig,
) -> eyre::Result<(Vec<BlockIdentity>, Vec<AddedBlock>)> {
    match notification {
        ExExNotification::ChainCommitted { new } => {
            let added = map_added_blocks(&normalize_chain(new, evm_config)?)?;
            Ok((Vec::new(), added))
        }
        ExExNotification::ChainReorged { old, new } => {
            let removed = removed_identities(old, evm_config)?;
            let added = map_added_blocks(&normalize_chain(new, evm_config)?)?;
            Ok((removed, added))
        }
        ExExNotification::ChainReverted { old } => {
            Ok((removed_identities(old, evm_config)?, Vec::new()))
        }
    }
}

fn removed_identities(
    chain: &Chain<EthPrimitives>,
    evm_config: &EthEvmConfig,
) -> eyre::Result<Vec<BlockIdentity>> {
    let normalized = normalize_chain(chain, evm_config)?;
    Ok(normalized
        .blocks
        .iter()
        .rev()
        .map(|block| BlockIdentity {
            number: block.identity.number,
            hash: block.identity.hash.0,
            parent_hash: block.identity.parent_hash.0,
            state_root: block.identity.state_root.0,
        })
        .collect())
}

fn split_forward(added: Vec<AddedBlock>) -> eyre::Result<Vec<Vec<AddedBlock>>> {
    let limits = DecodeLimits::default();
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_operations = 0usize;
    for block in added {
        let operations = block.changes.len();
        eyre::ensure!(
            operations <= limits.max_operations_per_block,
            "block {} has {operations} state operations, maximum is {}",
            block.block.identity.number,
            limits.max_operations_per_block
        );
        let would_exceed = current.len() == limits.max_added_blocks ||
            current_operations
                .checked_add(operations)
                .is_none_or(|total| total > limits.max_total_operations);
        if would_exceed && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
            current_operations = 0;
        }
        current_operations = current_operations
            .checked_add(operations)
            .ok_or_else(|| eyre::eyre!("forward operation count overflow"))?;
        eyre::ensure!(
            current_operations <= limits.max_total_operations,
            "block {} cannot fit in one atomic transition frame",
            block.block.identity.number
        );
        current.push(block);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    eyre::ensure!(!chunks.is_empty(), "empty committed notification");
    Ok(chunks)
}

async fn deliver_transition(
    coordinator: &mut ProducerCoordinator,
    connection: &mut ReplicaConnection,
    outbox: &DurableOutbox,
    removed: Vec<BlockIdentity>,
    added: Vec<AddedBlock>,
) -> eyre::Result<()> {
    let prepared = coordinator.prepare_transition(removed, added)?;
    persist_before_send(outbox, &prepared)?;
    let ack = connection.send_transition(prepared.frame()).await?;
    eyre::ensure!(ack == prepared.expected_ack(), "mandatory replica returned mismatched ACK");
    outbox.persist_ack(&ack)?;
    coordinator.accept_ack(&ack)?;
    Ok(())
}

fn persist_before_send(outbox: &DurableOutbox, prepared: &PreparedTransition) -> eyre::Result<()> {
    outbox.persist_frame(prepared.batch().sequence, prepared.frame())?;
    Ok(())
}

fn send_finished_height<Node>(
    ctx: &ExExContext<Node>,
    tip: &tip_state_wire::BlockDescriptor,
) -> eyre::Result<()>
where
    Node: FullNodeComponents,
{
    ctx.events.send(ExExEvent::FinishedHeight(BlockNumHash::new(
        tip.identity.number,
        B256::from(tip.identity.hash),
    )))?;
    Ok(())
}

fn seed_request_id(head: BlockNumHash) -> eyre::Result<B256> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let mut input = Vec::with_capacity(32 + 8 + 16 + 4);
    input.extend_from_slice(head.hash.as_slice());
    input.extend_from_slice(&head.number.to_be_bytes());
    input.extend_from_slice(&now.to_be_bytes());
    input.extend_from_slice(&std::process::id().to_be_bytes());
    let request_id = keccak256(input);
    eyre::ensure!(request_id != B256::ZERO, "derived zero seed request ID");
    Ok(request_id)
}

impl RuntimeConfig {
    fn from_env() -> eyre::Result<Self> {
        let replica_socket = env::var_os("TIP_STATE_REPLICA_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/data/tip-state.sock"));
        let outbox_root = env::var_os("TIP_STATE_OUTBOX_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/data/tip-state-outbox"));
        let seed_timeout = timeout_from_value(
            "TIP_STATE_SEED_TIMEOUT_SECONDS",
            env::var("TIP_STATE_SEED_TIMEOUT_SECONDS").ok(),
            3_600,
        )?;
        let io_timeout = timeout_from_value(
            "TIP_STATE_IO_TIMEOUT_SECONDS",
            env::var("TIP_STATE_IO_TIMEOUT_SECONDS").ok(),
            30,
        )?;
        Ok(Self { replica_socket, outbox_root, seed_timeout, io_timeout })
    }
}

fn timeout_from_value(
    name: &str,
    value: Option<String>,
    default_seconds: u64,
) -> eyre::Result<Duration> {
    let seconds = value.unwrap_or_else(|| default_seconds.to_string()).parse::<u64>()?;
    eyre::ensure!(seconds > 0, "{name} must be nonzero");
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_and_live_timeout_defaults_are_independent() {
        assert_eq!(
            timeout_from_value("TIP_STATE_SEED_TIMEOUT_SECONDS", None, 3_600).unwrap(),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            timeout_from_value("TIP_STATE_IO_TIMEOUT_SECONDS", None, 30).unwrap(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn timeout_values_must_be_positive_integers() {
        assert_eq!(
            timeout_from_value("TIP_STATE_SEED_TIMEOUT_SECONDS", Some("17".to_owned()), 3_600)
                .unwrap(),
            Duration::from_secs(17)
        );
        assert!(
            timeout_from_value("TIP_STATE_IO_TIMEOUT_SECONDS", Some("0".to_owned()), 30).is_err()
        );
        assert!(timeout_from_value(
            "TIP_STATE_IO_TIMEOUT_SECONDS",
            Some("not-a-number".to_owned()),
            30
        )
        .is_err());
    }
}
