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
use tip_state_wire::{
    encoded_added_block_len, encoded_forward_frame_len, AddedBlock, BlockDescriptor, BlockIdentity,
    DecodeLimits, StreamIdentity,
};

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
            for chunk in split_forward(added, coordinator.stream(), coordinator.tip())? {
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

fn split_forward(
    added: Vec<AddedBlock>,
    stream: &StreamIdentity,
    old_tip: &BlockDescriptor,
) -> eyre::Result<Vec<Vec<AddedBlock>>> {
    split_forward_with_limits(added, stream, old_tip, &DecodeLimits::default())
}

fn split_forward_with_limits(
    added: Vec<AddedBlock>,
    stream: &StreamIdentity,
    old_tip: &BlockDescriptor,
    limits: &DecodeLimits,
) -> eyre::Result<Vec<Vec<AddedBlock>>> {
    let mut chunks = Vec::new();
    let mut current: Vec<AddedBlock> = Vec::new();
    let mut current_old_tip = old_tip.clone();
    let mut current_operations = 0usize;
    let mut current_block_rlp_bytes = 0usize;
    let mut current_encoded_added_bytes = 0usize;
    for block in added {
        let operations = block.changes.len();
        let block_rlp_bytes = block.block_rlp.len();
        eyre::ensure!(
            operations <= limits.max_operations_per_block,
            "block {} has {operations} state operations, maximum is {}",
            block.block.identity.number,
            limits.max_operations_per_block
        );
        eyre::ensure!(
            !block.block_rlp.is_empty() && block_rlp_bytes <= limits.max_block_rlp_bytes,
            "block {} canonical RLP has {block_rlp_bytes} bytes, maximum is {}",
            block.block.identity.number,
            limits.max_block_rlp_bytes
        );
        let encoded_added_bytes = encoded_added_block_len(&block)?;
        let candidate_count = current
            .len()
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("forward block count overflow"))?;
        let candidate_operations = current_operations
            .checked_add(operations)
            .ok_or_else(|| eyre::eyre!("forward operation count overflow"))?;
        let candidate_block_rlp_bytes = current_block_rlp_bytes
            .checked_add(block_rlp_bytes)
            .ok_or_else(|| eyre::eyre!("forward canonical block RLP byte count overflow"))?;
        let candidate_encoded_added_bytes = current_encoded_added_bytes
            .checked_add(encoded_added_bytes)
            .ok_or_else(|| eyre::eyre!("forward encoded added-block byte count overflow"))?;
        let candidate_frame_bytes = encoded_forward_frame_len(
            stream,
            &current_old_tip,
            &block.block,
            candidate_count,
            candidate_encoded_added_bytes,
        )?;
        let would_exceed = candidate_count > limits.max_added_blocks ||
            candidate_operations > limits.max_total_operations ||
            candidate_block_rlp_bytes > limits.max_total_block_rlp_bytes ||
            candidate_frame_bytes > limits.max_frame_bytes;
        if would_exceed && !current.is_empty() {
            current_old_tip =
                current.last().expect("non-empty forward chunk has a final block").block.clone();
            chunks.push(std::mem::take(&mut current));
            current_operations = 0;
            current_block_rlp_bytes = 0;
            current_encoded_added_bytes = 0;
        }
        current_operations = current_operations
            .checked_add(operations)
            .ok_or_else(|| eyre::eyre!("forward operation count overflow"))?;
        eyre::ensure!(
            current_operations <= limits.max_total_operations,
            "block {} cannot fit in one atomic transition frame",
            block.block.identity.number
        );
        current_block_rlp_bytes = current_block_rlp_bytes
            .checked_add(block_rlp_bytes)
            .ok_or_else(|| eyre::eyre!("forward canonical block RLP byte count overflow"))?;
        eyre::ensure!(
            current_block_rlp_bytes <= limits.max_total_block_rlp_bytes,
            "block {} cannot fit in one atomic transition RLP budget",
            block.block.identity.number
        );
        current_encoded_added_bytes = current_encoded_added_bytes
            .checked_add(encoded_added_bytes)
            .ok_or_else(|| eyre::eyre!("forward encoded added-block byte count overflow"))?;
        eyre::ensure!(
            current.len() < limits.max_added_blocks,
            "block {} cannot fit in one atomic transition block-count budget",
            block.block.identity.number
        );
        let frame_bytes = encoded_forward_frame_len(
            stream,
            &current_old_tip,
            &block.block,
            current.len() + 1,
            current_encoded_added_bytes,
        )?;
        eyre::ensure!(
            frame_bytes <= limits.max_frame_bytes,
            "block {} cannot fit in one atomic transition frame: {frame_bytes} bytes exceeds {}",
            block.block.identity.number,
            limits.max_frame_bytes
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
    use tip_state_wire::{BlockExecutionContext, BlockIdentity, CanonicalBlockRlp, ExecutionFork};

    fn test_descriptor(number: u64, tag: u8, parent_hash: [u8; 32]) -> BlockDescriptor {
        BlockDescriptor {
            identity: BlockIdentity {
                number,
                hash: [tag; 32],
                parent_hash,
                state_root: [tag.wrapping_add(64); 32],
            },
            execution: BlockExecutionContext {
                active_fork: ExecutionFork::Frontier,
                timestamp: number,
                slot_number: None,
                fee_recipient: [tag; 20],
                gas_limit: 30_000_000,
                gas_used: 0,
                base_fee_per_gas: [0; 32],
                prev_randao: [tag.wrapping_add(1); 32],
                difficulty: [0; 32],
                blob_gas_used: None,
                excess_blob_gas: None,
                blob_base_fee: None,
                parent_beacon_block_root: None,
                withdrawals_root: None,
                requests_hash: None,
            },
        }
    }

    fn forward_fixture() -> (StreamIdentity, BlockDescriptor, Vec<AddedBlock>) {
        let seed_anchor = test_descriptor(1, 1, [9; 32]);
        let first = test_descriptor(2, 2, seed_anchor.identity.hash);
        let second = test_descriptor(3, 3, first.identity.hash);
        let stream = StreamIdentity {
            chain_id: 1,
            genesis_hash: [9; 32],
            seed_generation_id: [10; 32],
            seed_sequence: 0,
            seed_anchor: seed_anchor.clone(),
        };
        let added = [first, second]
            .into_iter()
            .map(|block| AddedBlock {
                block,
                block_rlp: CanonicalBlockRlp::new(vec![0xc0; 32]),
                changes: Vec::new(),
            })
            .collect();
        (stream, seed_anchor, added)
    }

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

    #[test]
    fn forward_combined_frame_overflow_splits_at_a_block_boundary() {
        let (stream, old_tip, added) = forward_fixture();
        let first_len = encoded_added_block_len(&added[0]).unwrap();
        let second_len = encoded_added_block_len(&added[1]).unwrap();
        let first_frame =
            encoded_forward_frame_len(&stream, &old_tip, &added[0].block, 1, first_len).unwrap();
        let second_frame =
            encoded_forward_frame_len(&stream, &added[0].block, &added[1].block, 1, second_len)
                .unwrap();
        let combined_frame = encoded_forward_frame_len(
            &stream,
            &old_tip,
            &added[1].block,
            2,
            first_len + second_len,
        )
        .unwrap();
        let max_frame_bytes = first_frame.max(second_frame);
        assert!(combined_frame > max_frame_bytes);

        let limits = DecodeLimits { max_frame_bytes, ..DecodeLimits::default() };
        let chunks = split_forward_with_limits(added, &stream, &old_tip, &limits).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 1);
        assert_eq!(chunks[1].len(), 1);
        assert_eq!(chunks[0][0].block.identity.number, 2);
        assert_eq!(chunks[1][0].block.identity.number, 3);
    }

    #[test]
    fn single_forward_block_larger_than_frame_limit_fails_closed() {
        let (stream, old_tip, mut added) = forward_fixture();
        added.truncate(1);
        let encoded_added_bytes = encoded_added_block_len(&added[0]).unwrap();
        let frame_bytes =
            encoded_forward_frame_len(&stream, &old_tip, &added[0].block, 1, encoded_added_bytes)
                .unwrap();
        let limits = DecodeLimits { max_frame_bytes: frame_bytes - 1, ..DecodeLimits::default() };

        let error = split_forward_with_limits(added, &stream, &old_tip, &limits).unwrap_err();
        assert!(error.to_string().contains("cannot fit in one atomic transition frame"));
    }
}
