//! Provider-independent coordination of one durable canonical transition at a time.

use std::{collections::VecDeque, sync::Arc};

use thiserror::Error;
use tip_state_wire::{
    encode_frame, AddedBlock, BlockDescriptor, BlockIdentity, DecodeLimits, Hash32,
    RecentBlockHashes, StreamIdentity, TransitionAck, TransitionBatch, WireError,
    FRAME_CHECKSUM_BYTES, SCHEMA_VERSION,
};

const BLOCKHASH_WINDOW: usize = 256;

/// Producer-side canonical cursor with exactly one possible durable frame in flight.
///
/// Preparing a transition does not change the acknowledged sequence, tip, descriptor history, or
/// BLOCKHASH window. Those values advance only after [`Self::accept_ack`] receives the exact ACK
/// for the prepared frame. A transport can retry [`Self::retry_in_flight`] byte-for-byte after a
/// disconnect or lost ACK without rebuilding the transition.
#[derive(Clone, Debug)]
pub struct ProducerCoordinator {
    stream: StreamIdentity,
    sequence: u64,
    history: VecDeque<BlockDescriptor>,
    history_limit: usize,
    recent_block_hashes: RecentBlockHashes,
    in_flight: Option<InFlightTransition>,
}

impl ProducerCoordinator {
    /// Creates a coordinator at one completed seed generation using the shared wire defaults.
    ///
    /// `descriptor_history` is ordered oldest-to-newest and must end at the seed anchor. It may
    /// include pre-anchor descriptors needed to reconstruct BLOCKHASH after a rollback, but those
    /// descriptors do not authorize unwinding state across the seed anchor. The default bound
    /// retains the 256 EVM ancestors plus the default maximum removed-block count and current tip.
    pub fn new(
        stream: StreamIdentity,
        seed_recent_block_hashes: RecentBlockHashes,
        descriptor_history: Vec<BlockDescriptor>,
    ) -> Result<Self, CoordinatorError> {
        let history_limit = BLOCKHASH_WINDOW
            .checked_add(DecodeLimits::default().max_removed_blocks)
            .and_then(|limit| limit.checked_add(1))
            .ok_or(WireError::LengthOverflow)?;
        Self::with_history_limit(
            stream,
            seed_recent_block_hashes,
            descriptor_history,
            history_limit,
        )
    }

    /// Creates a coordinator with an explicitly provisioned descriptor-history bound.
    ///
    /// The bound must retain an additional 256 descriptors before every rollback point whose
    /// complete EVM BLOCKHASH window must remain derivable.
    pub fn with_history_limit(
        stream: StreamIdentity,
        seed_recent_block_hashes: RecentBlockHashes,
        descriptor_history: Vec<BlockDescriptor>,
        history_limit: usize,
    ) -> Result<Self, CoordinatorError> {
        validate_seed_descriptor_history(&stream, &descriptor_history, history_limit)?;
        let limits = DecodeLimits::default();
        seed_recent_block_hashes.validate_for_tip(&stream.seed_anchor.identity, &limits)?;
        if !seed_recent_block_hashes.hashes.is_empty() &&
            seed_recent_block_hashes.start_number == 0 &&
            seed_recent_block_hashes.hashes.first() != Some(&stream.genesis_hash)
        {
            return Err(WireError::BlockHashWindowGenesisMismatch.into());
        }
        validate_seed_window_overlap(&descriptor_history, &seed_recent_block_hashes)?;

        Ok(Self {
            sequence: stream.seed_sequence,
            stream,
            history: descriptor_history.into(),
            history_limit,
            recent_block_hashes: seed_recent_block_hashes,
            in_flight: None,
        })
    }

    /// Returns the immutable stream binding shared with every frame.
    pub const fn stream(&self) -> &StreamIdentity {
        &self.stream
    }

    /// Returns the latest sequence acknowledged by the durable receiver.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the latest canonical descriptor acknowledged by the durable receiver.
    pub fn tip(&self) -> &BlockDescriptor {
        self.history.back().expect("constructor and ACK application preserve non-empty history")
    }

    /// Returns the complete BLOCKHASH window for the acknowledged tip.
    pub const fn recent_block_hashes(&self) -> &RecentBlockHashes {
        &self.recent_block_hashes
    }

    /// Returns the currently prepared transition, if one is awaiting an ACK.
    pub fn in_flight(&self) -> Option<&PreparedTransition> {
        self.in_flight.as_ref().map(|transition| &transition.prepared)
    }

    /// Returns a cheap handle to the exact in-flight frame for byte-identical retry.
    pub fn retry_in_flight(&self) -> Result<PreparedTransition, CoordinatorError> {
        self.in_flight
            .as_ref()
            .map(|transition| transition.prepared.clone())
            .ok_or(CoordinatorError::NoTransitionInFlight)
    }

    /// Prepares one commit, reorg, or pure revert without advancing the acknowledged cursor.
    ///
    /// `removed` must exactly equal retained canonical identities newest-first. `added` must be
    /// oldest-first and is normally produced by `wire::map_added_blocks`. The complete next
    /// BLOCKHASH window is derived from acknowledged ancestry and added identities; callers cannot
    /// supply or override it.
    pub fn prepare_transition(
        &mut self,
        removed: Vec<BlockIdentity>,
        added: Vec<AddedBlock>,
    ) -> Result<PreparedTransition, CoordinatorError> {
        if self.in_flight.is_some() {
            return Err(CoordinatorError::TransitionAlreadyInFlight);
        }
        if removed.is_empty() && added.is_empty() {
            return Err(WireError::EmptyCanonicalUpdate.into());
        }
        if removed.len() >= self.history.len() {
            return Err(CoordinatorError::RollbackBeyondRetainedHistory {
                removed: removed.len(),
                retained: self.history.len(),
            });
        }
        for (offset, (received, retained)) in
            removed.iter().zip(self.history.iter().rev()).enumerate()
        {
            if received != &retained.identity {
                return Err(CoordinatorError::RemovedIdentityMismatch { offset });
            }
        }

        let common_index = self.history.len().checked_sub(removed.len() + 1).ok_or(
            CoordinatorError::RollbackBeyondRetainedHistory {
                removed: removed.len(),
                retained: self.history.len(),
            },
        )?;
        let common_ancestor = self
            .history
            .get(common_index)
            .expect("validated rollback count has a retained common ancestor")
            .clone();
        if common_ancestor.identity.number < self.stream.seed_anchor.identity.number {
            return Err(CoordinatorError::RollbackAcrossSeedAnchor {
                requested: common_ancestor.identity.number,
                anchor: self.stream.seed_anchor.identity.number,
            });
        }

        let mut next_recent = if removed.is_empty() {
            self.recent_block_hashes.clone()
        } else {
            self.derive_window_for_tip(&common_ancestor.identity)?
        };
        let mut previous = &common_ancestor;
        for (offset, block) in added.iter().enumerate() {
            if block.block.identity.number !=
                previous.identity.number.checked_add(1).ok_or(
                    CoordinatorError::BlockNumberOverflow { previous: previous.identity.number },
                )? ||
                block.block.identity.parent_hash != previous.identity.hash
            {
                return Err(CoordinatorError::AddedLinkMismatch { offset });
            }
            next_recent =
                advance_block_hash_window(next_recent, &previous.identity, &block.block.identity)?;
            previous = &block.block;
        }

        let old_tip = self.tip().clone();
        let new_tip = added
            .last()
            .map(|block| block.block.clone())
            .unwrap_or_else(|| common_ancestor.clone());
        let sequence = self.sequence.checked_add(1).ok_or(CoordinatorError::SequenceOverflow)?;
        let batch = TransitionBatch {
            schema_version: SCHEMA_VERSION,
            stream: self.stream.clone(),
            sequence,
            old_tip,
            common_ancestor,
            new_tip,
            removed,
            added,
            recent_block_hashes: next_recent.clone(),
        };
        let frame = encode_frame(&batch)?;
        let digest_start =
            frame.len().checked_sub(FRAME_CHECKSUM_BYTES).ok_or(WireError::LengthOverflow)?;
        let frame_digest =
            frame[digest_start..].try_into().map_err(|_| WireError::LengthOverflow)?;
        let prepared =
            PreparedTransition { batch: Arc::new(batch), frame: Arc::from(frame), frame_digest };

        let mut next_history = self.history.clone();
        for _ in 0..prepared.batch.removed.len() {
            next_history.pop_back();
        }
        for block in &prepared.batch.added {
            next_history.push_back(block.block.clone());
        }
        while next_history.len() > self.history_limit {
            next_history.pop_front();
        }
        self.in_flight = Some(InFlightTransition {
            prepared: prepared.clone(),
            next_history,
            next_recent_block_hashes: next_recent,
        });
        Ok(prepared)
    }

    /// Advances the producer cursor only when `ack` exactly authenticates the in-flight frame.
    pub fn accept_ack(&mut self, ack: &TransitionAck) -> Result<(), CoordinatorError> {
        let transition = self.in_flight.as_ref().ok_or(CoordinatorError::NoTransitionInFlight)?;
        if ack != &transition.prepared.expected_ack() {
            return Err(CoordinatorError::AckMismatch);
        }

        let transition =
            self.in_flight.take().expect("in-flight transition was validated before removal");
        self.sequence = transition.prepared.batch.sequence;
        self.history = transition.next_history;
        self.recent_block_hashes = transition.next_recent_block_hashes;
        Ok(())
    }

    fn derive_window_for_tip(
        &self,
        tip: &BlockIdentity,
    ) -> Result<RecentBlockHashes, CoordinatorError> {
        let expected_len = usize::try_from(tip.number.min(BLOCKHASH_WINDOW as u64))
            .map_err(|_| WireError::LengthOverflow)?;
        let start_number =
            tip.number.checked_sub(expected_len as u64).ok_or(WireError::LengthOverflow)?;
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(expected_len).map_err(|_| WireError::AllocationFailed)?;
        for number in start_number..tip.number {
            hashes.push(self.canonical_hash_at(number).ok_or(
                CoordinatorError::BlockHashHistoryUnavailable { tip: tip.number, missing: number },
            )?);
        }
        let recent = RecentBlockHashes { start_number, hashes };
        recent.validate_for_tip(tip, &DecodeLimits::default())?;
        if !recent.hashes.is_empty() &&
            recent.start_number == 0 &&
            recent.hashes.first() != Some(&self.stream.genesis_hash)
        {
            return Err(WireError::BlockHashWindowGenesisMismatch.into());
        }
        Ok(recent)
    }

    fn canonical_hash_at(&self, number: u64) -> Option<Hash32> {
        let from_history = self.history.front().and_then(|oldest| {
            let offset = number.checked_sub(oldest.identity.number)?;
            let offset = usize::try_from(offset).ok()?;
            self.history
                .get(offset)
                .and_then(|block| (block.identity.number == number).then_some(block.identity.hash))
        });
        let from_window = number
            .checked_sub(self.recent_block_hashes.start_number)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| self.recent_block_hashes.hashes.get(offset).copied());
        from_history.or(from_window)
    }
}

/// Cheap immutable handle to one encoded transition and its semantic batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTransition {
    batch: Arc<TransitionBatch>,
    frame: Arc<[u8]>,
    frame_digest: Hash32,
}

impl PreparedTransition {
    /// Returns the exact semantic transition encoded in [`Self::frame`].
    pub fn batch(&self) -> &TransitionBatch {
        &self.batch
    }

    /// Returns the immutable byte-identical durable frame.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Returns the frame checksum bound into an exact receiver ACK.
    pub const fn frame_digest(&self) -> Hash32 {
        self.frame_digest
    }

    /// Builds the only ACK that can advance the producer cursor.
    pub fn expected_ack(&self) -> TransitionAck {
        TransitionAck {
            seed_generation_id: self.batch.stream.seed_generation_id,
            sequence: self.batch.sequence,
            frame_digest: self.frame_digest,
            new_tip: self.batch.new_tip.identity.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct InFlightTransition {
    prepared: PreparedTransition,
    next_history: VecDeque<BlockDescriptor>,
    next_recent_block_hashes: RecentBlockHashes,
}

/// A fail-closed producer coordination error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[allow(missing_docs)] // Every variant has a precise operational diagnostic.
pub enum CoordinatorError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("a durable transition is already in flight")]
    TransitionAlreadyInFlight,
    #[error("no durable transition is in flight")]
    NoTransitionInFlight,
    #[error("stream sequence overflow")]
    SequenceOverflow,
    #[error("rollback removes {removed} blocks but only {retained} descriptors are retained")]
    RollbackBeyondRetainedHistory { removed: usize, retained: usize },
    #[error("rollback common ancestor {requested} crosses seed anchor floor {anchor}")]
    RollbackAcrossSeedAnchor { requested: u64, anchor: u64 },
    #[error("removed identity at newest-first offset {offset} differs from retained history")]
    RemovedIdentityMismatch { offset: usize },
    #[error("added block at oldest-first offset {offset} does not extend its predecessor")]
    AddedLinkMismatch { offset: usize },
    #[error("block number overflow after {previous}")]
    BlockNumberOverflow { previous: u64 },
    #[error("seed descriptor history must be contiguous, bounded, and end at the seed anchor")]
    InvalidSeedDescriptorHistory,
    #[error("seed BLOCKHASH entry for block {number} differs from descriptor history")]
    SeedBlockHashMismatch { number: u64 },
    #[error(
        "cannot derive complete BLOCKHASH window for tip {tip}: block {missing} is unavailable"
    )]
    BlockHashHistoryUnavailable { tip: u64, missing: u64 },
    #[error("ACK does not exactly authenticate the in-flight frame")]
    AckMismatch,
}

fn validate_seed_descriptor_history(
    stream: &StreamIdentity,
    history: &[BlockDescriptor],
    history_limit: usize,
) -> Result<(), CoordinatorError> {
    if history_limit == 0 {
        return Err(WireError::ZeroHistoryLimit.into());
    }
    stream.validate()?;
    if history.is_empty()
        || history.len() > history_limit
        || history.last() != Some(&stream.seed_anchor)
    {
        return Err(CoordinatorError::InvalidSeedDescriptorHistory);
    }
    for descriptor in history {
        let mut descriptor_binding = stream.clone();
        descriptor_binding.seed_anchor = descriptor.clone();
        descriptor_binding.validate()?;
    }
    for pair in history.windows(2) {
        let expected_number =
            pair[0].identity.number.checked_add(1).ok_or(WireError::BlockNumberOverflow)?;
        if pair[1].identity.number != expected_number
            || pair[1].identity.parent_hash != pair[0].identity.hash
            || pair[1].execution.timestamp <= pair[0].execution.timestamp
            || pair[1].execution.active_fork < pair[0].execution.active_fork
        {
            return Err(CoordinatorError::InvalidSeedDescriptorHistory);
        }
    }
    Ok(())
}

fn validate_seed_window_overlap(
    history: &[BlockDescriptor],
    recent: &RecentBlockHashes,
) -> Result<(), CoordinatorError> {
    for descriptor in history {
        let Some(offset) = descriptor
            .identity
            .number
            .checked_sub(recent.start_number)
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        if let Some(hash) = recent.hashes.get(offset) &&
            hash != &descriptor.identity.hash
        {
            return Err(CoordinatorError::SeedBlockHashMismatch {
                number: descriptor.identity.number,
            });
        }
    }
    Ok(())
}

fn advance_block_hash_window(
    mut recent: RecentBlockHashes,
    parent: &BlockIdentity,
    child: &BlockIdentity,
) -> Result<RecentBlockHashes, CoordinatorError> {
    recent.validate_for_tip(parent, &DecodeLimits::default())?;
    if child.number !=
        parent
            .number
            .checked_add(1)
            .ok_or(CoordinatorError::BlockNumberOverflow { previous: parent.number })? ||
        child.parent_hash != parent.hash
    {
        return Err(CoordinatorError::AddedLinkMismatch { offset: 0 });
    }
    if recent.hashes.len() == BLOCKHASH_WINDOW {
        recent.hashes.remove(0);
        recent.start_number =
            recent.start_number.checked_add(1).ok_or(WireError::LengthOverflow)?;
    }
    recent.hashes.push(parent.hash);
    recent.validate_for_tip(child, &DecodeLimits::default())?;
    Ok(recent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tip_state_wire::{BlockExecutionContext, ExecutionFork, StateChange, FRAME_MAGIC};

    const SEED_SEQUENCE: u64 = 41;

    fn hash(tag: u64) -> Hash32 {
        let mut hash = [0u8; 32];
        hash[24..].copy_from_slice(&tag.to_be_bytes());
        hash
    }

    fn context(timestamp: u64) -> BlockExecutionContext {
        BlockExecutionContext {
            active_fork: ExecutionFork::Osaka,
            timestamp,
            slot_number: None,
            fee_recipient: [0x42; 20],
            gas_limit: 60_000_000,
            gas_used: 30_000_000,
            base_fee_per_gas: hash(1_000_000_000),
            prev_randao: hash(timestamp + 10_000),
            difficulty: [0; 32],
            blob_gas_used: Some(0),
            excess_blob_gas: Some(100),
            blob_base_fee: Some(hash(1)),
            parent_beacon_block_root: Some(hash(timestamp + 20_000)),
            withdrawals_root: Some(hash(timestamp + 30_000)),
            requests_hash: Some(hash(timestamp + 40_000)),
        }
    }

    fn block(number: u64, tag: u64, parent_hash: Hash32) -> BlockDescriptor {
        BlockDescriptor {
            identity: BlockIdentity {
                number,
                hash: hash(tag),
                parent_hash,
                state_root: hash(tag + 1_000),
            },
            execution: context(number * 12),
        }
    }

    fn added(block: BlockDescriptor) -> AddedBlock {
        AddedBlock { block, changes: Vec::new() }
    }

    fn fixture() -> (ProducerCoordinator, BlockDescriptor, BlockDescriptor, BlockDescriptor) {
        let genesis = block(0, 9, [0; 32]);
        let block_one = block(1, 11, genesis.identity.hash);
        let seed = block(2, 12, block_one.identity.hash);
        let stream = StreamIdentity {
            chain_id: 1,
            genesis_hash: genesis.identity.hash,
            seed_generation_id: hash(99_999),
            seed_sequence: SEED_SEQUENCE,
            seed_anchor: seed.clone(),
        };
        let recent = RecentBlockHashes {
            start_number: 0,
            hashes: vec![genesis.identity.hash, block_one.identity.hash],
        };
        let coordinator = ProducerCoordinator::new(
            stream,
            recent,
            vec![genesis.clone(), block_one.clone(), seed.clone()],
        )
        .unwrap();
        (coordinator, genesis, block_one, seed)
    }

    fn accept(coordinator: &mut ProducerCoordinator, prepared: &PreparedTransition) {
        coordinator.accept_ack(&prepared.expected_ack()).unwrap();
    }

    #[test]
    fn multi_block_reorg_derives_replacement_blockhash_window() {
        let (mut coordinator, genesis, block_one, seed) = fixture();
        let block_three = block(3, 13, seed.identity.hash);
        let block_four = block(4, 14, block_three.identity.hash);
        let committed = coordinator
            .prepare_transition(vec![], vec![added(block_three.clone()), added(block_four.clone())])
            .unwrap();
        accept(&mut coordinator, &committed);

        let replacement_three = block(3, 30, seed.identity.hash);
        let replacement_four = block(4, 31, replacement_three.identity.hash);
        let reorg = coordinator
            .prepare_transition(
                vec![block_four.identity, block_three.identity.clone()],
                vec![added(replacement_three.clone()), added(replacement_four.clone())],
            )
            .unwrap();
        assert_eq!(reorg.batch().common_ancestor, seed);
        assert_eq!(reorg.batch().new_tip, replacement_four);
        assert_eq!(
            reorg.batch().recent_block_hashes.hashes,
            vec![
                genesis.identity.hash,
                block_one.identity.hash,
                seed.identity.hash,
                replacement_three.identity.hash,
            ]
        );
        assert!(!reorg.batch().recent_block_hashes.hashes.contains(&block_three.identity.hash));
    }

    #[test]
    fn pure_revert_restores_exact_ancestor_context() {
        let (mut coordinator, _, _, seed) = fixture();
        let block_three = block(3, 13, seed.identity.hash);
        let block_four = block(4, 14, block_three.identity.hash);
        let committed = coordinator
            .prepare_transition(vec![], vec![added(block_three.clone()), added(block_four.clone())])
            .unwrap();
        accept(&mut coordinator, &committed);

        let reverted = coordinator
            .prepare_transition(vec![block_four.identity, block_three.identity], Vec::new())
            .unwrap();
        assert!(reverted.batch().added.is_empty());
        assert_eq!(reverted.batch().new_tip, seed);
        assert_eq!(
            reverted.batch().recent_block_hashes,
            RecentBlockHashes { start_number: 0, hashes: vec![hash(9), hash(11)] }
        );
        accept(&mut coordinator, &reverted);
        assert_eq!(coordinator.tip(), &coordinator.stream().seed_anchor);
    }

    #[test]
    fn removed_state_root_corruption_fails_before_frame_creation() {
        let (mut coordinator, _, _, seed) = fixture();
        let block_three = block(3, 13, seed.identity.hash);
        let block_four = block(4, 14, block_three.identity.hash);
        let committed = coordinator
            .prepare_transition(vec![], vec![added(block_three.clone()), added(block_four.clone())])
            .unwrap();
        accept(&mut coordinator, &committed);

        let mut corrupted_three = block_three.identity;
        corrupted_three.state_root = hash(777_777);
        assert_eq!(
            coordinator.prepare_transition(
                vec![block_four.identity, corrupted_three],
                vec![added(block(3, 30, seed.identity.hash))],
            ),
            Err(CoordinatorError::RemovedIdentityMismatch { offset: 1 })
        );
        assert!(coordinator.in_flight().is_none());
        assert_eq!(coordinator.sequence(), SEED_SEQUENCE + 1);
    }

    #[test]
    fn mismatched_ack_preserves_in_flight_and_lost_ack_retry_is_identical() {
        let (mut coordinator, _, _, seed) = fixture();
        let block_three = block(3, 13, seed.identity.hash);
        let prepared =
            coordinator.prepare_transition(Vec::new(), vec![added(block_three.clone())]).unwrap();
        assert_eq!(coordinator.sequence(), SEED_SEQUENCE);
        assert_eq!(coordinator.tip(), &seed);

        let retry = coordinator.retry_in_flight().unwrap();
        assert_eq!(retry, prepared);
        assert_eq!(retry.frame(), prepared.frame());
        assert_eq!(&retry.frame()[..FRAME_MAGIC.len()], &FRAME_MAGIC);

        let mut wrong_ack = prepared.expected_ack();
        wrong_ack.frame_digest[0] ^= 1;
        assert_eq!(coordinator.accept_ack(&wrong_ack), Err(CoordinatorError::AckMismatch));
        assert_eq!(coordinator.sequence(), SEED_SEQUENCE);
        assert_eq!(coordinator.tip(), &seed);
        assert_eq!(coordinator.retry_in_flight().unwrap(), prepared);
        assert_eq!(
            coordinator.prepare_transition(Vec::new(), vec![added(block_three.clone())]),
            Err(CoordinatorError::TransitionAlreadyInFlight)
        );

        accept(&mut coordinator, &prepared);
        assert_eq!(coordinator.sequence(), SEED_SEQUENCE + 1);
        assert_eq!(coordinator.tip(), &block_three);
        assert!(coordinator.in_flight().is_none());
    }

    #[test]
    fn seed_anchor_is_a_hard_rollback_floor() {
        let (mut coordinator, _, block_one, seed) = fixture();
        assert_eq!(
            coordinator.prepare_transition(vec![seed.identity], Vec::new()),
            Err(CoordinatorError::RollbackAcrossSeedAnchor {
                requested: block_one.identity.number,
                anchor: 2,
            })
        );
        assert_eq!(coordinator.tip(), &coordinator.stream().seed_anchor);
        assert!(coordinator.in_flight().is_none());
    }

    #[test]
    fn seed_window_must_match_overlapping_descriptor_history() {
        let genesis = block(0, 9, [0; 32]);
        let block_one = block(1, 11, genesis.identity.hash);
        let block_two = block(2, 12, block_one.identity.hash);
        let seed = block(3, 13, block_two.identity.hash);
        let stream = StreamIdentity {
            chain_id: 1,
            genesis_hash: genesis.identity.hash,
            seed_generation_id: hash(99_999),
            seed_sequence: SEED_SEQUENCE,
            seed_anchor: seed.clone(),
        };
        let mut recent = RecentBlockHashes {
            start_number: 0,
            hashes: vec![genesis.identity.hash, block_one.identity.hash, block_two.identity.hash],
        };
        let mut broken_block_one = block_one.clone();
        broken_block_one.identity.parent_hash = hash(123_456);
        assert!(matches!(
            ProducerCoordinator::new(
                stream.clone(),
                recent.clone(),
                vec![genesis.clone(), broken_block_one, block_two.clone(), seed.clone()],
            ),
            Err(CoordinatorError::InvalidSeedDescriptorHistory)
        ));
        recent.hashes[1] = hash(123_456);
        assert!(matches!(
            ProducerCoordinator::new(stream, recent, vec![genesis, block_one, block_two, seed],),
            Err(CoordinatorError::SeedBlockHashMismatch { number: 1 })
        ));
    }

    #[test]
    fn malformed_added_changes_are_rejected_by_shared_wire_validation() {
        let (mut coordinator, _, _, seed) = fixture();
        let mut next = added(block(3, 13, seed.identity.hash));
        next.changes.push(StateChange::StorageSet {
            account: hash(100),
            slot: hash(200),
            value: [0; 32],
        });
        assert_eq!(
            coordinator.prepare_transition(Vec::new(), vec![next]),
            Err(CoordinatorError::Wire(WireError::ZeroStorageSet))
        );
        assert!(coordinator.in_flight().is_none());
    }
}
