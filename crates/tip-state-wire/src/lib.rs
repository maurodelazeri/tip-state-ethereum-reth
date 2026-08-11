//! Versioned, deterministic wire format for normalized tip-state transitions.
//!
//! This codec is intentionally independent of Reth, revm, alloy, databases, RPC, and transports.
//! Addresses, hashes, words, and balances are fixed byte arrays with explicitly documented byte
//! order. A producer adapter and every replica version can therefore share this module without
//! sharing an execution-client ABI.
//!
//! The frame binds every transition to one chain and one completed seed generation. Canonical
//! removals are newest-first, additions are oldest-first, and state changes inside each added block
//! use a canonical key order. The recent BLOCKHASH data is a complete replacement window for the
//! newly visible tip, not an incremental cache hint.
//!
//! Transport durability, durable outbox retention, fan-out, ACK/NACK policy, retry, and sink
//! backpressure are deliberately outside this codec. Those layers must fail closed; decoding a
//! valid frame does not mean it has been durably accepted or atomically published.
//!
//! Default limits are operational producer chunk limits, not Reth notification maxima. A pure
//! forward notification may be split only at block boundaries into consecutive frames whose old
//! and new tips chain exactly and whose sequences advance by one. A block is never split. A reorg
//! or pure revert must remain one atomic frame; if it or one block exceeds configured limits, the
//! producer and receiver fail closed and require an explicitly provisioned larger bound or a new
//! seed snapshot. In particular, the codec never turns an oversized reorg into partially visible
//! unwind/forward steps.

use std::collections::VecDeque;

use blake3::Hasher as Blake3Hasher;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Keccak256};
use thiserror::Error;

pub mod bootstrap;

pub const SCHEMA_VERSION: u16 = 2;
pub const FRAME_MAGIC: [u8; 8] = *b"TIPWIRE2";
pub const FRAME_HEADER_BYTES: usize = 16;
pub const FRAME_CHECKSUM_BYTES: usize = 32;
const FRAME_FLAGS: u16 = 0;
const CHECKSUM_DOMAIN: &[u8] = b"tip-state-transition-wire-v2";
const BLOCKHASH_WINDOW: usize = 256;
const BLOCK_IDENTITY_ENCODED_BYTES: usize = 8 + 32 + 32 + 32;
const MIN_EXECUTION_CONTEXT_ENCODED_BYTES: usize =
    1 + 8 + 1 + 20 + 8 + 8 + 32 + 32 + 32 + 1 + 1 + 1 + 1 + 1 + 1;
const MIN_BLOCK_DESCRIPTOR_ENCODED_BYTES: usize =
    BLOCK_IDENTITY_ENCODED_BYTES + MIN_EXECUTION_CONTEXT_ENCODED_BYTES;
const MIN_ADDED_BLOCK_ENCODED_BYTES: usize = MIN_BLOCK_DESCRIPTOR_ENCODED_BYTES + 4 + 1 + 4;
const MIN_STATE_CHANGE_ENCODED_BYTES: usize = 1 + 32;

/// A Keccak hash, block hash, state root, hashed address, or hashed slot.
pub type Hash32 = [u8; 32];
/// An Ethereum address in its exact 20-byte form.
pub type Address20 = [u8; 20];
/// An unsigned 256-bit value encoded in big-endian byte order.
pub type Word32 = [u8; 32];

/// One complete canonical Ethereum block encoded as RLP (`header`, transactions, ommers, and,
/// when present, withdrawals).
///
/// Bootstrap JSON represents these bytes as a lowercase, even-length, `0x`-prefixed hex string.
/// TIPWIRE2 carries the same bytes verbatim behind a bounded big-endian `u32` length. The receiver
/// must strictly decode the Ethereum block, verify it against the enclosing descriptor, and require
/// byte-identical canonical re-encoding before publishing a generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalBlockRlp(Vec<u8>);

impl CanonicalBlockRlp {
    /// Wraps bytes produced by a canonical Ethereum block encoder.
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the encoded block bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the encoded byte length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the encoded block is empty and therefore invalid in a container.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper and returns the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for CanonicalBlockRlp {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Serialize for CanonicalBlockRlp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let capacity =
            self.0.len().checked_mul(2).and_then(|length| length.checked_add(2)).ok_or_else(
                || <S::Error as ser::Error>::custom("canonical block RLP hex length overflow"),
            )?;
        let mut encoded = String::with_capacity(capacity);
        encoded.push_str("0x");
        for byte in &self.0 {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for CanonicalBlockRlp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = <&str>::deserialize(deserializer)?;
        let digits = encoded.strip_prefix("0x").ok_or_else(|| {
            <D::Error as de::Error>::custom("canonical block RLP must start with 0x")
        })?;
        if digits.len() % 2 != 0 {
            return Err(<D::Error as de::Error>::custom(
                "canonical block RLP hex length must be even",
            ));
        }

        let mut bytes = Vec::with_capacity(digits.len() / 2);
        for pair in digits.as_bytes().as_chunks::<2>().0 {
            let high = decode_lower_hex_nibble(pair[0]).ok_or_else(|| {
                <D::Error as de::Error>::custom(
                    "canonical block RLP must use lowercase hexadecimal",
                )
            })?;
            let low = decode_lower_hex_nibble(pair[1]).ok_or_else(|| {
                <D::Error as de::Error>::custom(
                    "canonical block RLP must use lowercase hexadecimal",
                )
            })?;
            bytes.push((high << 4) | low);
        }
        Ok(Self(bytes))
    }
}

const fn decode_lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Symmetric producer/receiver bounds. Raising them is an explicit capacity decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_frame_bytes: usize,
    pub max_block_rlp_bytes: usize,
    pub max_total_block_rlp_bytes: usize,
    pub max_removed_blocks: usize,
    pub max_added_blocks: usize,
    pub max_operations_per_block: usize,
    pub max_total_operations: usize,
    pub max_code_bytes: usize,
    pub max_recent_block_hashes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 64 * 1024 * 1024,
            max_block_rlp_bytes: 32 * 1024 * 1024,
            max_total_block_rlp_bytes: 48 * 1024 * 1024,
            max_removed_blocks: 256,
            max_added_blocks: 256,
            max_operations_per_block: 1_000_000,
            max_total_operations: 2_000_000,
            max_code_bytes: 1024 * 1024,
            max_recent_block_hashes: BLOCKHASH_WINDOW,
        }
    }
}

/// Stable fork identifiers owned by this schema, not revm numeric discriminants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExecutionFork {
    Frontier = 0,
    Homestead = 1,
    Tangerine = 2,
    SpuriousDragon = 3,
    Byzantium = 4,
    Petersburg = 5,
    Istanbul = 6,
    Berlin = 7,
    London = 8,
    Paris = 9,
    Shanghai = 10,
    Cancun = 11,
    Prague = 12,
    Osaka = 13,
    Amsterdam = 14,
}

impl TryFrom<u8> for ExecutionFork {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Frontier),
            1 => Ok(Self::Homestead),
            2 => Ok(Self::Tangerine),
            3 => Ok(Self::SpuriousDragon),
            4 => Ok(Self::Byzantium),
            5 => Ok(Self::Petersburg),
            6 => Ok(Self::Istanbul),
            7 => Ok(Self::Berlin),
            8 => Ok(Self::London),
            9 => Ok(Self::Paris),
            10 => Ok(Self::Shanghai),
            11 => Ok(Self::Cancun),
            12 => Ok(Self::Prague),
            13 => Ok(Self::Osaka),
            14 => Ok(Self::Amsterdam),
            tag => Err(WireError::InvalidTag { field: "execution_fork", tag }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockIdentity {
    pub number: u64,
    pub hash: Hash32,
    pub parent_hash: Hash32,
    pub state_root: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockExecutionContext {
    pub active_fork: ExecutionFork,
    pub timestamp: u64,
    /// Beacon-chain slot exposed to the EVM by Amsterdam/EIP-7843.
    pub slot_number: Option<u64>,
    pub fee_recipient: Address20,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub base_fee_per_gas: Word32,
    pub prev_randao: Hash32,
    pub difficulty: Word32,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub blob_base_fee: Option<Word32>,
    pub parent_beacon_block_root: Option<Hash32>,
    pub withdrawals_root: Option<Hash32>,
    pub requests_hash: Option<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDescriptor {
    pub identity: BlockIdentity,
    pub execution: BlockExecutionContext,
}

/// Identifies the exact immutable generation on which this transition stream starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamIdentity {
    pub chain_id: u64,
    pub genesis_hash: Hash32,
    pub seed_generation_id: Hash32,
    pub seed_sequence: u64,
    pub seed_anchor: BlockDescriptor,
}

/// Complete EVM BLOCKHASH window for one tip.
///
/// The entries are ascending by number and cover exactly
/// max(0, tip.number - 256)..tip.number. The final entry is the tip parent hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentBlockHashes {
    pub start_number: u64,
    pub hashes: Vec<Hash32>,
}

/// Normalized final-state changes. Account and slot keys use Reth storage-v2 semantics:
/// keccak(address) and keccak(slot), respectively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateChange {
    CodeInsert {
        code_hash: Hash32,
        bytecode: Vec<u8>,
    },
    AccountSet {
        account: Hash32,
        balance: Word32,
        nonce: u64,
        code_hash: Hash32,
    },
    /// Deletes the account and semantically wipes its complete storage namespace.
    AccountDelete {
        account: Hash32,
    },
    /// Wipes storage while allowing the account to remain or be recreated in the same block.
    StorageWipe {
        account: Hash32,
    },
    /// A nonzero storage value. Zero is invalid here and must use StorageClear.
    StorageSet {
        account: Hash32,
        slot: Hash32,
        value: Word32,
    },
    StorageClear {
        account: Hash32,
        slot: Hash32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddedBlock {
    pub block: BlockDescriptor,
    pub block_rlp: CanonicalBlockRlp,
    pub changes: Vec<StateChange>,
}

/// One atomic canonical transition.
///
/// Removed identities are newest-first. Added blocks are oldest-first. The common ancestor is not
/// itself removed or re-added. The explicit new tip descriptor also supplies execution context for
/// a pure rewind with no added blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionBatch {
    pub schema_version: u16,
    pub stream: StreamIdentity,
    pub sequence: u64,
    pub old_tip: BlockDescriptor,
    pub common_ancestor: BlockDescriptor,
    pub new_tip: BlockDescriptor,
    pub removed: Vec<BlockIdentity>,
    pub added: Vec<AddedBlock>,
    pub recent_block_hashes: RecentBlockHashes,
}

impl StreamIdentity {
    pub fn validate(&self) -> Result<(), WireError> {
        if self.chain_id == 0 {
            return Err(WireError::InvalidChainId);
        }
        if is_zero(&self.genesis_hash) {
            return Err(WireError::ZeroIdentity("genesis_hash"));
        }
        if is_zero(&self.seed_generation_id) {
            return Err(WireError::ZeroIdentity("seed_generation_id"));
        }
        self.seed_anchor.validate()?;
        if self.seed_anchor.identity.number == 0 &&
            self.seed_anchor.identity.hash != self.genesis_hash
        {
            return Err(WireError::GenesisAnchorMismatch);
        }
        Ok(())
    }
}

impl BlockIdentity {
    fn validate(&self) -> Result<(), WireError> {
        if is_zero(&self.hash) {
            return Err(WireError::ZeroIdentity("block_hash"));
        }
        if is_zero(&self.state_root) {
            return Err(WireError::ZeroIdentity("state_root"));
        }
        Ok(())
    }
}

impl BlockExecutionContext {
    fn validate(&self) -> Result<(), WireError> {
        if self.gas_limit == 0 {
            return Err(WireError::ZeroGasLimit);
        }
        if self.gas_used > self.gas_limit {
            return Err(WireError::GasUsedExceedsLimit {
                used: self.gas_used,
                limit: self.gas_limit,
            });
        }
        let blob_fields = [
            self.blob_gas_used.is_some(),
            self.excess_blob_gas.is_some(),
            self.blob_base_fee.is_some(),
        ];
        if blob_fields.iter().any(|present| *present) && !blob_fields.iter().all(|present| *present)
        {
            return Err(WireError::IncompleteBlobContext);
        }
        let cancun_or_later = self.active_fork >= ExecutionFork::Cancun;
        require_fork_field(
            "blob_context",
            blob_fields.iter().all(|present| *present),
            cancun_or_later,
        )?;
        require_fork_field(
            "parent_beacon_block_root",
            self.parent_beacon_block_root.is_some(),
            cancun_or_later,
        )?;
        require_fork_field(
            "withdrawals_root",
            self.withdrawals_root.is_some(),
            self.active_fork >= ExecutionFork::Shanghai,
        )?;
        require_fork_field(
            "requests_hash",
            self.requests_hash.is_some(),
            self.active_fork >= ExecutionFork::Prague,
        )?;
        require_fork_field(
            "slot_number",
            self.slot_number.is_some(),
            self.active_fork >= ExecutionFork::Amsterdam,
        )?;
        Ok(())
    }
}

impl BlockDescriptor {
    fn validate(&self) -> Result<(), WireError> {
        self.identity.validate()?;
        self.execution.validate()
    }
}

impl RecentBlockHashes {
    pub fn validate_for_tip(
        &self,
        tip: &BlockIdentity,
        limits: &DecodeLimits,
    ) -> Result<(), WireError> {
        check_limit("recent_block_hashes", self.hashes.len(), limits.max_recent_block_hashes)?;
        if self.hashes.len() > BLOCKHASH_WINDOW {
            return Err(WireError::LimitExceeded {
                field: "protocol_blockhash_window",
                value: self.hashes.len(),
                max: BLOCKHASH_WINDOW,
            });
        }
        let expected_len = usize::try_from(tip.number.min(BLOCKHASH_WINDOW as u64))
            .map_err(|_| WireError::LengthOverflow)?;
        let expected_start =
            tip.number.checked_sub(expected_len as u64).ok_or(WireError::LengthOverflow)?;
        if self.start_number != expected_start || self.hashes.len() != expected_len {
            return Err(WireError::InvalidBlockHashWindow {
                expected_start,
                expected_len,
                received_start: self.start_number,
                received_len: self.hashes.len(),
            });
        }
        if let Some(parent) = self.hashes.last() &&
            *parent != tip.parent_hash
        {
            return Err(WireError::BlockHashWindowParentMismatch);
        }
        if self.hashes.iter().any(is_zero) {
            return Err(WireError::ZeroIdentity("recent_block_hash"));
        }
        Ok(())
    }
}

impl TransitionBatch {
    pub fn validate(&self, limits: &DecodeLimits) -> Result<(), WireError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WireError::UnsupportedSchema(self.schema_version));
        }
        self.stream.validate()?;
        self.old_tip.validate()?;
        self.common_ancestor.validate()?;
        self.new_tip.validate()?;
        if self.sequence <= self.stream.seed_sequence {
            return Err(WireError::SequenceNotAfterSeed {
                seed: self.stream.seed_sequence,
                received: self.sequence,
            });
        }
        if self.removed.is_empty() && self.added.is_empty() {
            return Err(WireError::EmptyCanonicalUpdate);
        }
        check_limit("removed_blocks", self.removed.len(), limits.max_removed_blocks)?;
        check_limit("added_blocks", self.added.len(), limits.max_added_blocks)?;

        self.validate_removed_order()?;
        self.validate_added_order(limits)?;
        self.recent_block_hashes.validate_for_tip(&self.new_tip.identity, limits)?;
        if !self.recent_block_hashes.hashes.is_empty() &&
            self.recent_block_hashes.start_number == 0 &&
            self.recent_block_hashes.hashes.first() != Some(&self.stream.genesis_hash)
        {
            return Err(WireError::BlockHashWindowGenesisMismatch);
        }
        Ok(())
    }

    fn validate_removed_order(&self) -> Result<(), WireError> {
        for block in &self.removed {
            block.validate()?;
        }
        if self.common_ancestor.identity.number > self.old_tip.identity.number {
            return Err(WireError::InvalidCommonAncestor);
        }
        let expected_removed = self
            .old_tip
            .identity
            .number
            .checked_sub(self.common_ancestor.identity.number)
            .ok_or(WireError::InvalidCommonAncestor)?;
        let expected_removed =
            usize::try_from(expected_removed).map_err(|_| WireError::LengthOverflow)?;
        if self.removed.len() != expected_removed {
            return Err(WireError::RemovedOrder);
        }
        if self.removed.is_empty() {
            if self.common_ancestor != self.old_tip {
                return Err(WireError::InvalidCommonAncestor);
            }
            return Ok(());
        }
        if self.removed.first() != Some(&self.old_tip.identity) {
            return Err(WireError::RemovedOrder);
        }
        for pair in self.removed.windows(2) {
            let newer = &pair[0];
            let older = &pair[1];
            if newer.number.checked_sub(1) != Some(older.number) || newer.parent_hash != older.hash
            {
                return Err(WireError::RemovedOrder);
            }
        }
        let oldest_removed = self.removed.last().ok_or(WireError::RemovedOrder)?;
        if oldest_removed.number.checked_sub(1) != Some(self.common_ancestor.identity.number) ||
            oldest_removed.parent_hash != self.common_ancestor.identity.hash
        {
            return Err(WireError::RemovedOrder);
        }
        Ok(())
    }

    fn validate_added_order(&self, limits: &DecodeLimits) -> Result<(), WireError> {
        if self.common_ancestor.identity.number > self.new_tip.identity.number {
            return Err(WireError::InvalidCommonAncestor);
        }
        let expected_added = self
            .new_tip
            .identity
            .number
            .checked_sub(self.common_ancestor.identity.number)
            .ok_or(WireError::InvalidCommonAncestor)?;
        let expected_added =
            usize::try_from(expected_added).map_err(|_| WireError::LengthOverflow)?;
        if self.added.len() != expected_added {
            return Err(WireError::AddedOrder);
        }
        if self.added.is_empty() {
            if self.new_tip != self.common_ancestor {
                return Err(WireError::NewTipMismatch);
            }
            return Ok(());
        }

        let mut previous = &self.common_ancestor;
        let mut total_operations = 0usize;
        let mut total_block_rlp_bytes = 0usize;
        for added in &self.added {
            added.block.validate()?;
            validate_block_rlp(&added.block_rlp, limits)?;
            total_block_rlp_bytes = total_block_rlp_bytes
                .checked_add(added.block_rlp.len())
                .ok_or(WireError::LengthOverflow)?;
            check_limit(
                "total_block_rlp_bytes",
                total_block_rlp_bytes,
                limits.max_total_block_rlp_bytes,
            )?;
            if added.block.identity.number !=
                previous.identity.number.checked_add(1).ok_or(WireError::BlockNumberOverflow)? ||
                added.block.identity.parent_hash != previous.identity.hash
            {
                return Err(WireError::AddedOrder);
            }
            if added.block.execution.timestamp <= previous.execution.timestamp {
                return Err(WireError::NonIncreasingTimestamp);
            }
            if added.block.execution.active_fork < previous.execution.active_fork {
                return Err(WireError::ForkRegression);
            }
            check_limit(
                "operations_per_block",
                added.changes.len(),
                limits.max_operations_per_block,
            )?;
            total_operations = total_operations
                .checked_add(added.changes.len())
                .ok_or(WireError::LengthOverflow)?;
            check_limit("total_operations", total_operations, limits.max_total_operations)?;
            validate_changes(&added.changes, limits)?;
            previous = &added.block;
        }
        if previous != &self.new_tip {
            return Err(WireError::NewTipMismatch);
        }
        Ok(())
    }
}

fn validate_block_rlp(
    block_rlp: &CanonicalBlockRlp,
    limits: &DecodeLimits,
) -> Result<(), WireError> {
    if block_rlp.is_empty() {
        return Err(WireError::EmptyCanonicalBlockRlp);
    }
    check_limit("block_rlp_bytes", block_rlp.len(), limits.max_block_rlp_bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ChangeKey {
    class: u8,
    primary: Hash32,
    secondary: Hash32,
}

fn validate_changes(changes: &[StateChange], limits: &DecodeLimits) -> Result<(), WireError> {
    let mut previous_key = None;
    let mut deleted_accounts = Vec::new();
    let deleted_count =
        changes.iter().filter(|change| matches!(change, StateChange::AccountDelete { .. })).count();
    deleted_accounts.try_reserve_exact(deleted_count).map_err(|_| WireError::AllocationFailed)?;
    for change in changes {
        let key = change_key(change);
        if previous_key.is_some_and(|previous| previous >= key) {
            return Err(WireError::NonCanonicalChangeOrder);
        }
        previous_key = Some(key);

        match change {
            StateChange::CodeInsert { code_hash, bytecode } => {
                check_limit("code_bytes", bytecode.len(), limits.max_code_bytes)?;
                if bytecode.is_empty() {
                    return Err(WireError::EmptyCodeInsert);
                }
                let actual = keccak256(bytecode);
                if actual != *code_hash {
                    return Err(WireError::CodeHashMismatch { expected: *code_hash, actual });
                }
            }
            StateChange::AccountDelete { account } => deleted_accounts.push(*account),
            StateChange::StorageSet { value, .. } if is_zero(value) => {
                return Err(WireError::ZeroStorageSet);
            }
            StateChange::AccountSet { .. } |
            StateChange::StorageWipe { .. } |
            StateChange::StorageSet { .. } |
            StateChange::StorageClear { .. } => {}
        }
    }
    for change in changes {
        let account = match change {
            StateChange::StorageWipe { account } |
            StateChange::StorageSet { account, .. } |
            StateChange::StorageClear { account, .. } => Some(account),
            StateChange::CodeInsert { .. } |
            StateChange::AccountSet { .. } |
            StateChange::AccountDelete { .. } => None,
        };
        if account.is_some_and(|account| deleted_accounts.binary_search(account).is_ok()) {
            return Err(WireError::StorageForDeletedAccount);
        }
    }
    Ok(())
}

fn change_key(change: &StateChange) -> ChangeKey {
    match change {
        StateChange::CodeInsert { code_hash, .. } => {
            ChangeKey { class: 0, primary: *code_hash, secondary: [0; 32] }
        }
        StateChange::AccountSet { account, .. } | StateChange::AccountDelete { account } => {
            ChangeKey { class: 1, primary: *account, secondary: [0; 32] }
        }
        StateChange::StorageWipe { account } => {
            ChangeKey { class: 2, primary: *account, secondary: [0; 32] }
        }
        StateChange::StorageSet { account, slot, .. } |
        StateChange::StorageClear { account, slot } => {
            ChangeKey { class: 3, primary: *account, secondary: *slot }
        }
    }
}

fn check_limit(field: &'static str, value: usize, max: usize) -> Result<(), WireError> {
    if value > max {
        Err(WireError::LimitExceeded { field, value, max })
    } else {
        Ok(())
    }
}

fn descriptors_are_contiguous(
    older: &BlockDescriptor,
    newer: &BlockDescriptor,
) -> Result<bool, WireError> {
    Ok(newer.identity.number ==
        older.identity.number.checked_add(1).ok_or(WireError::BlockNumberOverflow)? &&
        newer.identity.parent_hash == older.identity.hash &&
        newer.execution.timestamp > older.execution.timestamp &&
        newer.execution.active_fork >= older.execution.active_fork)
}

fn require_fork_field(field: &'static str, present: bool, required: bool) -> Result<(), WireError> {
    match (present, required) {
        (false, true) => Err(WireError::MissingForkContext(field)),
        (true, false) => Err(WireError::UnexpectedForkContext(field)),
        _ => Ok(()),
    }
}

fn is_zero(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn keccak256(bytes: &[u8]) -> Hash32 {
    Keccak256::digest(bytes).into()
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("unsupported transition schema {0}")]
    UnsupportedSchema(u16),
    #[error("unsupported frame flags {0}")]
    UnsupportedFlags(u16),
    #[error("frame is truncated: needed {needed} bytes, received {received}")]
    Truncated { needed: usize, received: usize },
    #[error("frame contains {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("frame size {declared} exceeds configured maximum {max}")]
    FrameTooLarge { declared: usize, max: usize },
    #[error("frame length arithmetic overflow")]
    LengthOverflow,
    #[error(
        "{field} declares {count} items requiring at least {required} bytes, but only {remaining} bytes remain"
    )]
    CountExceedsRemaining { field: &'static str, count: usize, required: usize, remaining: usize },
    #[error("encoded {field} length differs from preflight: expected {expected}, wrote {actual}")]
    EncodedLengthMismatch { field: &'static str, expected: usize, actual: usize },
    #[error("failed to reserve bounded decode storage")]
    AllocationFailed,
    #[error("frame checksum mismatch")]
    ChecksumMismatch { expected: Hash32, received: Hash32 },
    #[error("invalid {field} tag {tag}")]
    InvalidTag { field: &'static str, tag: u8 },
    #[error("{field} count {value} exceeds maximum {max}")]
    LimitExceeded { field: &'static str, value: usize, max: usize },
    #[error("chain ID must be nonzero")]
    InvalidChainId,
    #[error("{0} must be nonzero")]
    ZeroIdentity(&'static str),
    #[error("genesis seed anchor hash differs from genesis hash")]
    GenesisAnchorMismatch,
    #[error("block gas limit must be nonzero")]
    ZeroGasLimit,
    #[error("block gas used {used} exceeds gas limit {limit}")]
    GasUsedExceedsLimit { used: u64, limit: u64 },
    #[error("blob gas used, excess blob gas, and blob base fee must be present together")]
    IncompleteBlobContext,
    #[error("active fork requires execution-context field {0}")]
    MissingForkContext(&'static str),
    #[error("execution-context field {0} is not valid for the active fork")]
    UnexpectedForkContext(&'static str),
    #[error("sequence {received} is not after seed sequence {seed}")]
    SequenceNotAfterSeed { seed: u64, received: u64 },
    #[error("canonical transition removes and adds no blocks")]
    EmptyCanonicalUpdate,
    #[error("common ancestor is inconsistent with canonical tips")]
    InvalidCommonAncestor,
    #[error("removed blocks are not newest-first from the old tip to the common ancestor")]
    RemovedOrder,
    #[error("added blocks are not oldest-first from the common ancestor")]
    AddedOrder,
    #[error("explicit new tip differs from the final added block or common ancestor")]
    NewTipMismatch,
    #[error("block number overflow")]
    BlockNumberOverflow,
    #[error("added block timestamps must strictly increase")]
    NonIncreasingTimestamp,
    #[error("active execution fork regressed across added blocks")]
    ForkRegression,
    #[error("canonical full-block RLP must not be empty")]
    EmptyCanonicalBlockRlp,
    #[error("state changes are not in canonical code/account/wipe/storage key order")]
    NonCanonicalChangeOrder,
    #[error("code insert contains empty bytecode")]
    EmptyCodeInsert,
    #[error("code hash mismatch")]
    CodeHashMismatch { expected: Hash32, actual: Hash32 },
    #[error("StorageSet cannot encode zero; use StorageClear")]
    ZeroStorageSet,
    #[error("storage change targets an account deleted in the same normalized block")]
    StorageForDeletedAccount,
    #[error(
        "invalid BLOCKHASH window: expected start {expected_start} and length {expected_len}, received start {received_start} and length {received_len}"
    )]
    InvalidBlockHashWindow {
        expected_start: u64,
        expected_len: usize,
        received_start: u64,
        received_len: usize,
    },
    #[error("last BLOCKHASH entry differs from the new tip parent hash")]
    BlockHashWindowParentMismatch,
    #[error("first genesis-spanning BLOCKHASH entry differs from stream genesis hash")]
    BlockHashWindowGenesisMismatch,
    #[error("transition stream identity differs from cursor seed binding")]
    StreamMismatch,
    #[error("sequence gap: expected {expected}, received {received}")]
    SequenceGap { expected: u64, received: u64 },
    #[error("stream sequence overflow")]
    SequenceOverflow,
    #[error("stale sequence {received}; durable checkpoint is {checkpoint}")]
    StaleSequence { checkpoint: u64, received: u64 },
    #[error("sequence {sequence} was retransmitted with a different generation or frame digest")]
    ConflictingRetransmission { sequence: u64 },
    #[error("transition old tip differs from cursor tip")]
    OldTipMismatch,
    #[error("reorg common ancestor is outside retained cursor history")]
    RollbackBeyondCursorHistory,
    #[error("reorg common ancestor differs from retained cursor history")]
    CursorCommonAncestorMismatch,
    #[error("removed block identity differs from retained cursor history")]
    CursorRemovedHistoryMismatch,
    #[error("cursor history limit must be nonzero")]
    ZeroHistoryLimit,
    #[error("receiver checkpoint canonical history is invalid")]
    InvalidCheckpointHistory,
    #[error("receiver checkpoint ACK does not match its stream, sequence, or tip")]
    InvalidCheckpointAck,
}

/// A decoded frame plus the digest used for receiver idempotency checkpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFrame {
    pub batch: TransitionBatch,
    pub frame_digest: Hash32,
}

/// Exact receiver checkpoint returned to the producer only after durable acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionAck {
    pub seed_generation_id: Hash32,
    pub sequence: u64,
    pub frame_digest: Hash32,
    pub new_tip: BlockIdentity,
}

/// Cross-version receiver state that must be persisted with the applied generation.
///
/// This module validates and reconstructs it but does not choose a database, transaction, or ACK
/// transport. Applications may wrap it in their own durable record format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverCheckpoint {
    pub stream: StreamIdentity,
    pub sequence: u64,
    pub tip: BlockDescriptor,
    pub canonical_history: Vec<BlockDescriptor>,
    pub history_limit: usize,
    pub last_ack: Option<TransitionAck>,
}

/// A receiver decision is intentionally two-phase.
///
/// For Apply, the caller must atomically persist the state transition and next_cursor checkpoint,
/// then install next_cursor and return ack. If persistence fails, it must discard the candidate and
/// fail closed. Idempotent returns the prior ACK and performs no application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverDecision {
    Apply { next_cursor: Box<TransitionCursor>, ack: TransitionAck },
    Idempotent { ack: TransitionAck },
}

/// Stateful semantic checkpoint for gap detection, exact retransmission, and bounded reorg order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionCursor {
    stream: StreamIdentity,
    sequence: u64,
    tip: BlockDescriptor,
    history: VecDeque<BlockDescriptor>,
    history_limit: usize,
    last_ack: Option<TransitionAck>,
}

impl TransitionCursor {
    pub fn new(stream: StreamIdentity) -> Result<Self, WireError> {
        Self::with_history_limit(stream, DecodeLimits::default().max_removed_blocks + 1)
    }

    pub fn with_history_limit(
        stream: StreamIdentity,
        history_limit: usize,
    ) -> Result<Self, WireError> {
        if history_limit == 0 {
            return Err(WireError::ZeroHistoryLimit);
        }
        stream.validate()?;
        let seed_anchor = stream.seed_anchor.clone();
        Ok(Self {
            sequence: stream.seed_sequence,
            tip: seed_anchor.clone(),
            history: VecDeque::from([seed_anchor]),
            stream,
            history_limit,
            last_ack: None,
        })
    }

    pub fn from_checkpoint(checkpoint: ReceiverCheckpoint) -> Result<Self, WireError> {
        checkpoint.stream.validate()?;
        if checkpoint.history_limit == 0 {
            return Err(WireError::ZeroHistoryLimit);
        }
        if checkpoint.canonical_history.is_empty() ||
            checkpoint.canonical_history.len() > checkpoint.history_limit
        {
            return Err(WireError::InvalidCheckpointHistory);
        }
        for block in &checkpoint.canonical_history {
            block.validate()?;
            if block.identity.number < checkpoint.stream.seed_anchor.identity.number ||
                (block.identity.number == checkpoint.stream.seed_anchor.identity.number &&
                    block != &checkpoint.stream.seed_anchor)
            {
                return Err(WireError::InvalidCheckpointHistory);
            }
        }
        for pair in checkpoint.canonical_history.windows(2) {
            if !descriptors_are_contiguous(&pair[0], &pair[1])? {
                return Err(WireError::InvalidCheckpointHistory);
            }
        }
        if checkpoint.canonical_history.last() != Some(&checkpoint.tip) {
            return Err(WireError::InvalidCheckpointHistory);
        }
        if checkpoint.sequence < checkpoint.stream.seed_sequence {
            return Err(WireError::InvalidCheckpointAck);
        }
        if checkpoint.sequence == checkpoint.stream.seed_sequence &&
            checkpoint.canonical_history.as_slice() !=
                std::slice::from_ref(&checkpoint.stream.seed_anchor)
        {
            return Err(WireError::InvalidCheckpointHistory);
        }
        match &checkpoint.last_ack {
            None if checkpoint.sequence == checkpoint.stream.seed_sequence &&
                checkpoint.tip == checkpoint.stream.seed_anchor => {}
            Some(ack)
                if checkpoint.sequence > checkpoint.stream.seed_sequence &&
                    ack.seed_generation_id == checkpoint.stream.seed_generation_id &&
                    ack.sequence == checkpoint.sequence &&
                    ack.new_tip == checkpoint.tip.identity => {}
            _ => return Err(WireError::InvalidCheckpointAck),
        }
        Ok(Self {
            stream: checkpoint.stream,
            sequence: checkpoint.sequence,
            tip: checkpoint.tip,
            history: checkpoint.canonical_history.into(),
            history_limit: checkpoint.history_limit,
            last_ack: checkpoint.last_ack,
        })
    }

    pub const fn stream(&self) -> &StreamIdentity {
        &self.stream
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn tip(&self) -> &BlockDescriptor {
        &self.tip
    }

    pub const fn last_ack(&self) -> Option<&TransitionAck> {
        self.last_ack.as_ref()
    }

    pub fn checkpoint(&self) -> ReceiverCheckpoint {
        ReceiverCheckpoint {
            stream: self.stream.clone(),
            sequence: self.sequence,
            tip: self.tip.clone(),
            canonical_history: self.history.iter().cloned().collect(),
            history_limit: self.history_limit,
            last_ack: self.last_ack.clone(),
        }
    }

    /// Evaluates a frame without mutating the durable checkpoint represented by self.
    pub fn evaluate_frame(
        &self,
        frame: &[u8],
        limits: &DecodeLimits,
    ) -> Result<ReceiverDecision, WireError> {
        let decoded = decode_frame_with_limits(frame, limits)?;
        self.evaluate_decoded(decoded, limits)
    }

    fn evaluate_decoded(
        &self,
        decoded: DecodedFrame,
        limits: &DecodeLimits,
    ) -> Result<ReceiverDecision, WireError> {
        decoded.batch.validate(limits)?;
        if decoded.batch.stream != self.stream {
            return Err(WireError::StreamMismatch);
        }

        if decoded.batch.sequence == self.sequence {
            let Some(last_ack) = &self.last_ack else {
                return Err(WireError::ConflictingRetransmission {
                    sequence: decoded.batch.sequence,
                });
            };
            if last_ack.seed_generation_id == decoded.batch.stream.seed_generation_id &&
                last_ack.sequence == decoded.batch.sequence &&
                last_ack.frame_digest == decoded.frame_digest
            {
                return Ok(ReceiverDecision::Idempotent { ack: last_ack.clone() });
            }
            return Err(WireError::ConflictingRetransmission { sequence: decoded.batch.sequence });
        }
        if decoded.batch.sequence < self.sequence {
            return Err(WireError::StaleSequence {
                checkpoint: self.sequence,
                received: decoded.batch.sequence,
            });
        }
        let expected_sequence = self.sequence.checked_add(1).ok_or(WireError::SequenceOverflow)?;
        if decoded.batch.sequence != expected_sequence {
            return Err(WireError::SequenceGap {
                expected: expected_sequence,
                received: decoded.batch.sequence,
            });
        }
        if decoded.batch.old_tip != self.tip {
            return Err(WireError::OldTipMismatch);
        }
        if decoded.batch.removed.len() >= self.history.len() {
            return Err(WireError::RollbackBeyondCursorHistory);
        }
        for (removed, retained) in decoded.batch.removed.iter().zip(self.history.iter().rev()) {
            if removed != &retained.identity {
                return Err(WireError::CursorRemovedHistoryMismatch);
            }
        }
        let common_index = self
            .history
            .len()
            .checked_sub(decoded.batch.removed.len() + 1)
            .ok_or(WireError::RollbackBeyondCursorHistory)?;
        if self.history.get(common_index) != Some(&decoded.batch.common_ancestor) {
            return Err(WireError::CursorCommonAncestorMismatch);
        }

        let mut next = self.clone();
        for _ in 0..decoded.batch.removed.len() {
            next.history.pop_back();
        }
        for added in &decoded.batch.added {
            next.history.push_back(added.block.clone());
        }
        while next.history.len() > next.history_limit {
            next.history.pop_front();
        }
        next.sequence = decoded.batch.sequence;
        next.tip = decoded.batch.new_tip.clone();
        let ack = TransitionAck {
            seed_generation_id: next.stream.seed_generation_id,
            sequence: next.sequence,
            frame_digest: decoded.frame_digest,
            new_tip: next.tip.identity.clone(),
        };
        next.last_ack = Some(ack.clone());
        Ok(ReceiverDecision::Apply { next_cursor: Box::new(next), ack })
    }
}

/// Encodes and validates one exact frame using default production bounds.
pub fn encode_frame(batch: &TransitionBatch) -> Result<Vec<u8>, WireError> {
    encode_frame_with_limits(batch, &DecodeLimits::default())
}

/// Encodes and validates one exact frame using caller-provided bounds.
pub fn encode_frame_with_limits(
    batch: &TransitionBatch,
    limits: &DecodeLimits,
) -> Result<Vec<u8>, WireError> {
    batch.validate(limits)?;

    let expected_payload_len = encoded_payload_len(batch)?;
    let payload_len = u32::try_from(expected_payload_len).map_err(|_| WireError::LengthOverflow)?;
    let frame_len = encoded_frame_len(expected_payload_len)?;
    if frame_len > limits.max_frame_bytes {
        return Err(WireError::FrameTooLarge { declared: frame_len, max: limits.max_frame_bytes });
    }

    let mut payload = Vec::new();
    payload.try_reserve_exact(expected_payload_len).map_err(|_| WireError::AllocationFailed)?;
    encode_stream_identity(&mut payload, &batch.stream)?;
    put_u64(&mut payload, batch.sequence);
    encode_block_descriptor(&mut payload, &batch.old_tip);
    encode_block_descriptor(&mut payload, &batch.common_ancestor);
    encode_block_descriptor(&mut payload, &batch.new_tip);
    put_len(&mut payload, batch.removed.len())?;
    for block in &batch.removed {
        encode_block_identity(&mut payload, block);
    }
    put_len(&mut payload, batch.added.len())?;
    for added in &batch.added {
        encode_block_descriptor(&mut payload, &added.block);
        put_len(&mut payload, added.block_rlp.len())?;
        payload.extend_from_slice(added.block_rlp.as_slice());
        put_len(&mut payload, added.changes.len())?;
        for change in &added.changes {
            encode_change(&mut payload, change)?;
        }
    }
    encode_recent_hashes(&mut payload, &batch.recent_block_hashes)?;
    if payload.len() != expected_payload_len {
        return Err(WireError::EncodedLengthMismatch {
            field: "payload",
            expected: expected_payload_len,
            actual: payload.len(),
        });
    }

    let mut frame = Vec::new();
    frame.try_reserve_exact(frame_len).map_err(|_| WireError::AllocationFailed)?;
    frame.extend_from_slice(&FRAME_MAGIC);
    put_u16(&mut frame, batch.schema_version);
    put_u16(&mut frame, FRAME_FLAGS);
    put_u32(&mut frame, payload_len);
    frame.extend_from_slice(&payload);
    let checksum = compute_frame_digest(&frame);
    frame.extend_from_slice(&checksum);
    if frame.len() != frame_len {
        return Err(WireError::EncodedLengthMismatch {
            field: "frame",
            expected: frame_len,
            actual: frame.len(),
        });
    }
    Ok(frame)
}

/// Returns the exact TIPWIRE2 payload bytes occupied by one added block.
///
/// This measures only the encoding. Callers must still validate the block and configured bounds.
/// The result can be accumulated once per block and passed to
/// [`encoded_forward_frame_len`] to size candidate forward chunks in linear time.
pub fn encoded_added_block_len(added: &AddedBlock) -> Result<usize, WireError> {
    let mut length = 0usize;
    add_encoded_len(&mut length, encoded_block_descriptor_len(&added.block)?)?;
    check_wire_count(added.block_rlp.len())?;
    add_encoded_len(&mut length, 4)?;
    add_encoded_len(&mut length, added.block_rlp.len())?;
    check_wire_count(added.changes.len())?;
    add_encoded_len(&mut length, 4)?;
    for change in &added.changes {
        add_encoded_len(&mut length, encoded_change_len(change)?)?;
    }
    Ok(length)
}

/// Returns the exact total TIPWIRE2 frame bytes for a pure forward transition.
///
/// `encoded_added_blocks_len` must be the checked sum of [`encoded_added_block_len`] for the
/// `added_count` consecutive blocks, and `new_tip` must be the final one. This split interface lets
/// a producer evaluate each additional block in constant time without duplicating the wire
/// format's length formula. Semantic validation remains the responsibility of frame encoding.
pub fn encoded_forward_frame_len(
    stream: &StreamIdentity,
    old_tip: &BlockDescriptor,
    new_tip: &BlockDescriptor,
    added_count: usize,
    encoded_added_blocks_len: usize,
) -> Result<usize, WireError> {
    if added_count == 0 {
        return Err(WireError::EmptyCanonicalUpdate);
    }
    let recent_hash_count = usize::try_from(new_tip.identity.number.min(BLOCKHASH_WINDOW as u64))
        .map_err(|_| WireError::LengthOverflow)?;
    let payload_len = encoded_transition_payload_len(
        stream,
        old_tip,
        old_tip,
        new_tip,
        0,
        added_count,
        encoded_added_blocks_len,
        recent_hash_count,
    )?;
    encoded_frame_len(payload_len)
}

fn encoded_payload_len(batch: &TransitionBatch) -> Result<usize, WireError> {
    let mut encoded_added_blocks_len = 0usize;
    for added in &batch.added {
        add_encoded_len(&mut encoded_added_blocks_len, encoded_added_block_len(added)?)?;
    }
    encoded_transition_payload_len(
        &batch.stream,
        &batch.old_tip,
        &batch.common_ancestor,
        &batch.new_tip,
        batch.removed.len(),
        batch.added.len(),
        encoded_added_blocks_len,
        batch.recent_block_hashes.hashes.len(),
    )
}

#[allow(clippy::too_many_arguments)]
fn encoded_transition_payload_len(
    stream: &StreamIdentity,
    old_tip: &BlockDescriptor,
    common_ancestor: &BlockDescriptor,
    new_tip: &BlockDescriptor,
    removed_count: usize,
    added_count: usize,
    encoded_added_blocks_len: usize,
    recent_hash_count: usize,
) -> Result<usize, WireError> {
    let mut length = 0usize;

    add_encoded_len(&mut length, 8 + 32 + 32 + 8)?;
    add_encoded_len(&mut length, encoded_block_descriptor_len(&stream.seed_anchor)?)?;
    add_encoded_len(&mut length, 8)?;
    for block in [old_tip, common_ancestor, new_tip] {
        add_encoded_len(&mut length, encoded_block_descriptor_len(block)?)?;
    }

    check_wire_count(removed_count)?;
    add_encoded_len(&mut length, 4)?;
    add_encoded_len(
        &mut length,
        checked_encoded_product(removed_count, BLOCK_IDENTITY_ENCODED_BYTES)?,
    )?;

    check_wire_count(added_count)?;
    add_encoded_len(&mut length, 4)?;
    add_encoded_len(&mut length, encoded_added_blocks_len)?;

    add_encoded_len(&mut length, 8)?;
    check_wire_count(recent_hash_count)?;
    add_encoded_len(&mut length, 4)?;
    add_encoded_len(&mut length, checked_encoded_product(recent_hash_count, 32)?)?;
    Ok(length)
}

fn encoded_frame_len(payload_len: usize) -> Result<usize, WireError> {
    u32::try_from(payload_len).map_err(|_| WireError::LengthOverflow)?;
    FRAME_HEADER_BYTES
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(FRAME_CHECKSUM_BYTES))
        .ok_or(WireError::LengthOverflow)
}

fn encoded_block_descriptor_len(block: &BlockDescriptor) -> Result<usize, WireError> {
    BLOCK_IDENTITY_ENCODED_BYTES
        .checked_add(encoded_execution_context_len(&block.execution)?)
        .ok_or(WireError::LengthOverflow)
}

fn encoded_execution_context_len(context: &BlockExecutionContext) -> Result<usize, WireError> {
    let mut length = MIN_EXECUTION_CONTEXT_ENCODED_BYTES;
    for present in [
        context.slot_number.is_some(),
        context.blob_gas_used.is_some(),
        context.excess_blob_gas.is_some(),
    ] {
        if present {
            add_encoded_len(&mut length, 8)?;
        }
    }
    for present in [
        context.blob_base_fee.is_some(),
        context.parent_beacon_block_root.is_some(),
        context.withdrawals_root.is_some(),
        context.requests_hash.is_some(),
    ] {
        if present {
            add_encoded_len(&mut length, 32)?;
        }
    }
    Ok(length)
}

fn encoded_change_len(change: &StateChange) -> Result<usize, WireError> {
    match change {
        StateChange::CodeInsert { bytecode, .. } => {
            check_wire_count(bytecode.len())?;
            (1usize + 32 + 4).checked_add(bytecode.len()).ok_or(WireError::LengthOverflow)
        }
        StateChange::AccountSet { .. } => Ok(1 + 32 + 32 + 8 + 32),
        StateChange::AccountDelete { .. } | StateChange::StorageWipe { .. } => {
            Ok(MIN_STATE_CHANGE_ENCODED_BYTES)
        }
        StateChange::StorageSet { .. } => Ok(1 + 32 + 32 + 32),
        StateChange::StorageClear { .. } => Ok(1 + 32 + 32),
    }
}

fn check_wire_count(value: usize) -> Result<(), WireError> {
    u32::try_from(value).map(|_| ()).map_err(|_| WireError::LengthOverflow)
}

fn add_encoded_len(total: &mut usize, additional: usize) -> Result<(), WireError> {
    *total = total.checked_add(additional).ok_or(WireError::LengthOverflow)?;
    Ok(())
}

fn checked_encoded_product(count: usize, width: usize) -> Result<usize, WireError> {
    count.checked_mul(width).ok_or(WireError::LengthOverflow)
}

/// Decodes one complete frame with default production bounds.
pub fn decode_frame(frame: &[u8]) -> Result<DecodedFrame, WireError> {
    decode_frame_with_limits(frame, &DecodeLimits::default())
}

/// Decodes exactly one frame. It checks declared size before allocating vectors or bytecode.
pub fn decode_frame_with_limits(
    frame: &[u8],
    limits: &DecodeLimits,
) -> Result<DecodedFrame, WireError> {
    if frame.len() > limits.max_frame_bytes {
        return Err(WireError::FrameTooLarge { declared: frame.len(), max: limits.max_frame_bytes });
    }
    if frame.len() < FRAME_HEADER_BYTES {
        return Err(WireError::Truncated { needed: FRAME_HEADER_BYTES, received: frame.len() });
    }
    if frame[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(WireError::InvalidMagic);
    }
    let schema_version = u16::from_be_bytes([frame[8], frame[9]]);
    if schema_version != SCHEMA_VERSION {
        return Err(WireError::UnsupportedSchema(schema_version));
    }
    let flags = u16::from_be_bytes([frame[10], frame[11]]);
    if flags != FRAME_FLAGS {
        return Err(WireError::UnsupportedFlags(flags));
    }
    let payload_len = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]) as usize;
    let declared_len = FRAME_HEADER_BYTES
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(FRAME_CHECKSUM_BYTES))
        .ok_or(WireError::LengthOverflow)?;
    if declared_len > limits.max_frame_bytes {
        return Err(WireError::FrameTooLarge {
            declared: declared_len,
            max: limits.max_frame_bytes,
        });
    }
    if frame.len() < declared_len {
        return Err(WireError::Truncated { needed: declared_len, received: frame.len() });
    }
    if frame.len() > declared_len {
        return Err(WireError::TrailingBytes(frame.len() - declared_len));
    }

    let checksum_start = FRAME_HEADER_BYTES + payload_len;
    let received: Hash32 =
        frame[checksum_start..declared_len].try_into().map_err(|_| WireError::LengthOverflow)?;
    let expected = compute_frame_digest(&frame[..checksum_start]);
    if received != expected {
        return Err(WireError::ChecksumMismatch { expected, received });
    }

    let mut reader = Reader::new(&frame[FRAME_HEADER_BYTES..checksum_start], limits);
    let batch = decode_batch(&mut reader, schema_version)?;
    if !reader.is_empty() {
        return Err(WireError::TrailingBytes(reader.remaining()));
    }
    batch.validate(limits)?;
    Ok(DecodedFrame { batch, frame_digest: received })
}

fn compute_frame_digest(header_and_payload: &[u8]) -> Hash32 {
    let mut hasher = Blake3Hasher::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(header_and_payload);
    *hasher.finalize().as_bytes()
}

fn encode_stream_identity(output: &mut Vec<u8>, stream: &StreamIdentity) -> Result<(), WireError> {
    put_u64(output, stream.chain_id);
    output.extend_from_slice(&stream.genesis_hash);
    output.extend_from_slice(&stream.seed_generation_id);
    put_u64(output, stream.seed_sequence);
    encode_block_descriptor(output, &stream.seed_anchor);
    Ok(())
}

fn encode_block_identity(output: &mut Vec<u8>, block: &BlockIdentity) {
    put_u64(output, block.number);
    output.extend_from_slice(&block.hash);
    output.extend_from_slice(&block.parent_hash);
    output.extend_from_slice(&block.state_root);
}

fn encode_block_descriptor(output: &mut Vec<u8>, block: &BlockDescriptor) {
    encode_block_identity(output, &block.identity);
    encode_execution_context(output, &block.execution);
}

fn encode_execution_context(output: &mut Vec<u8>, context: &BlockExecutionContext) {
    put_u8(output, context.active_fork as u8);
    put_u64(output, context.timestamp);
    put_option_u64(output, context.slot_number);
    output.extend_from_slice(&context.fee_recipient);
    put_u64(output, context.gas_limit);
    put_u64(output, context.gas_used);
    output.extend_from_slice(&context.base_fee_per_gas);
    output.extend_from_slice(&context.prev_randao);
    output.extend_from_slice(&context.difficulty);
    put_option_u64(output, context.blob_gas_used);
    put_option_u64(output, context.excess_blob_gas);
    put_option_hash(output, context.blob_base_fee.as_ref());
    put_option_hash(output, context.parent_beacon_block_root.as_ref());
    put_option_hash(output, context.withdrawals_root.as_ref());
    put_option_hash(output, context.requests_hash.as_ref());
}

fn encode_recent_hashes(output: &mut Vec<u8>, recent: &RecentBlockHashes) -> Result<(), WireError> {
    put_u64(output, recent.start_number);
    put_len(output, recent.hashes.len())?;
    for hash in &recent.hashes {
        output.extend_from_slice(hash);
    }
    Ok(())
}

fn encode_change(output: &mut Vec<u8>, change: &StateChange) -> Result<(), WireError> {
    match change {
        StateChange::CodeInsert { code_hash, bytecode } => {
            put_u8(output, 0);
            output.extend_from_slice(code_hash);
            put_len(output, bytecode.len())?;
            output.extend_from_slice(bytecode);
        }
        StateChange::AccountSet { account, balance, nonce, code_hash } => {
            put_u8(output, 1);
            output.extend_from_slice(account);
            output.extend_from_slice(balance);
            put_u64(output, *nonce);
            output.extend_from_slice(code_hash);
        }
        StateChange::AccountDelete { account } => {
            put_u8(output, 2);
            output.extend_from_slice(account);
        }
        StateChange::StorageWipe { account } => {
            put_u8(output, 3);
            output.extend_from_slice(account);
        }
        StateChange::StorageSet { account, slot, value } => {
            put_u8(output, 4);
            output.extend_from_slice(account);
            output.extend_from_slice(slot);
            output.extend_from_slice(value);
        }
        StateChange::StorageClear { account, slot } => {
            put_u8(output, 5);
            output.extend_from_slice(account);
            output.extend_from_slice(slot);
        }
    }
    Ok(())
}

fn put_option_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            put_u8(output, 1);
            put_u64(output, value);
        }
        None => put_u8(output, 0),
    }
}

fn put_option_hash(output: &mut Vec<u8>, value: Option<&Hash32>) {
    match value {
        Some(value) => {
            put_u8(output, 1);
            output.extend_from_slice(value);
        }
        None => put_u8(output, 0),
    }
}

fn put_u8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_len(output: &mut Vec<u8>, value: usize) -> Result<(), WireError> {
    put_u32(output, u32::try_from(value).map_err(|_| WireError::LengthOverflow)?);
    Ok(())
}

fn decode_batch(
    reader: &mut Reader<'_>,
    schema_version: u16,
) -> Result<TransitionBatch, WireError> {
    let stream = decode_stream_identity(reader)?;
    let sequence = reader.read_u64()?;
    let old_tip = decode_block_descriptor(reader)?;
    let common_ancestor = decode_block_descriptor(reader)?;
    let new_tip = decode_block_descriptor(reader)?;

    let removed_len = reader.read_count("removed_blocks", reader.limits.max_removed_blocks)?;
    reader.require_count_bytes("removed_blocks", removed_len, BLOCK_IDENTITY_ENCODED_BYTES)?;
    let mut removed = Vec::new();
    reserve(&mut removed, removed_len)?;
    for _ in 0..removed_len {
        removed.push(decode_block_identity(reader)?);
    }

    let added_len = reader.read_count("added_blocks", reader.limits.max_added_blocks)?;
    reader.require_count_bytes("added_blocks", added_len, MIN_ADDED_BLOCK_ENCODED_BYTES)?;
    let mut added = Vec::new();
    reserve(&mut added, added_len)?;
    let mut total_operations = 0usize;
    let mut total_block_rlp_bytes = 0usize;
    for _ in 0..added_len {
        let block = decode_block_descriptor(reader)?;
        let block_rlp_len =
            reader.read_count("block_rlp_bytes", reader.limits.max_block_rlp_bytes)?;
        if block_rlp_len == 0 {
            return Err(WireError::EmptyCanonicalBlockRlp);
        }
        total_block_rlp_bytes =
            total_block_rlp_bytes.checked_add(block_rlp_len).ok_or(WireError::LengthOverflow)?;
        check_limit(
            "total_block_rlp_bytes",
            total_block_rlp_bytes,
            reader.limits.max_total_block_rlp_bytes,
        )?;
        let encoded_block_rlp = reader.read_exact(block_rlp_len)?;
        let mut block_rlp = Vec::new();
        reserve(&mut block_rlp, block_rlp_len)?;
        block_rlp.extend_from_slice(encoded_block_rlp);
        let operation_len =
            reader.read_count("operations_per_block", reader.limits.max_operations_per_block)?;
        reader.require_count_bytes(
            "operations_per_block",
            operation_len,
            MIN_STATE_CHANGE_ENCODED_BYTES,
        )?;
        total_operations =
            total_operations.checked_add(operation_len).ok_or(WireError::LengthOverflow)?;
        check_limit("total_operations", total_operations, reader.limits.max_total_operations)?;
        let mut changes = Vec::new();
        reserve(&mut changes, operation_len)?;
        for _ in 0..operation_len {
            changes.push(decode_change(reader)?);
        }
        added.push(AddedBlock { block, block_rlp: CanonicalBlockRlp::new(block_rlp), changes });
    }
    let recent_block_hashes = decode_recent_hashes(reader)?;
    Ok(TransitionBatch {
        schema_version,
        stream,
        sequence,
        old_tip,
        common_ancestor,
        new_tip,
        removed,
        added,
        recent_block_hashes,
    })
}

fn decode_stream_identity(reader: &mut Reader<'_>) -> Result<StreamIdentity, WireError> {
    Ok(StreamIdentity {
        chain_id: reader.read_u64()?,
        genesis_hash: reader.read_hash()?,
        seed_generation_id: reader.read_hash()?,
        seed_sequence: reader.read_u64()?,
        seed_anchor: decode_block_descriptor(reader)?,
    })
}

fn decode_block_identity(reader: &mut Reader<'_>) -> Result<BlockIdentity, WireError> {
    Ok(BlockIdentity {
        number: reader.read_u64()?,
        hash: reader.read_hash()?,
        parent_hash: reader.read_hash()?,
        state_root: reader.read_hash()?,
    })
}

fn decode_block_descriptor(reader: &mut Reader<'_>) -> Result<BlockDescriptor, WireError> {
    Ok(BlockDescriptor {
        identity: decode_block_identity(reader)?,
        execution: decode_execution_context(reader)?,
    })
}

fn decode_execution_context(reader: &mut Reader<'_>) -> Result<BlockExecutionContext, WireError> {
    Ok(BlockExecutionContext {
        active_fork: ExecutionFork::try_from(reader.read_u8()?)?,
        timestamp: reader.read_u64()?,
        slot_number: reader.read_option_u64("slot_number")?,
        fee_recipient: reader.read_array()?,
        gas_limit: reader.read_u64()?,
        gas_used: reader.read_u64()?,
        base_fee_per_gas: reader.read_hash()?,
        prev_randao: reader.read_hash()?,
        difficulty: reader.read_hash()?,
        blob_gas_used: reader.read_option_u64("blob_gas_used")?,
        excess_blob_gas: reader.read_option_u64("excess_blob_gas")?,
        blob_base_fee: reader.read_option_hash("blob_base_fee")?,
        parent_beacon_block_root: reader.read_option_hash("parent_beacon_block_root")?,
        withdrawals_root: reader.read_option_hash("withdrawals_root")?,
        requests_hash: reader.read_option_hash("requests_hash")?,
    })
}

fn decode_recent_hashes(reader: &mut Reader<'_>) -> Result<RecentBlockHashes, WireError> {
    let start_number = reader.read_u64()?;
    let count = reader.read_count("recent_block_hashes", reader.limits.max_recent_block_hashes)?;
    reader.require_count_bytes("recent_block_hashes", count, 32)?;
    let mut hashes = Vec::new();
    reserve(&mut hashes, count)?;
    for _ in 0..count {
        hashes.push(reader.read_hash()?);
    }
    Ok(RecentBlockHashes { start_number, hashes })
}

fn decode_change(reader: &mut Reader<'_>) -> Result<StateChange, WireError> {
    match reader.read_u8()? {
        0 => {
            let code_hash = reader.read_hash()?;
            let length = reader.read_count("code_bytes", reader.limits.max_code_bytes)?;
            let bytecode = reader.read_exact(length)?.to_vec();
            Ok(StateChange::CodeInsert { code_hash, bytecode })
        }
        1 => Ok(StateChange::AccountSet {
            account: reader.read_hash()?,
            balance: reader.read_hash()?,
            nonce: reader.read_u64()?,
            code_hash: reader.read_hash()?,
        }),
        2 => Ok(StateChange::AccountDelete { account: reader.read_hash()? }),
        3 => Ok(StateChange::StorageWipe { account: reader.read_hash()? }),
        4 => Ok(StateChange::StorageSet {
            account: reader.read_hash()?,
            slot: reader.read_hash()?,
            value: reader.read_hash()?,
        }),
        5 => Ok(StateChange::StorageClear {
            account: reader.read_hash()?,
            slot: reader.read_hash()?,
        }),
        tag => Err(WireError::InvalidTag { field: "state_change", tag }),
    }
}

fn reserve<T>(values: &mut Vec<T>, additional: usize) -> Result<(), WireError> {
    values.try_reserve_exact(additional).map_err(|_| WireError::AllocationFailed)
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    limits: &'a DecodeLimits,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: &'a DecodeLimits) -> Self {
        Self { bytes, position: 0, limits }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let end = self.position.checked_add(length).ok_or(WireError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(WireError::Truncated { needed: end, received: self.bytes.len() });
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.read_exact(N)?.try_into().map_err(|_| WireError::LengthOverflow)
    }

    fn read_hash(&mut self) -> Result<Hash32, WireError> {
        self.read_array()
    }

    fn read_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_count(&mut self, field: &'static str, max: usize) -> Result<usize, WireError> {
        let value = self.read_u32()? as usize;
        check_limit(field, value, max)?;
        Ok(value)
    }

    fn require_count_bytes(
        &self,
        field: &'static str,
        count: usize,
        minimum_item_bytes: usize,
    ) -> Result<(), WireError> {
        let required = count.checked_mul(minimum_item_bytes).ok_or(WireError::LengthOverflow)?;
        let remaining = self.remaining();
        if required > remaining {
            return Err(WireError::CountExceedsRemaining { field, count, required, remaining });
        }
        Ok(())
    }

    fn read_option_u64(&mut self, field: &'static str) -> Result<Option<u64>, WireError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u64()?)),
            tag => Err(WireError::InvalidTag { field, tag }),
        }
    }

    fn read_option_hash(&mut self, field: &'static str) -> Result<Option<Hash32>, WireError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_hash()?)),
            tag => Err(WireError::InvalidTag { field, tag }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SEQUENCE: u64 = 700;

    fn hash(tag: u64) -> Hash32 {
        let mut value = [0u8; 32];
        value[24..].copy_from_slice(&tag.to_be_bytes());
        value
    }

    fn word(tag: u64) -> Word32 {
        hash(tag)
    }

    fn context(timestamp: u64) -> BlockExecutionContext {
        BlockExecutionContext {
            active_fork: ExecutionFork::Osaka,
            timestamp,
            slot_number: None,
            fee_recipient: [0x42; 20],
            gas_limit: 60_000_000,
            gas_used: 30_000_000,
            base_fee_per_gas: word(1_000_000_000),
            prev_randao: hash(timestamp + 10_000),
            difficulty: [0; 32],
            blob_gas_used: Some(0),
            excess_blob_gas: Some(100),
            blob_base_fee: Some(word(1)),
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

    fn stream() -> StreamIdentity {
        StreamIdentity {
            chain_id: 1,
            genesis_hash: hash(9),
            seed_generation_id: hash(99_999),
            seed_sequence: SEED_SEQUENCE,
            seed_anchor: block(2, 12, hash(11)),
        }
    }

    fn recent_for(tip: &BlockIdentity) -> RecentBlockHashes {
        assert_eq!(tip.number, 3);
        RecentBlockHashes { start_number: 0, hashes: vec![hash(9), hash(11), tip.parent_hash] }
    }

    fn changes() -> Vec<StateChange> {
        let bytecode = vec![0x60, 0x00, 0x56];
        let code_hash = keccak256(&bytecode);
        let account_a = hash(100);
        let account_b = hash(200);
        vec![
            StateChange::CodeInsert { code_hash, bytecode },
            StateChange::AccountSet {
                account: account_a,
                balance: word(1_000),
                nonce: 7,
                code_hash,
            },
            StateChange::AccountDelete { account: account_b },
            StateChange::StorageWipe { account: account_a },
            StateChange::StorageSet { account: account_a, slot: hash(300), value: word(44) },
            StateChange::StorageClear { account: account_a, slot: hash(301) },
        ]
    }

    fn block_rlp(tag: u8) -> CanonicalBlockRlp {
        CanonicalBlockRlp::new(vec![0xc3, 0xc0, 0xc0, tag])
    }

    fn forward_batch(sequence: u64) -> TransitionBatch {
        let stream = stream();
        let old_tip = stream.seed_anchor.clone();
        let new_tip = block(3, 13, old_tip.identity.hash);
        TransitionBatch {
            schema_version: SCHEMA_VERSION,
            stream,
            sequence,
            old_tip: old_tip.clone(),
            common_ancestor: old_tip,
            new_tip: new_tip.clone(),
            removed: Vec::new(),
            added: vec![AddedBlock {
                block: new_tip.clone(),
                block_rlp: block_rlp(13),
                changes: changes(),
            }],
            recent_block_hashes: recent_for(&new_tip.identity),
        }
    }

    fn reorg_batch(
        sequence: u64,
        old_tip: BlockDescriptor,
        common: BlockDescriptor,
    ) -> TransitionBatch {
        let new_tip = block(3, 30, common.identity.hash);
        TransitionBatch {
            schema_version: SCHEMA_VERSION,
            stream: stream(),
            sequence,
            old_tip: old_tip.clone(),
            common_ancestor: common,
            new_tip: new_tip.clone(),
            removed: vec![old_tip.identity],
            added: vec![AddedBlock {
                block: new_tip.clone(),
                block_rlp: block_rlp(30),
                changes: Vec::new(),
            }],
            recent_block_hashes: recent_for(&new_tip.identity),
        }
    }

    fn anchor_crossing_batch(common: BlockDescriptor) -> TransitionBatch {
        let stream = stream();
        let old_tip = stream.seed_anchor.clone();
        TransitionBatch {
            schema_version: SCHEMA_VERSION,
            stream,
            sequence: SEED_SEQUENCE + 1,
            old_tip: old_tip.clone(),
            common_ancestor: common.clone(),
            new_tip: common.clone(),
            removed: vec![old_tip.identity],
            added: Vec::new(),
            recent_block_hashes: RecentBlockHashes {
                start_number: 0,
                hashes: vec![common.identity.parent_hash],
            },
        }
    }

    #[test]
    fn deterministic_round_trip_covers_every_change_kind() {
        let batch = forward_batch(SEED_SEQUENCE + 1);
        let first = encode_frame(&batch).unwrap();
        let second = encode_frame(&batch).unwrap();
        assert_eq!(first, second);
        assert_eq!(&first[..8], &FRAME_MAGIC);
        assert_eq!(u16::from_be_bytes([first[8], first[9]]), SCHEMA_VERSION);

        let decoded = decode_frame(&first).unwrap();
        assert_eq!(decoded.batch, batch);
        assert_eq!(decoded.frame_digest, first[first.len() - FRAME_CHECKSUM_BYTES..]);
    }

    #[test]
    fn tamper_is_rejected_by_checksum() {
        let mut frame = encode_frame(&forward_batch(SEED_SEQUENCE + 1)).unwrap();
        frame[FRAME_HEADER_BYTES + 20] ^= 0x80;
        assert!(matches!(decode_frame(&frame), Err(WireError::ChecksumMismatch { .. })));
    }

    #[test]
    fn tipwire1_identity_is_rejected() {
        let frame = encode_frame(&forward_batch(SEED_SEQUENCE + 1)).unwrap();

        let mut old_magic = frame.clone();
        old_magic[..8].copy_from_slice(b"TIPWIRE1");
        assert_eq!(decode_frame(&old_magic), Err(WireError::InvalidMagic));

        let mut old_schema = frame;
        old_schema[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(decode_frame(&old_schema), Err(WireError::UnsupportedSchema(1)));
    }

    #[test]
    fn truncation_is_rejected_before_payload_decode() {
        let mut frame = encode_frame(&forward_batch(SEED_SEQUENCE + 1)).unwrap();
        frame.pop();
        assert!(matches!(decode_frame(&frame), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn oversized_declared_frame_is_rejected_without_allocation() {
        let limits = DecodeLimits { max_frame_bytes: 1_024, ..DecodeLimits::default() };
        let mut header = vec![0u8; FRAME_HEADER_BYTES];
        header[..8].copy_from_slice(&FRAME_MAGIC);
        header[8..10].copy_from_slice(&SCHEMA_VERSION.to_be_bytes());
        header[10..12].copy_from_slice(&FRAME_FLAGS.to_be_bytes());
        header[12..16].copy_from_slice(&2_048u32.to_be_bytes());
        assert_eq!(
            decode_frame_with_limits(&header, &limits),
            Err(WireError::FrameTooLarge {
                declared: FRAME_HEADER_BYTES + 2_048 + FRAME_CHECKSUM_BYTES,
                max: 1_024,
            })
        );
    }

    #[test]
    fn encoder_preflights_exact_frame_size() {
        let batch = forward_batch(SEED_SEQUENCE + 1);
        let payload_len = encoded_payload_len(&batch).unwrap();
        let expected_frame_len = FRAME_HEADER_BYTES + payload_len + FRAME_CHECKSUM_BYTES;
        let too_small =
            DecodeLimits { max_frame_bytes: expected_frame_len - 1, ..DecodeLimits::default() };
        assert_eq!(
            encode_frame_with_limits(&batch, &too_small),
            Err(WireError::FrameTooLarge {
                declared: expected_frame_len,
                max: expected_frame_len - 1,
            })
        );

        let exact = DecodeLimits { max_frame_bytes: expected_frame_len, ..DecodeLimits::default() };
        let frame = encode_frame_with_limits(&batch, &exact).unwrap();
        assert_eq!(frame.len(), expected_frame_len);
        assert_eq!(u32::from_be_bytes(frame[12..16].try_into().unwrap()) as usize, payload_len);
    }

    #[test]
    fn declared_collection_bytes_are_checked_before_reserve() {
        let mut frame = encode_frame(&forward_batch(SEED_SEQUENCE + 1)).unwrap();
        let checksum_start = frame.len() - FRAME_CHECKSUM_BYTES;
        let removed_count_offset = {
            let decode_limits = DecodeLimits::default();
            let mut reader =
                Reader::new(&frame[FRAME_HEADER_BYTES..checksum_start], &decode_limits);
            decode_stream_identity(&mut reader).unwrap();
            reader.read_u64().unwrap();
            decode_block_descriptor(&mut reader).unwrap();
            decode_block_descriptor(&mut reader).unwrap();
            decode_block_descriptor(&mut reader).unwrap();
            FRAME_HEADER_BYTES +
                (frame[FRAME_HEADER_BYTES..checksum_start].len() - reader.remaining())
        };
        let malicious_count = 1_000_000u32;
        frame[removed_count_offset..removed_count_offset + 4]
            .copy_from_slice(&malicious_count.to_be_bytes());
        let checksum = compute_frame_digest(&frame[..checksum_start]);
        frame[checksum_start..].copy_from_slice(&checksum);

        let limits = DecodeLimits {
            max_removed_blocks: malicious_count as usize,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            decode_frame_with_limits(&frame, &limits),
            Err(WireError::CountExceedsRemaining {
                field: "removed_blocks",
                count,
                required,
                remaining,
            }) if count == malicious_count as usize
                && required == malicious_count as usize * BLOCK_IDENTITY_ENCODED_BYTES
                && remaining < required
        ));
    }

    #[test]
    fn nested_code_limit_is_checked_before_bytecode_copy() {
        let frame = encode_frame(&forward_batch(SEED_SEQUENCE + 1)).unwrap();
        let limits = DecodeLimits { max_code_bytes: 2, ..DecodeLimits::default() };
        assert_eq!(
            decode_frame_with_limits(&frame, &limits),
            Err(WireError::LimitExceeded { field: "code_bytes", value: 3, max: 2 })
        );
    }

    #[test]
    fn canonical_block_rlp_limits_are_enforced_on_encode_and_decode() {
        let mut empty = forward_batch(SEED_SEQUENCE + 1);
        empty.added[0].block_rlp = CanonicalBlockRlp::new(Vec::new());
        assert_eq!(encode_frame(&empty), Err(WireError::EmptyCanonicalBlockRlp));

        let batch = forward_batch(SEED_SEQUENCE + 1);
        let per_block_limit = DecodeLimits {
            max_block_rlp_bytes: batch.added[0].block_rlp.len() - 1,
            ..DecodeLimits::default()
        };
        assert_eq!(
            encode_frame_with_limits(&batch, &per_block_limit),
            Err(WireError::LimitExceeded {
                field: "block_rlp_bytes",
                value: batch.added[0].block_rlp.len(),
                max: batch.added[0].block_rlp.len() - 1,
            })
        );

        let frame = encode_frame(&batch).unwrap();
        assert_eq!(
            decode_frame_with_limits(&frame, &per_block_limit),
            Err(WireError::LimitExceeded {
                field: "block_rlp_bytes",
                value: batch.added[0].block_rlp.len(),
                max: batch.added[0].block_rlp.len() - 1,
            })
        );
    }

    #[test]
    fn aggregate_canonical_block_rlp_limit_is_enforced() {
        let mut batch = forward_batch(SEED_SEQUENCE + 1);
        let block_three = batch.new_tip.clone();
        let block_four = block(4, 14, block_three.identity.hash);
        batch.new_tip = block_four.clone();
        batch.added.push(AddedBlock {
            block: block_four.clone(),
            block_rlp: block_rlp(14),
            changes: Vec::new(),
        });
        batch.recent_block_hashes = RecentBlockHashes {
            start_number: 0,
            hashes: vec![
                hash(9),
                hash(11),
                batch.stream.seed_anchor.identity.hash,
                block_three.identity.hash,
            ],
        };
        let total = batch.added.iter().map(|added| added.block_rlp.len()).sum::<usize>();
        let limits =
            DecodeLimits { max_total_block_rlp_bytes: total - 1, ..DecodeLimits::default() };
        assert_eq!(
            encode_frame_with_limits(&batch, &limits),
            Err(WireError::LimitExceeded {
                field: "total_block_rlp_bytes",
                value: total,
                max: total - 1,
            })
        );
        let frame = encode_frame(&batch).unwrap();
        assert_eq!(
            decode_frame_with_limits(&frame, &limits),
            Err(WireError::LimitExceeded {
                field: "total_block_rlp_bytes",
                value: total,
                max: total - 1,
            })
        );
    }

    #[test]
    fn forward_frame_length_uses_the_encoder_formula() {
        let batch = forward_batch(SEED_SEQUENCE + 1);
        let encoded_added_blocks_len = batch.added.iter().try_fold(0usize, |total, added| {
            total.checked_add(encoded_added_block_len(added)?).ok_or(WireError::LengthOverflow)
        });
        assert_eq!(
            encoded_forward_frame_len(
                &batch.stream,
                &batch.old_tip,
                &batch.new_tip,
                batch.added.len(),
                encoded_added_blocks_len.unwrap(),
            )
            .unwrap(),
            encode_frame(&batch).unwrap().len()
        );
    }

    #[test]
    fn zero_gas_limit_is_rejected() {
        let mut execution = context(12);
        execution.gas_limit = 0;
        assert_eq!(execution.validate(), Err(WireError::ZeroGasLimit));
    }

    #[test]
    fn noncanonical_change_and_reorg_order_are_rejected() {
        let limits = DecodeLimits::default();
        let mut bad_changes = forward_batch(SEED_SEQUENCE + 1);
        bad_changes.added[0].changes.swap(0, 1);
        assert_eq!(bad_changes.validate(&limits), Err(WireError::NonCanonicalChangeOrder));

        let old_tip = forward_batch(SEED_SEQUENCE + 1).new_tip;
        let mut bad_reorg = reorg_batch(SEED_SEQUENCE + 2, old_tip, stream().seed_anchor.clone());
        bad_reorg.removed[0] = stream().seed_anchor.identity;
        assert_eq!(bad_reorg.validate(&limits), Err(WireError::RemovedOrder));
    }

    #[test]
    fn cursor_detects_gap_and_accepts_post_anchor_reorg() {
        let limits = DecodeLimits::default();
        let seed = stream();
        let cursor = TransitionCursor::new(seed.clone()).unwrap();
        let gap_frame = encode_frame(&forward_batch(SEED_SEQUENCE + 2)).unwrap();
        assert!(matches!(
            cursor.evaluate_frame(&gap_frame, &limits),
            Err(WireError::SequenceGap { expected, received })
                if expected == SEED_SEQUENCE + 1 && received == SEED_SEQUENCE + 2
        ));

        let first_frame = encode_frame(&forward_batch(SEED_SEQUENCE + 1)).unwrap();
        let ReceiverDecision::Apply { next_cursor, ack: first_ack } =
            cursor.evaluate_frame(&first_frame, &limits).unwrap()
        else {
            panic!("first frame must apply");
        };
        assert_eq!(first_ack.sequence, SEED_SEQUENCE + 1);
        let next_cursor = TransitionCursor::from_checkpoint(next_cursor.checkpoint()).unwrap();
        let old_tip = next_cursor.tip().clone();
        let reorg = reorg_batch(SEED_SEQUENCE + 2, old_tip, seed.seed_anchor.clone());
        let reorg_frame = encode_frame(&reorg).unwrap();
        let ReceiverDecision::Apply { next_cursor: after_reorg, ack: reorg_ack } =
            next_cursor.evaluate_frame(&reorg_frame, &limits).unwrap()
        else {
            panic!("ordered reorg must apply");
        };
        assert_eq!(after_reorg.tip(), &reorg.new_tip);
        assert_eq!(reorg_ack.new_tip, reorg.new_tip.identity);
    }

    #[test]
    fn exact_retransmission_returns_prior_ack_but_digest_conflict_is_fatal() {
        let limits = DecodeLimits::default();
        let cursor = TransitionCursor::new(stream()).unwrap();
        let batch = forward_batch(SEED_SEQUENCE + 1);
        let frame = encode_frame(&batch).unwrap();
        let ReceiverDecision::Apply { next_cursor, ack: applied_ack } =
            cursor.evaluate_frame(&frame, &limits).unwrap()
        else {
            panic!("first frame must apply");
        };
        let next_cursor = TransitionCursor::from_checkpoint(next_cursor.checkpoint()).unwrap();

        let ReceiverDecision::Idempotent { ack: replayed_ack } =
            next_cursor.evaluate_frame(&frame, &limits).unwrap()
        else {
            panic!("exact frame must be idempotent");
        };
        assert_eq!(replayed_ack, applied_ack);

        let mut conflicting = batch;
        conflicting.new_tip = block(3, 31, conflicting.old_tip.identity.hash);
        conflicting.added[0].block = conflicting.new_tip.clone();
        conflicting.recent_block_hashes = recent_for(&conflicting.new_tip.identity);
        let conflicting_frame = encode_frame(&conflicting).unwrap();
        assert_eq!(
            next_cursor.evaluate_frame(&conflicting_frame, &limits),
            Err(WireError::ConflictingRetransmission { sequence: SEED_SEQUENCE + 1 })
        );
    }

    #[test]
    fn cursor_seed_anchor_is_hard_floor_and_seed_checkpoint_is_anchor_only() {
        let limits = DecodeLimits::default();
        let stream = stream();
        let block_one = block(1, 11, stream.genesis_hash);
        let cursor = TransitionCursor::with_history_limit(stream.clone(), 2).unwrap();
        assert_eq!(cursor.checkpoint().canonical_history, vec![stream.seed_anchor.clone()]);

        let frame = encode_frame(&anchor_crossing_batch(block_one.clone())).unwrap();
        assert_eq!(
            cursor.evaluate_frame(&frame, &limits),
            Err(WireError::RollbackBeyondCursorHistory)
        );

        let mut checkpoint = cursor.checkpoint();
        checkpoint.canonical_history.insert(0, block_one);
        assert_eq!(
            TransitionCursor::from_checkpoint(checkpoint),
            Err(WireError::InvalidCheckpointHistory)
        );

        let mut forged_anchor = stream.seed_anchor.clone();
        forged_anchor.identity.hash = hash(50);
        let forged_checkpoint = ReceiverCheckpoint {
            stream: stream.clone(),
            sequence: SEED_SEQUENCE + 1,
            tip: forged_anchor.clone(),
            canonical_history: vec![forged_anchor.clone()],
            history_limit: 2,
            last_ack: Some(TransitionAck {
                seed_generation_id: stream.seed_generation_id,
                sequence: SEED_SEQUENCE + 1,
                frame_digest: hash(51),
                new_tip: forged_anchor.identity,
            }),
        };
        assert_eq!(
            TransitionCursor::from_checkpoint(forged_checkpoint),
            Err(WireError::InvalidCheckpointHistory)
        );
    }

    #[test]
    fn cursor_rejects_corrupted_identity_inside_multi_block_removal() {
        let limits = DecodeLimits::default();
        let stream = stream();
        let seed_anchor = stream.seed_anchor.clone();
        let block_three = block(3, 13, seed_anchor.identity.hash);
        let block_four = block(4, 14, block_three.identity.hash);
        let cursor = TransitionCursor::with_history_limit(stream.clone(), 4).unwrap();
        let forward = TransitionBatch {
            schema_version: SCHEMA_VERSION,
            stream: stream.clone(),
            sequence: SEED_SEQUENCE + 1,
            old_tip: seed_anchor.clone(),
            common_ancestor: seed_anchor.clone(),
            new_tip: block_four.clone(),
            removed: Vec::new(),
            added: vec![
                AddedBlock {
                    block: block_three.clone(),
                    block_rlp: block_rlp(13),
                    changes: Vec::new(),
                },
                AddedBlock {
                    block: block_four.clone(),
                    block_rlp: block_rlp(14),
                    changes: Vec::new(),
                },
            ],
            recent_block_hashes: RecentBlockHashes {
                start_number: 0,
                hashes: vec![
                    hash(9),
                    hash(11),
                    seed_anchor.identity.hash,
                    block_three.identity.hash,
                ],
            },
        };
        let ReceiverDecision::Apply { next_cursor, .. } =
            cursor.evaluate_frame(&encode_frame(&forward).unwrap(), &limits).unwrap()
        else {
            panic!("post-anchor blocks must apply");
        };
        let mut rewind = TransitionBatch {
            schema_version: SCHEMA_VERSION,
            stream,
            sequence: SEED_SEQUENCE + 2,
            old_tip: block_four.clone(),
            common_ancestor: seed_anchor.clone(),
            new_tip: seed_anchor,
            removed: vec![block_four.identity, block_three.identity],
            added: Vec::new(),
            recent_block_hashes: RecentBlockHashes {
                start_number: 0,
                hashes: vec![hash(9), hash(11)],
            },
        };
        rewind.removed[1].state_root = hash(777_777);
        rewind.validate(&limits).unwrap();
        let frame = encode_frame(&rewind).unwrap();
        assert_eq!(
            next_cursor.evaluate_frame(&frame, &limits),
            Err(WireError::CursorRemovedHistoryMismatch)
        );
    }
}
