//! Flat normalization of Reth canonical-chain state and fail-closed producer integration.
//!
//! This crate validates block-aligned hashed flat deltas, maps them to the wire schema, constructs
//! a pinned seed, durably frames transitions, and coordinates the exact cohort acknowledgement
//! through the mandatory local fanout.

pub mod coordinator;
pub mod producer_io;
pub mod seed_source;
pub mod wire;

use alloy_consensus::Header;
use alloy_primitives::{keccak256, Address, BlockHash, BlockNumber, Bytes, B256, U256};
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::{ConfigureEvm, EvmEnv};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::Chain;
use reth_primitives_traits::Account;
use reth_trie_common::{HashedPostStateSorted, HashedStorageSorted};
use revm::{
    database::states::{reverts::AccountInfoRevert, BundleState},
    primitives::{hardfork::SpecId, KECCAK_EMPTY},
};
use std::collections::HashSet;
use thiserror::Error;

/// Which complete Reth source shape supplied the per-block state deltas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NormalizationSource {
    /// One exact per-block hashed flat delta was present for every block.
    PerBlockHashedFlatDeltas,
    /// Pipeline/backfill supplied no per-block hashed flat deltas, so the aggregate bundle was
    /// reverse-walked.
    AggregateBundleReverts,
}

/// A normalized, contiguous chain segment.
///
/// Consumers must validate/install `codes` before applying the blocks. Within each block the
/// fields are deliberately arranged in executable order: account sets, storage updates, then
/// account deletes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedChain {
    /// Whether per-block hashed flat deltas or the aggregate reverse-walk supplied the deltas.
    pub source: NormalizationSource,
    /// Content-addressed bytecode introduced anywhere in this chain segment.
    pub codes: Vec<CodeUpdate>,
    /// Contiguous blocks in ascending canonical order.
    pub blocks: Vec<NormalizedBlock>,
}

/// Contract bytecode keyed by its validated Keccak-256 hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeUpdate {
    /// Keccak-256 of the original, unanalysed bytes.
    pub code_hash: B256,
    /// Original EVM bytecode, not revm's analysed representation.
    pub bytecode: Bytes,
}

/// Identity fields that bind a generation to a canonical block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockIdentity {
    /// Canonical block number.
    pub number: BlockNumber,
    /// Canonical block hash.
    pub hash: BlockHash,
    /// Hash of the preceding canonical block.
    pub parent_hash: BlockHash,
    /// Ethereum state root committed by this block.
    pub state_root: B256,
}

/// One complete block context and its forward storage-v2 delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedBlock {
    /// Canonical block identity and state commitment.
    pub identity: BlockIdentity,
    /// The complete Ethereum header is retained so no execution-relevant field is discarded.
    pub header: Header,
    /// Mainnet fork selection, chain ID, EVM limits, and block environment derived by Reth.
    pub evm_env: EvmEnv<SpecId>,
    /// Apply before storage updates so newly created accounts have a storage namespace.
    pub account_sets: Vec<AccountSet>,
    /// For every entry, wipe the namespace first when `wiped`, then apply slots in key order.
    pub storage_updates: Vec<StorageUpdate>,
    /// Apply last so an account deletion and its storage wipe remain executable as one block.
    pub account_deletes: Vec<AccountDelete>,
}

/// Set current account metadata at an exact storage-v2 hashed address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountSet {
    /// `keccak256(address)` storage-v2 key.
    pub hashed_address: B256,
    /// Current nonce, balance, and optional code hash.
    pub account: Account,
}

/// Delete an account at an exact storage-v2 hashed address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountDelete {
    /// `keccak256(address)` storage-v2 key to delete.
    pub hashed_address: B256,
}

/// Update one exact storage-v2 hashed storage namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageUpdate {
    /// `keccak256(address)` storage-v2 namespace.
    pub hashed_address: B256,
    /// Whether the complete namespace must be cleared before applying `slots`.
    pub wiped: bool,
    /// Zero values are explicit slot clears, not missing records.
    pub slots: Vec<StorageSlotUpdate>,
}

/// Set or clear one exact storage-v2 hashed slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageSlotUpdate {
    /// `keccak256(B256::from(slot))` storage-v2 key.
    pub hashed_slot: B256,
    /// Current word, where zero explicitly deletes the flat-state record.
    pub value: U256,
}

/// A structural disagreement in a supposedly canonical Reth notification.
#[derive(Debug, Error, PartialEq, Eq)]
#[allow(missing_docs)] // Every variant is documented by its fail-closed diagnostic.
pub enum NormalizeError {
    #[error("canonical chain notification is empty")]
    EmptyChain,
    #[error("execution outcome starts at {actual}, but first block is {expected}")]
    FirstBlockMismatch { expected: BlockNumber, actual: BlockNumber },
    #[error("block count {blocks} does not match execution outcome length {outcome}")]
    OutcomeLengthMismatch { blocks: usize, outcome: usize },
    #[error("block count {blocks} does not match request-vector length {requests}")]
    RequestsLengthMismatch { blocks: usize, requests: usize },
    #[error("block count {blocks} does not match bundle revert length {reverts}")]
    RevertLengthMismatch { blocks: usize, reverts: usize },
    #[error("block number overflow after {previous}")]
    BlockNumberOverflow { previous: BlockNumber },
    #[error("expected block number {expected}, got map key {actual}")]
    NonContiguousBlock { expected: BlockNumber, actual: BlockNumber },
    #[error("block map key {key} does not match header number {header}")]
    HeaderNumberMismatch { key: BlockNumber, header: BlockNumber },
    #[error("block {number} has parent {actual:?}, but previous block hash is {expected:?}")]
    ParentHashMismatch { number: BlockNumber, expected: BlockHash, actual: BlockHash },
    #[error(
        "partial per-block hashed flat deltas: expected either 0 or {expected} entries, got {actual}"
    )]
    PartialPerBlockHashedFlatDeltas { expected: usize, actual: usize },
    #[error("per-block hashed flat delta key {actual} does not match block number {expected}")]
    PerBlockHashedFlatDeltaKeyMismatch { expected: BlockNumber, actual: BlockNumber },
    #[error("account keys are not strictly sorted at block {block}: {previous:?} then {next:?}")]
    AccountsNotStrictlySorted { block: BlockNumber, previous: B256, next: B256 },
    #[error(
        "storage slot keys are not strictly sorted at block {block}, account {account:?}: {previous:?} then {next:?}"
    )]
    StorageSlotsNotStrictlySorted { block: BlockNumber, account: B256, previous: B256, next: B256 },
    #[error("duplicate revert address {address:?} at block {block}")]
    DuplicateRevertAddress { block: BlockNumber, address: Address },
    #[error("revert for address {address:?} at block {block} has no current bundle account")]
    MissingCurrentAccount { block: BlockNumber, address: Address },
    #[error("changed slot {slot:?} for address {address:?} at block {block} has no current value")]
    MissingCurrentStorage { block: BlockNumber, address: Address, slot: U256 },
    #[error("bundle had no latest revert to remove for block {block}")]
    RevertWalkFailed { block: BlockNumber },
    #[error("bundle retained {remaining} revert vectors after normalizing every block")]
    RevertWalkRemainder { remaining: usize },
    #[error("bytecode table key {expected:?} does not match Keccak-256 {actual:?}")]
    CodeHashMismatch { expected: B256, actual: B256 },
}

/// Normalize one non-empty Ethereum `Chain` without consulting a provider or RPC endpoint.
pub fn normalize_chain(
    chain: &Chain<EthPrimitives>,
    evm_config: &EthEvmConfig,
) -> Result<NormalizedChain, NormalizeError> {
    validate_chain_shape(chain)?;

    let codes = normalize_codes(chain.execution_outcome().state())?;
    let (source, deltas) = if chain.trie_data().is_empty() {
        (NormalizationSource::AggregateBundleReverts, reverse_walk_bundle(chain)?)
    } else {
        let expected = chain.blocks().len();
        if chain.trie_data().len() != expected {
            return Err(NormalizeError::PartialPerBlockHashedFlatDeltas {
                expected,
                actual: chain.trie_data().len(),
            });
        }
        validate_per_block_hashed_flat_delta_keys(chain)?;
        (
            NormalizationSource::PerBlockHashedFlatDeltas,
            chain
                .blocks()
                .keys()
                .map(|number| {
                    let hashed = chain
                        .trie_data_at(*number)
                        .expect("complete per-block hashed flat delta key set was validated")
                        .hashed_state();
                    normalize_hashed_delta(*number, &hashed)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
    };

    let blocks = chain
        .blocks()
        .values()
        .zip(deltas)
        .map(|(block, delta)| {
            let header = block.header().clone();
            let evm_env = evm_config.evm_env(&header).expect("EthEvmConfig::evm_env is infallible");
            NormalizedBlock {
                identity: BlockIdentity {
                    number: header.number,
                    hash: block.hash(),
                    parent_hash: header.parent_hash,
                    state_root: header.state_root,
                },
                header,
                evm_env,
                account_sets: delta.account_sets,
                storage_updates: delta.storage_updates,
                account_deletes: delta.account_deletes,
            }
        })
        .collect();

    Ok(NormalizedChain { source, codes, blocks })
}

#[derive(Default)]
struct StateDelta {
    account_sets: Vec<AccountSet>,
    storage_updates: Vec<StorageUpdate>,
    account_deletes: Vec<AccountDelete>,
}

fn validate_chain_shape(chain: &Chain<EthPrimitives>) -> Result<(), NormalizeError> {
    let Some((&first_number, _)) = chain.blocks().first_key_value() else {
        return Err(NormalizeError::EmptyChain);
    };
    let block_count = chain.blocks().len();
    let outcome = chain.execution_outcome();

    if outcome.first_block() != first_number {
        return Err(NormalizeError::FirstBlockMismatch {
            expected: first_number,
            actual: outcome.first_block(),
        });
    }
    if outcome.len() != block_count {
        return Err(NormalizeError::OutcomeLengthMismatch {
            blocks: block_count,
            outcome: outcome.len(),
        });
    }
    if outcome.requests.len() != block_count {
        return Err(NormalizeError::RequestsLengthMismatch {
            blocks: block_count,
            requests: outcome.requests.len(),
        });
    }
    if outcome.state().reverts.len() != block_count {
        return Err(NormalizeError::RevertLengthMismatch {
            blocks: block_count,
            reverts: outcome.state().reverts.len(),
        });
    }

    let mut expected_number = first_number;
    let mut previous_hash = None;
    for (&number, block) in chain.blocks() {
        if number != expected_number {
            return Err(NormalizeError::NonContiguousBlock {
                expected: expected_number,
                actual: number,
            });
        }
        if block.header().number != number {
            return Err(NormalizeError::HeaderNumberMismatch {
                key: number,
                header: block.header().number,
            });
        }
        if let Some(expected_parent) = previous_hash
            && block.header().parent_hash != expected_parent
        {
            return Err(NormalizeError::ParentHashMismatch {
                number,
                expected: expected_parent,
                actual: block.header().parent_hash,
            });
        }
        previous_hash = Some(block.hash());
        expected_number = expected_number
            .checked_add(1)
            .ok_or(NormalizeError::BlockNumberOverflow { previous: number })?;
    }

    Ok(())
}

fn validate_per_block_hashed_flat_delta_keys(
    chain: &Chain<EthPrimitives>,
) -> Result<(), NormalizeError> {
    for (expected, actual) in chain.blocks().keys().zip(chain.trie_data().keys()) {
        if expected != actual {
            return Err(NormalizeError::PerBlockHashedFlatDeltaKeyMismatch {
                expected: *expected,
                actual: *actual,
            });
        }
    }
    Ok(())
}

fn normalize_codes(bundle: &BundleState) -> Result<Vec<CodeUpdate>, NormalizeError> {
    let mut codes = Vec::with_capacity(bundle.contracts.len());
    for (&code_hash, bytecode) in &bundle.contracts {
        if code_hash == KECCAK_EMPTY {
            continue;
        }
        let bytecode = Bytes::copy_from_slice(bytecode.original_byte_slice());
        let actual = keccak256(&bytecode);
        if actual != code_hash {
            return Err(NormalizeError::CodeHashMismatch { expected: code_hash, actual });
        }
        codes.push(CodeUpdate { code_hash, bytecode });
    }
    codes.sort_unstable_by_key(|code| code.code_hash);
    Ok(codes)
}

fn normalize_hashed_delta(
    block: BlockNumber,
    hashed: &HashedPostStateSorted,
) -> Result<StateDelta, NormalizeError> {
    validate_account_order(block, &hashed.accounts)?;

    let mut delta = StateDelta::default();
    for &(hashed_address, account) in &hashed.accounts {
        match account {
            Some(account) => delta.account_sets.push(AccountSet { hashed_address, account }),
            None => delta.account_deletes.push(AccountDelete { hashed_address }),
        }
    }

    delta.storage_updates = hashed
        .storages
        .iter()
        .map(|(&hashed_address, storage)| normalize_storage(block, hashed_address, storage))
        .collect::<Result<Vec<_>, _>>()?;
    delta.storage_updates.sort_unstable_by_key(|storage| storage.hashed_address);
    Ok(delta)
}

fn validate_account_order(
    block: BlockNumber,
    accounts: &[(B256, Option<Account>)],
) -> Result<(), NormalizeError> {
    for pair in accounts.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(NormalizeError::AccountsNotStrictlySorted {
                block,
                previous: pair[0].0,
                next: pair[1].0,
            });
        }
    }
    Ok(())
}

fn normalize_storage(
    block: BlockNumber,
    hashed_address: B256,
    storage: &HashedStorageSorted,
) -> Result<StorageUpdate, NormalizeError> {
    for pair in storage.storage_slots.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(NormalizeError::StorageSlotsNotStrictlySorted {
                block,
                account: hashed_address,
                previous: pair[0].0,
                next: pair[1].0,
            });
        }
    }
    Ok(StorageUpdate {
        hashed_address,
        wiped: storage.wiped,
        slots: storage
            .storage_slots
            .iter()
            .map(|&(hashed_slot, value)| StorageSlotUpdate { hashed_slot, value })
            .collect(),
    })
}

fn reverse_walk_bundle(chain: &Chain<EthPrimitives>) -> Result<Vec<StateDelta>, NormalizeError> {
    let mut bundle = chain.execution_outcome().state().clone();
    let mut deltas = Vec::with_capacity(chain.blocks().len());

    for &block in chain.blocks().keys().rev() {
        let reverts = bundle.reverts.last().expect("revert length was validated").clone();
        deltas.push(delta_from_current_bundle(block, &bundle, &reverts)?);
        if !bundle.revert_latest() {
            return Err(NormalizeError::RevertWalkFailed { block });
        }
    }
    if !bundle.reverts.is_empty() {
        return Err(NormalizeError::RevertWalkRemainder { remaining: bundle.reverts.len() });
    }
    deltas.reverse();
    Ok(deltas)
}

fn delta_from_current_bundle(
    block: BlockNumber,
    bundle: &BundleState,
    reverts: &[(Address, revm::database::AccountRevert)],
) -> Result<StateDelta, NormalizeError> {
    let mut seen = HashSet::with_capacity(reverts.len());
    let mut delta = StateDelta::default();

    for (address, revert) in reverts {
        if !seen.insert(*address) {
            return Err(NormalizeError::DuplicateRevertAddress { block, address: *address });
        }
        let hashed_address = keccak256(address);
        let Some(account) = bundle.account(address) else {
            if !matches!(&revert.account, AccountInfoRevert::RevertTo(_)) {
                return Err(NormalizeError::MissingCurrentAccount { block, address: *address });
            }

            // A later account creation can disappear while reverse-walking, leaving the current
            // post-state vacant. RevertTo supplies the account that existed before this deletion.
            delta.account_deletes.push(AccountDelete { hashed_address });
            delta.storage_updates.push(StorageUpdate {
                hashed_address,
                wiped: true,
                slots: Vec::new(),
            });
            continue;
        };

        if let Some(info) = &account.info {
            delta.account_sets.push(AccountSet { hashed_address, account: info.into() });
        } else {
            delta.account_deletes.push(AccountDelete { hashed_address });
        }

        let mut slots = if revert.wipe_storage {
            account
                .storage
                .iter()
                .map(|(slot, value)| StorageSlotUpdate {
                    hashed_slot: keccak256(B256::from(*slot)),
                    value: value.present_value,
                })
                .collect::<Vec<_>>()
        } else {
            revert
                .storage
                .keys()
                .map(|slot| {
                    let value = account.storage_slot(*slot).ok_or(
                        NormalizeError::MissingCurrentStorage {
                            block,
                            address: *address,
                            slot: *slot,
                        },
                    )?;
                    Ok(StorageSlotUpdate { hashed_slot: keccak256(B256::from(*slot)), value })
                })
                .collect::<Result<Vec<_>, NormalizeError>>()?
        };
        slots.sort_unstable_by_key(|slot| slot.hashed_slot);

        if revert.wipe_storage || !slots.is_empty() {
            delta.storage_updates.push(StorageUpdate {
                hashed_address,
                wiped: revert.wipe_storage,
                slots,
            });
        }
    }

    delta.account_sets.sort_unstable_by_key(|update| update.hashed_address);
    delta.account_deletes.sort_unstable_by_key(|update| update.hashed_address);
    delta.storage_updates.sort_unstable_by_key(|update| update.hashed_address);
    Ok(delta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip7685::Requests;
    use alloy_primitives::map::{AddressMap, B256Map};
    use reth_ethereum_primitives::{Block, Receipt};
    use reth_execution_types::ExecutionOutcome;
    use reth_primitives_traits::RecoveredBlock;
    use reth_trie_common::{
        updates::TrieUpdatesSorted, HashedPostState, KeccakKeyHasher, LazyTrieData,
    };
    use revm::{
        bytecode::Bytecode,
        database::{
            states::{
                bundle_state::BundleRetention, AccountStatus, StorageSlot, TransitionAccount,
                TransitionState,
            },
            BundleAccount,
        },
        state::AccountInfo,
    };
    use std::{collections::BTreeMap, sync::Arc};

    const FIRST_BLOCK: u64 = 20_000_000;

    #[derive(Clone)]
    struct Fixture {
        blocks: Vec<RecoveredBlock<Block>>,
        outcome: ExecutionOutcome<Receipt>,
        per_block_hashed_flat_deltas: Vec<HashedPostStateSorted>,
        existing_delete: Address,
        wipe_recreate: Address,
        repeated: Address,
        zero_clear: Address,
        code_hash: B256,
    }

    fn account(nonce: u64, balance: u64) -> AccountInfo {
        AccountInfo { nonce, balance: U256::from(balance), code: None, ..Default::default() }
    }

    fn contract(nonce: u64, bytes: &[u8]) -> (AccountInfo, B256) {
        let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(bytes));
        let code_hash = keccak256(bytecode.original_byte_slice());
        (AccountInfo { nonce, code_hash, code: Some(bytecode), ..Default::default() }, code_hash)
    }

    fn transition(
        previous_info: Option<AccountInfo>,
        info: Option<AccountInfo>,
        previous_status: AccountStatus,
        status: AccountStatus,
        storage: impl IntoIterator<Item = (U256, U256, U256)>,
        storage_was_destroyed: bool,
    ) -> TransitionAccount {
        TransitionAccount {
            info,
            status,
            previous_info,
            previous_status,
            storage: storage
                .into_iter()
                .map(|(slot, previous, present)| {
                    (slot, StorageSlot::new_changed(previous, present))
                })
                .collect(),
            storage_was_destroyed,
        }
    }

    fn apply_block(
        bundle: &mut BundleState,
        transitions: impl IntoIterator<Item = (Address, TransitionAccount)>,
    ) -> HashedPostStateSorted {
        let transitions = transitions.into_iter().collect::<Vec<_>>();
        let block_accounts = transitions
            .iter()
            .map(|(address, transition)| (*address, transition.present_bundle_account()))
            .collect::<AddressMap<BundleAccount>>();
        let hashed_flat_delta =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(&block_accounts).into_sorted();

        let mut transition_state = TransitionState::default();
        transition_state.add_transitions(transitions);
        bundle.apply_transitions_and_create_reverts(transition_state, BundleRetention::Reverts);
        hashed_flat_delta
    }

    fn recovered_block(number: u64, parent_hash: B256) -> RecoveredBlock<Block> {
        let header = Header {
            number,
            parent_hash,
            state_root: B256::repeat_byte((number as u8).wrapping_add(1)),
            beneficiary: Address::with_last_byte(number as u8),
            timestamp: 1_720_000_000 + number,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000 + number),
            mix_hash: B256::repeat_byte(0x42),
            excess_blob_gas: Some(number),
            blob_gas_used: Some(393_216),
            parent_beacon_block_root: Some(B256::repeat_byte(0x43)),
            withdrawals_root: Some(B256::repeat_byte(0x44)),
            ..Default::default()
        };
        let hash = header.hash_slow();
        RecoveredBlock::new(Block { header, body: Default::default() }, Vec::new(), hash)
    }

    #[allow(clippy::vec_init_then_push)] // Each entry mutates the aggregate used by the next.
    fn fixture() -> Fixture {
        let repeated = Address::repeat_byte(0x11);
        let code_account = Address::repeat_byte(0x22);
        let existing_delete = Address::repeat_byte(0x33);
        let wipe_recreate = Address::repeat_byte(0x44);
        let zero_clear = Address::repeat_byte(0x55);
        let slot_one = U256::from(1);
        let slot_two = U256::from(2);

        let repeated_one = account(1, 100);
        let repeated_two = account(2, 90);
        let deleted_before = account(7, 700);
        let wiped_before = account(4, 400);
        let wiped_after = account(5, 350);
        let zero_clear_info = account(9, 900);
        let (code_info, code_hash) = contract(1, &[0x60, 0x2a, 0x60, 0, 0x52, 0x60, 0x20, 0xf3]);

        let mut bundle = BundleState::default();
        let mut per_block_hashed_flat_deltas = Vec::new();

        // Block 0: create two accounts, install code, and delete an existing account. The
        // deletion deliberately produces account=None plus a wiped storage namespace.
        per_block_hashed_flat_deltas.push(apply_block(
            &mut bundle,
            [
                (
                    repeated,
                    transition(
                        None,
                        Some(repeated_one.clone()),
                        AccountStatus::LoadedNotExisting,
                        AccountStatus::InMemoryChange,
                        [(slot_one, U256::ZERO, U256::from(10))],
                        false,
                    ),
                ),
                (
                    code_account,
                    transition(
                        None,
                        Some(code_info),
                        AccountStatus::LoadedNotExisting,
                        AccountStatus::InMemoryChange,
                        [],
                        false,
                    ),
                ),
                (
                    existing_delete,
                    transition(
                        Some(deleted_before),
                        None,
                        AccountStatus::Loaded,
                        AccountStatus::Destroyed,
                        [],
                        true,
                    ),
                ),
            ],
        ));

        // Block 1: change the same slot again, add another slot, and destroy/recreate an existing
        // contract in one transition. The latter must wipe before installing its new slots.
        per_block_hashed_flat_deltas.push(apply_block(
            &mut bundle,
            [
                (
                    repeated,
                    transition(
                        Some(repeated_one),
                        Some(repeated_two.clone()),
                        AccountStatus::InMemoryChange,
                        AccountStatus::InMemoryChange,
                        [
                            (slot_one, U256::from(10), U256::from(20)),
                            (slot_two, U256::ZERO, U256::from(7)),
                        ],
                        false,
                    ),
                ),
                (
                    wipe_recreate,
                    transition(
                        Some(wiped_before),
                        Some(wiped_after),
                        AccountStatus::Loaded,
                        AccountStatus::DestroyedChanged,
                        [(slot_two, U256::from(99), U256::from(5))],
                        true,
                    ),
                ),
            ],
        ));

        // Block 2 is a real empty transition and therefore still has one aligned revert vector.
        per_block_hashed_flat_deltas.push(apply_block(&mut bundle, []));

        // Block 3 deletes the account created in block 0 after its repeated slot mutations and
        // explicitly clears a slot on another existing account by writing zero.
        per_block_hashed_flat_deltas.push(apply_block(
            &mut bundle,
            [
                (
                    repeated,
                    transition(
                        Some(repeated_two),
                        None,
                        AccountStatus::InMemoryChange,
                        AccountStatus::Destroyed,
                        [],
                        true,
                    ),
                ),
                (
                    zero_clear,
                    transition(
                        Some(zero_clear_info.clone()),
                        Some(zero_clear_info),
                        AccountStatus::Loaded,
                        AccountStatus::Changed,
                        [(U256::from(9), U256::from(42), U256::ZERO)],
                        false,
                    ),
                ),
            ],
        ));

        let mut parent = B256::repeat_byte(0x9f);
        let blocks = (0..4)
            .map(|index| {
                let block = recovered_block(FIRST_BLOCK + index, parent);
                parent = block.hash();
                block
            })
            .collect::<Vec<_>>();
        let outcome = ExecutionOutcome::new(
            bundle,
            vec![Vec::new(); blocks.len()],
            FIRST_BLOCK,
            vec![Requests::default(); blocks.len()],
        );

        Fixture {
            blocks,
            outcome,
            per_block_hashed_flat_deltas,
            existing_delete,
            wipe_recreate,
            repeated,
            zero_clear,
            code_hash,
        }
    }

    fn make_chain(
        fixture: &Fixture,
        with_per_block_hashed_flat_deltas: bool,
    ) -> Chain<EthPrimitives> {
        let per_block_hashed_flat_deltas = if with_per_block_hashed_flat_deltas {
            fixture
                .blocks
                .iter()
                .zip(&fixture.per_block_hashed_flat_deltas)
                .map(|(block, state)| {
                    (
                        block.header().number,
                        LazyTrieData::ready(
                            Arc::new(state.clone()),
                            Arc::new(TrieUpdatesSorted::default()),
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        } else {
            BTreeMap::new()
        };
        Chain::new(fixture.blocks.clone(), fixture.outcome.clone(), per_block_hashed_flat_deltas)
    }

    fn assert_same_payload(per_block: &NormalizedChain, aggregate: &NormalizedChain) {
        assert_eq!(per_block.codes, aggregate.codes);
        assert_eq!(per_block.blocks, aggregate.blocks);
        assert_eq!(per_block.source, NormalizationSource::PerBlockHashedFlatDeltas);
        assert_eq!(aggregate.source, NormalizationSource::AggregateBundleReverts);
    }

    #[test]
    fn aggregate_reverse_walk_matches_per_block_hashed_flat_deltas() {
        let fixture = fixture();
        let evm_config = EthEvmConfig::mainnet();
        let per_block = normalize_chain(&make_chain(&fixture, true), &evm_config).unwrap();
        let aggregate = normalize_chain(&make_chain(&fixture, false), &evm_config).unwrap();
        assert_same_payload(&per_block, &aggregate);

        assert_eq!(per_block.codes.len(), 1);
        assert_eq!(per_block.codes[0].code_hash, fixture.code_hash);
        assert_eq!(per_block.codes[0].code_hash, keccak256(&per_block.codes[0].bytecode));
        assert!(per_block.blocks[2].account_sets.is_empty());
        assert!(per_block.blocks[2].storage_updates.is_empty());
        assert!(per_block.blocks[2].account_deletes.is_empty());

        let repeated_hash = keccak256(fixture.repeated);
        let first_slot = keccak256(B256::from(U256::from(1)));
        assert_eq!(
            per_block.blocks[0]
                .storage_updates
                .iter()
                .find(|update| update.hashed_address == repeated_hash)
                .unwrap()
                .slots[0],
            StorageSlotUpdate { hashed_slot: first_slot, value: U256::from(10) }
        );
        assert_eq!(
            per_block.blocks[1]
                .storage_updates
                .iter()
                .find(|update| update.hashed_address == repeated_hash)
                .unwrap()
                .slots
                .iter()
                .find(|slot| slot.hashed_slot == first_slot)
                .unwrap()
                .value,
            U256::from(20)
        );

        let wiped_hash = keccak256(fixture.wipe_recreate);
        assert!(
            per_block.blocks[1]
                .storage_updates
                .iter()
                .find(|update| update.hashed_address == wiped_hash)
                .unwrap()
                .wiped
        );

        let zero_clear_hash = keccak256(fixture.zero_clear);
        let zero_clear = per_block.blocks[3]
            .storage_updates
            .iter()
            .find(|update| update.hashed_address == zero_clear_hash)
            .unwrap();
        assert!(!zero_clear.wiped);
        assert_eq!(zero_clear.slots.len(), 1);
        assert_eq!(zero_clear.slots[0].value, U256::ZERO);
    }

    #[test]
    fn vacant_current_revert_to_matches_flat_delete() {
        let address = Address::repeat_byte(0x66);
        let slot = U256::from(3);
        let created = account(1, 100);
        let recreated = account(2, 80);
        let mut bundle = BundleState::default();

        apply_block(
            &mut bundle,
            [(
                address,
                transition(
                    None,
                    Some(created.clone()),
                    AccountStatus::LoadedNotExisting,
                    AccountStatus::InMemoryChange,
                    [(slot, U256::ZERO, U256::from(9))],
                    false,
                ),
            )],
        );
        let expected_flat_delete_delta = apply_block(
            &mut bundle,
            [(
                address,
                transition(
                    Some(created.clone()),
                    None,
                    AccountStatus::InMemoryChange,
                    AccountStatus::Destroyed,
                    [],
                    true,
                ),
            )],
        );
        apply_block(
            &mut bundle,
            [(
                address,
                transition(
                    None,
                    Some(recreated),
                    AccountStatus::Destroyed,
                    AccountStatus::DestroyedChanged,
                    [(slot, U256::ZERO, U256::from(11))],
                    false,
                ),
            )],
        );

        assert!(matches!(bundle.reverts.last().unwrap()[0].1.account, AccountInfoRevert::DeleteIt));
        assert!(bundle.revert_latest());
        assert!(bundle.account(&address).is_none());

        let reverts = bundle.reverts.last().unwrap().clone();
        assert_eq!(reverts.len(), 1);
        assert!(matches!(reverts[0].1.account, AccountInfoRevert::RevertTo(_)));
        assert!(reverts[0].1.wipe_storage);

        let delta = delta_from_current_bundle(FIRST_BLOCK + 1, &bundle, &reverts).unwrap();
        let expected =
            normalize_hashed_delta(FIRST_BLOCK + 1, &expected_flat_delete_delta).unwrap();
        assert_eq!(delta.account_sets, expected.account_sets);
        assert_eq!(delta.account_deletes, expected.account_deletes);
        assert_eq!(delta.storage_updates, expected.storage_updates);
        assert_eq!(delta.storage_updates.len(), 1);
        assert!(delta.storage_updates[0].wiped);
        assert!(delta.storage_updates[0].slots.is_empty());

        assert!(bundle.revert_latest());
        let restored = bundle.account(&address).unwrap();
        assert_eq!(restored.info.as_ref(), Some(&created));
        assert_eq!(restored.storage_slot(slot), Some(U256::from(9)));
    }

    #[test]
    fn vacant_current_accepts_only_revert_to() {
        let address = Address::repeat_byte(0x67);
        let bundle = BundleState::default();

        for wipe_storage in [false, true] {
            let reverts = [(
                address,
                revm::database::AccountRevert {
                    account: AccountInfoRevert::RevertTo(account(1, 1)),
                    storage: Default::default(),
                    previous_status: AccountStatus::Changed,
                    wipe_storage,
                },
            )];
            let delta = delta_from_current_bundle(FIRST_BLOCK, &bundle, &reverts).unwrap();
            assert_eq!(
                delta.account_deletes,
                vec![AccountDelete { hashed_address: keccak256(address) }]
            );
            assert_eq!(delta.storage_updates.len(), 1);
            assert!(delta.storage_updates[0].wiped);
            assert!(delta.storage_updates[0].slots.is_empty());
        }

        for account in [AccountInfoRevert::DeleteIt, AccountInfoRevert::DoNothing] {
            for wipe_storage in [false, true] {
                let reverts = [(
                    address,
                    revm::database::AccountRevert {
                        account: account.clone(),
                        storage: Default::default(),
                        previous_status: AccountStatus::LoadedNotExisting,
                        wipe_storage,
                    },
                )];
                assert!(matches!(
                    delta_from_current_bundle(FIRST_BLOCK, &bundle, &reverts),
                    Err(NormalizeError::MissingCurrentAccount { block, address: missing })
                        if block == FIRST_BLOCK && missing == address
                ));
            }
        }
    }

    #[derive(Default)]
    struct StrictOverlay {
        accounts: B256Map<Account>,
        storage: B256Map<B256Map<U256>>,
        codes: B256Map<Bytes>,
    }

    impl StrictOverlay {
        fn apply(&mut self, chain: &NormalizedChain) -> Result<(), &'static str> {
            for code in &chain.codes {
                if keccak256(&code.bytecode) != code.code_hash {
                    return Err("bad code hash");
                }
                self.codes.insert(code.code_hash, code.bytecode.clone());
            }
            for block in &chain.blocks {
                for update in &block.account_sets {
                    self.accounts.insert(update.hashed_address, update.account);
                    self.storage.entry(update.hashed_address).or_default();
                }
                for update in &block.storage_updates {
                    if !self.accounts.contains_key(&update.hashed_address) {
                        return Err("storage update on missing account");
                    }
                    let namespace = self.storage.entry(update.hashed_address).or_default();
                    if update.wiped {
                        namespace.clear();
                    }
                    for slot in &update.slots {
                        if slot.value.is_zero() {
                            namespace.remove(&slot.hashed_slot);
                        } else {
                            namespace.insert(slot.hashed_slot, slot.value);
                        }
                    }
                }
                for update in &block.account_deletes {
                    self.accounts.remove(&update.hashed_address);
                    self.storage.remove(&update.hashed_address);
                }
            }
            Ok(())
        }
    }

    #[test]
    fn deletion_wipe_is_executable_before_account_delete() {
        let fixture = fixture();
        let normalized =
            normalize_chain(&make_chain(&fixture, true), &EthEvmConfig::mainnet()).unwrap();
        let deleted_hash = keccak256(fixture.existing_delete);
        let delete_block = &normalized.blocks[0];
        assert!(delete_block
            .account_deletes
            .contains(&AccountDelete { hashed_address: deleted_hash }));
        assert!(delete_block
            .storage_updates
            .iter()
            .any(|update| update.hashed_address == deleted_hash && update.wiped));

        let mut overlay = StrictOverlay::default();
        overlay.accounts.insert(deleted_hash, Account::default());
        overlay
            .storage
            .insert(deleted_hash, B256Map::from_iter([(B256::repeat_byte(0xfe), U256::from(99))]));
        let wipe_hash = keccak256(fixture.wipe_recreate);
        overlay.accounts.insert(wipe_hash, Account::default());
        overlay
            .storage
            .insert(wipe_hash, B256Map::from_iter([(B256::repeat_byte(0xfd), U256::from(88))]));

        overlay.apply(&normalized).unwrap();
        assert!(!overlay.accounts.contains_key(&deleted_hash));
        assert!(!overlay.storage.contains_key(&deleted_hash));
        assert_eq!(overlay.codes.len(), 1);
    }

    #[test]
    fn rejects_bad_parent_link_and_partial_per_block_hashed_flat_deltas() {
        let fixture = fixture();
        let mut bad_blocks = fixture.blocks.clone();
        bad_blocks[1] = recovered_block(FIRST_BLOCK + 1, B256::repeat_byte(0xee));
        let bad_link = Chain::new(bad_blocks, fixture.outcome.clone(), BTreeMap::new());
        assert!(matches!(
            normalize_chain(&bad_link, &EthEvmConfig::mainnet()),
            Err(NormalizeError::ParentHashMismatch { number, .. }) if number == FIRST_BLOCK + 1
        ));

        let mut partial_deltas = BTreeMap::new();
        partial_deltas.insert(
            FIRST_BLOCK,
            LazyTrieData::ready(
                Arc::new(fixture.per_block_hashed_flat_deltas[0].clone()),
                Arc::new(TrieUpdatesSorted::default()),
            ),
        );
        let partial = Chain::new(fixture.blocks, fixture.outcome, partial_deltas);
        assert_eq!(
            normalize_chain(&partial, &EthEvmConfig::mainnet()).unwrap_err(),
            NormalizeError::PartialPerBlockHashedFlatDeltas { expected: 4, actual: 1 }
        );
    }

    #[test]
    fn rejects_wrong_flat_delta_keys_and_unsorted_per_block_delta() {
        let fixture = fixture();
        let mut wrong_delta_keys = BTreeMap::new();
        for (index, state) in fixture.per_block_hashed_flat_deltas.iter().enumerate() {
            wrong_delta_keys.insert(
                FIRST_BLOCK + 100 + index as u64,
                LazyTrieData::ready(
                    Arc::new(state.clone()),
                    Arc::new(TrieUpdatesSorted::default()),
                ),
            );
        }
        let chain = Chain::new(fixture.blocks.clone(), fixture.outcome.clone(), wrong_delta_keys);
        assert!(matches!(
            normalize_chain(&chain, &EthEvmConfig::mainnet()),
            Err(NormalizeError::PerBlockHashedFlatDeltaKeyMismatch { .. })
        ));

        let mut unsorted = fixture.per_block_hashed_flat_deltas.clone();
        assert!(unsorted[0].accounts.len() > 1);
        unsorted[0].accounts.swap(0, 1);
        let mut per_block_hashed_flat_deltas = BTreeMap::new();
        for (block, state) in fixture.blocks.iter().zip(unsorted) {
            per_block_hashed_flat_deltas.insert(
                block.header().number,
                LazyTrieData::ready(Arc::new(state), Arc::new(TrieUpdatesSorted::default())),
            );
        }
        let chain = Chain::new(fixture.blocks, fixture.outcome, per_block_hashed_flat_deltas);
        assert!(matches!(
            normalize_chain(&chain, &EthEvmConfig::mainnet()),
            Err(NormalizeError::AccountsNotStrictlySorted { block, .. }) if block == FIRST_BLOCK
        ));
    }

    #[test]
    fn rejects_code_whose_table_key_does_not_match_original_bytes() {
        let fixture = fixture();
        let mut outcome = fixture.outcome;
        let bytecode = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00]));
        outcome.state_mut().contracts.insert(B256::repeat_byte(0xff), bytecode);
        let chain = Chain::new(fixture.blocks, outcome, BTreeMap::new());
        assert!(matches!(
            normalize_chain(&chain, &EthEvmConfig::mainnet()),
            Err(NormalizeError::CodeHashMismatch { expected, .. })
                if expected == B256::repeat_byte(0xff)
        ));
    }

    #[test]
    fn rejects_misaligned_lengths() {
        let fixture = fixture();
        let mut outcome = fixture.outcome;
        outcome.requests.pop();
        let chain = Chain::new(fixture.blocks, outcome, BTreeMap::new());
        assert_eq!(
            normalize_chain(&chain, &EthEvmConfig::mainnet()).unwrap_err(),
            NormalizeError::RequestsLengthMismatch { blocks: 4, requests: 3 }
        );
    }

    #[test]
    fn per_block_and_aggregate_deltas_map_to_identical_valid_wire_additions() {
        let fixture = fixture();
        let evm_config = EthEvmConfig::mainnet();
        let per_block = normalize_chain(&make_chain(&fixture, true), &evm_config).unwrap();
        let aggregate = normalize_chain(&make_chain(&fixture, false), &evm_config).unwrap();
        let per_block_added = wire::map_added_blocks(&per_block).unwrap();
        let aggregate_added = wire::map_added_blocks(&aggregate).unwrap();

        assert_eq!(per_block_added, aggregate_added);
        assert!(matches!(
            per_block_added[0].changes.first(),
            Some(tip_state_wire::StateChange::CodeInsert { code_hash, .. })
                if *code_hash == fixture.code_hash.0
        ));
        assert!(per_block_added[1..]
            .iter()
            .all(|block| block.changes.iter().all(|change| {
                !matches!(change, tip_state_wire::StateChange::CodeInsert { .. })
            })));

        let repeated = keccak256(fixture.repeated).0;
        assert!(per_block_added[0].changes.iter().any(|change| matches!(
            change,
            tip_state_wire::StateChange::AccountSet { account, balance, code_hash, .. }
                if *account == repeated &&
                    *balance == U256::from(100).to_be_bytes::<32>() &&
                    *code_hash == KECCAK_EMPTY.0
        )));
        let derived_blob_price =
            per_block.blocks[0].evm_env.block_env.blob_excess_gas_and_price.unwrap().blob_gasprice;
        assert_eq!(
            per_block_added[0].block.execution.blob_base_fee,
            Some(U256::from(derived_blob_price).to_be_bytes::<32>())
        );

        let deleted = keccak256(fixture.existing_delete).0;
        assert!(per_block_added[0].changes.iter().any(|change| matches!(
            change,
            tip_state_wire::StateChange::AccountDelete { account } if *account == deleted
        )));
        assert!(per_block_added[0].changes.iter().all(|change| match change {
            tip_state_wire::StateChange::StorageWipe { account }
            | tip_state_wire::StateChange::StorageSet { account, .. }
            | tip_state_wire::StateChange::StorageClear { account, .. } => *account != deleted,
            _ => true,
        }));

        let zero_clear = keccak256(fixture.zero_clear).0;
        assert!(per_block_added[3].changes.iter().any(|change| matches!(
            change,
            tip_state_wire::StateChange::StorageClear { account, .. }
                if *account == zero_clear
        )));

        let first = &per_block_added[0].block;
        let mut ancestor = first.clone();
        ancestor.identity.number = ancestor.identity.number.checked_sub(1).unwrap();
        ancestor.identity.hash = first.identity.parent_hash;
        ancestor.identity.parent_hash = [0x9e; 32];
        ancestor.identity.state_root = [0x9d; 32];
        ancestor.execution.timestamp = ancestor.execution.timestamp.checked_sub(1).unwrap();
        ancestor.execution.gas_used = 0;

        let new_tip = per_block_added.last().unwrap().block.clone();
        let mut recent_hashes = vec![[0x9c; 32]; 256];
        *recent_hashes.last_mut().unwrap() = new_tip.identity.parent_hash;
        let batch = tip_state_wire::TransitionBatch {
            schema_version: tip_state_wire::SCHEMA_VERSION,
            stream: tip_state_wire::StreamIdentity {
                chain_id: 1,
                genesis_hash: [0x9b; 32],
                seed_generation_id: [0x9a; 32],
                seed_sequence: 0,
                seed_anchor: ancestor.clone(),
            },
            sequence: 1,
            old_tip: ancestor.clone(),
            common_ancestor: ancestor,
            new_tip: new_tip.clone(),
            removed: Vec::new(),
            added: per_block_added,
            recent_block_hashes: tip_state_wire::RecentBlockHashes {
                start_number: new_tip.identity.number - 256,
                hashes: recent_hashes,
            },
        };
        batch.validate(&tip_state_wire::DecodeLimits::default()).unwrap();
    }

    #[test]
    fn wire_mapping_rejects_storage_that_conflicts_with_account_delete() {
        let fixture = fixture();
        let mut normalized =
            normalize_chain(&make_chain(&fixture, true), &EthEvmConfig::mainnet()).unwrap();
        let deleted = keccak256(fixture.existing_delete);
        let storage = normalized.blocks[0]
            .storage_updates
            .iter_mut()
            .find(|update| update.hashed_address == deleted)
            .unwrap();
        assert!(storage.wiped && storage.slots.is_empty());
        storage
            .slots
            .push(StorageSlotUpdate { hashed_slot: B256::repeat_byte(0xee), value: U256::from(1) });

        assert_eq!(
            wire::map_added_blocks(&normalized).unwrap_err(),
            wire::WireMappingError::DeletedAccountStorageConflict {
                block: FIRST_BLOCK,
                account: deleted,
            }
        );
    }

    #[test]
    fn wire_fork_mapping_is_exhaustive_and_stable() {
        let cases = [
            (SpecId::FRONTIER, tip_state_wire::ExecutionFork::Frontier),
            (SpecId::HOMESTEAD, tip_state_wire::ExecutionFork::Homestead),
            (SpecId::TANGERINE, tip_state_wire::ExecutionFork::Tangerine),
            (SpecId::SPURIOUS_DRAGON, tip_state_wire::ExecutionFork::SpuriousDragon),
            (SpecId::BYZANTIUM, tip_state_wire::ExecutionFork::Byzantium),
            (SpecId::PETERSBURG, tip_state_wire::ExecutionFork::Petersburg),
            (SpecId::ISTANBUL, tip_state_wire::ExecutionFork::Istanbul),
            (SpecId::BERLIN, tip_state_wire::ExecutionFork::Berlin),
            (SpecId::LONDON, tip_state_wire::ExecutionFork::London),
            (SpecId::MERGE, tip_state_wire::ExecutionFork::Paris),
            (SpecId::SHANGHAI, tip_state_wire::ExecutionFork::Shanghai),
            (SpecId::CANCUN, tip_state_wire::ExecutionFork::Cancun),
            (SpecId::PRAGUE, tip_state_wire::ExecutionFork::Prague),
            (SpecId::OSAKA, tip_state_wire::ExecutionFork::Osaka),
            (SpecId::AMSTERDAM, tip_state_wire::ExecutionFork::Amsterdam),
        ];
        for (spec, expected) in cases {
            assert_eq!(wire::map_execution_fork(spec), expected);
        }
    }

    #[test]
    fn wire_mapping_cross_checks_amsterdam_slot_number() {
        let fixture = fixture();
        let mut normalized =
            normalize_chain(&make_chain(&fixture, true), &EthEvmConfig::mainnet()).unwrap();
        normalized.blocks[0].evm_env.cfg_env.spec = SpecId::AMSTERDAM;
        normalized.blocks[0].header.slot_number = Some(12_345);
        normalized.blocks[0].identity.hash = normalized.blocks[0].header.hash_slow();
        normalized.blocks[0].evm_env.block_env.slot_num = 12_345;
        let added = wire::map_added_blocks(&normalized).unwrap();
        assert_eq!(added[0].block.execution.slot_number, Some(12_345));

        normalized.blocks[0].evm_env.block_env.slot_num += 1;
        assert_eq!(
            wire::map_added_blocks(&normalized).unwrap_err(),
            wire::WireMappingError::EvmHeaderMismatch { block: FIRST_BLOCK, field: "slot_number" }
        );
    }

    #[test]
    fn wire_mapping_rejects_cached_hash_header_disagreement() {
        let fixture = fixture();
        let mut normalized =
            normalize_chain(&make_chain(&fixture, true), &EthEvmConfig::mainnet()).unwrap();
        normalized.blocks[0].identity.hash = B256::repeat_byte(0xff);

        assert_eq!(
            wire::map_added_blocks(&normalized).unwrap_err(),
            wire::WireMappingError::IdentityHeaderMismatch { block: FIRST_BLOCK, field: "hash" }
        );
    }
}
