//! Provider-free conversion from normalized Reth state to stable wire additions.

use crate::{NormalizedBlock, NormalizedChain};
use alloy_consensus::Header;
use alloy_primitives::{keccak256, B256, U256};
use reth_evm::{ConfigureEvm, EvmEnv};
use reth_evm_ethereum::EthEvmConfig;
use revm::primitives::hardfork::SpecId;
use std::collections::BTreeSet;
use thiserror::Error;
use tip_state_wire::{
    AddedBlock, BlockDescriptor, BlockExecutionContext, BlockIdentity, CanonicalBlockRlp,
    ExecutionFork, StateChange,
};

/// Converts one normalized, contiguous chain segment into canonically ordered wire additions.
///
/// The returned additions deliberately contain no stream sequence or recent-block-hash window.
/// Those values belong to the canonical-notification coordinator, which has the old tip and
/// retained ancestry needed to construct a complete atomic transition.
pub fn map_added_blocks(chain: &NormalizedChain) -> Result<Vec<AddedBlock>, WireMappingError> {
    let Some((first, remaining)) = chain.blocks.split_first() else {
        return Err(WireMappingError::EmptyChain);
    };

    let code_prelude = map_code_prelude(chain)?;
    let mut added = Vec::with_capacity(chain.blocks.len());
    added.push(map_block(first, code_prelude)?);
    for block in remaining {
        added.push(map_block(block, Vec::new())?);
    }
    Ok(added)
}

/// Builds the exact wire descriptor for a persisted sealed header during the awaited seed gate.
///
/// The caller supplies the provider's cached canonical hash separately so this repeats the same
/// slow-seal consistency check used for live notification blocks. Fork selection and every EVM
/// environment field are derived by Reth's mainnet configuration rather than inferred by the
/// external replica.
pub fn map_seed_header(
    header: &Header,
    sealed_hash: B256,
    evm_config: &EthEvmConfig,
) -> Result<BlockDescriptor, WireMappingError> {
    let identity = crate::BlockIdentity {
        number: header.number,
        hash: sealed_hash,
        parent_hash: header.parent_hash,
        state_root: header.state_root,
    };
    let evm_env = evm_config.evm_env(header).expect("EthEvmConfig::evm_env is infallible");
    map_block_descriptor_parts(&identity, header, &evm_env)
}

/// Maps one revm specification identifier to the wire schema's stable fork identifier.
///
/// This is intentionally exhaustive instead of relying on revm's numeric discriminants.
pub const fn map_execution_fork(spec: SpecId) -> ExecutionFork {
    match spec {
        SpecId::FRONTIER => ExecutionFork::Frontier,
        SpecId::HOMESTEAD => ExecutionFork::Homestead,
        SpecId::TANGERINE => ExecutionFork::Tangerine,
        SpecId::SPURIOUS_DRAGON => ExecutionFork::SpuriousDragon,
        SpecId::BYZANTIUM => ExecutionFork::Byzantium,
        SpecId::PETERSBURG => ExecutionFork::Petersburg,
        SpecId::ISTANBUL => ExecutionFork::Istanbul,
        SpecId::BERLIN => ExecutionFork::Berlin,
        SpecId::LONDON => ExecutionFork::London,
        SpecId::MERGE => ExecutionFork::Paris,
        SpecId::SHANGHAI => ExecutionFork::Shanghai,
        SpecId::CANCUN => ExecutionFork::Cancun,
        SpecId::PRAGUE => ExecutionFork::Prague,
        SpecId::OSAKA => ExecutionFork::Osaka,
        SpecId::AMSTERDAM => ExecutionFork::Amsterdam,
    }
}

/// A fail-closed disagreement between normalized Reth data and the stable wire model.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[allow(missing_docs)] // Every variant has a precise diagnostic.
pub enum WireMappingError {
    #[error("normalized chain is empty")]
    EmptyChain,
    #[error("block {block} identity field {field} disagrees with its retained header")]
    IdentityHeaderMismatch { block: u64, field: &'static str },
    #[error("block {block} Reth EVM field {field} disagrees with its retained header")]
    EvmHeaderMismatch { block: u64, field: &'static str },
    #[error("block {block} has incomplete or contradictory blob context")]
    BlobContextMismatch { block: u64 },
    #[error("block {block} has zero gas limit")]
    ZeroGasLimit { block: u64 },
    #[error("code {code_hash:?} is empty")]
    EmptyCode { code_hash: B256 },
    #[error("code table key {expected:?} does not match Keccak-256 {actual:?}")]
    CodeHashMismatch { expected: B256, actual: B256 },
    #[error("duplicate code hash {code_hash:?}")]
    DuplicateCode { code_hash: B256 },
    #[error("block {block} changes account {account:?} more than once")]
    DuplicateAccountChange { block: u64, account: B256 },
    #[error("block {block} changes storage namespace {account:?} more than once")]
    DuplicateStorageNamespace { block: u64, account: B256 },
    #[error("block {block}, account {account:?} changes slot {slot:?} more than once")]
    DuplicateStorageSlot { block: u64, account: B256, slot: B256 },
    #[error(
        "block {block} deletes account {account:?} but its storage delta is not one redundant empty wipe"
    )]
    DeletedAccountStorageConflict { block: u64, account: B256 },
}

fn map_block(
    block: &NormalizedBlock,
    mut changes: Vec<StateChange>,
) -> Result<AddedBlock, WireMappingError> {
    changes.extend(map_state_changes(block)?);
    Ok(AddedBlock {
        block: map_block_descriptor(block)?,
        block_rlp: CanonicalBlockRlp::new(block.block_rlp.clone()),
        changes,
    })
}

fn map_code_prelude(chain: &NormalizedChain) -> Result<Vec<StateChange>, WireMappingError> {
    let mut codes = chain.codes.iter().collect::<Vec<_>>();
    codes.sort_unstable_by_key(|code| code.code_hash);

    let mut previous = None;
    let mut changes = Vec::with_capacity(codes.len());
    for code in codes {
        if previous == Some(code.code_hash) {
            return Err(WireMappingError::DuplicateCode { code_hash: code.code_hash });
        }
        previous = Some(code.code_hash);
        if code.bytecode.is_empty() {
            return Err(WireMappingError::EmptyCode { code_hash: code.code_hash });
        }
        let actual = keccak256(&code.bytecode);
        if actual != code.code_hash {
            return Err(WireMappingError::CodeHashMismatch { expected: code.code_hash, actual });
        }
        changes.push(StateChange::CodeInsert {
            code_hash: code.code_hash.0,
            bytecode: code.bytecode.to_vec(),
        });
    }
    Ok(changes)
}

fn map_state_changes(block: &NormalizedBlock) -> Result<Vec<StateChange>, WireMappingError> {
    let number = block.identity.number;
    let mut accounts = Vec::with_capacity(block.account_sets.len() + block.account_deletes.len());
    let mut deleted = BTreeSet::new();

    for update in &block.account_sets {
        accounts.push((
            update.hashed_address,
            StateChange::AccountSet {
                account: update.hashed_address.0,
                balance: update.account.balance.to_be_bytes::<32>(),
                nonce: update.account.nonce,
                code_hash: update.account.get_bytecode_hash().0,
            },
        ));
    }
    for update in &block.account_deletes {
        deleted.insert(update.hashed_address);
        accounts.push((
            update.hashed_address,
            StateChange::AccountDelete { account: update.hashed_address.0 },
        ));
    }
    accounts.sort_unstable_by_key(|(account, _)| *account);
    reject_duplicate_accounts(number, &accounts)?;

    let mut storage = block.storage_updates.iter().collect::<Vec<_>>();
    storage.sort_unstable_by_key(|update| update.hashed_address);
    for pair in storage.windows(2) {
        if pair[0].hashed_address == pair[1].hashed_address {
            return Err(WireMappingError::DuplicateStorageNamespace {
                block: number,
                account: pair[0].hashed_address,
            });
        }
    }

    let mut wipes = Vec::new();
    let mut slots = Vec::new();
    for update in storage {
        if deleted.contains(&update.hashed_address) {
            if !update.wiped || !update.slots.is_empty() {
                return Err(WireMappingError::DeletedAccountStorageConflict {
                    block: number,
                    account: update.hashed_address,
                });
            }
            // AccountDelete is itself the authoritative full namespace wipe.
            continue;
        }

        if update.wiped {
            wipes.push(StateChange::StorageWipe { account: update.hashed_address.0 });
        }

        let mut updates = update.slots.iter().collect::<Vec<_>>();
        updates.sort_unstable_by_key(|slot| slot.hashed_slot);
        for pair in updates.windows(2) {
            if pair[0].hashed_slot == pair[1].hashed_slot {
                return Err(WireMappingError::DuplicateStorageSlot {
                    block: number,
                    account: update.hashed_address,
                    slot: pair[0].hashed_slot,
                });
            }
        }
        slots.extend(updates.into_iter().map(|slot| {
            if slot.value.is_zero() {
                StateChange::StorageClear {
                    account: update.hashed_address.0,
                    slot: slot.hashed_slot.0,
                }
            } else {
                StateChange::StorageSet {
                    account: update.hashed_address.0,
                    slot: slot.hashed_slot.0,
                    value: slot.value.to_be_bytes::<32>(),
                }
            }
        }));
    }

    let mut changes = Vec::with_capacity(accounts.len() + wipes.len() + slots.len());
    changes.extend(accounts.into_iter().map(|(_, change)| change));
    changes.extend(wipes);
    changes.extend(slots);
    Ok(changes)
}

fn reject_duplicate_accounts(
    block: u64,
    accounts: &[(B256, StateChange)],
) -> Result<(), WireMappingError> {
    for pair in accounts.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(WireMappingError::DuplicateAccountChange { block, account: pair[0].0 });
        }
    }
    Ok(())
}

fn map_block_descriptor(block: &NormalizedBlock) -> Result<BlockDescriptor, WireMappingError> {
    map_block_descriptor_parts(&block.identity, &block.header, &block.evm_env)
}

fn map_block_descriptor_parts(
    identity: &crate::BlockIdentity,
    header: &Header,
    evm_env: &EvmEnv<SpecId>,
) -> Result<BlockDescriptor, WireMappingError> {
    let number = identity.number;
    let env = &evm_env.block_env;
    let spec = evm_env.cfg_env.spec;

    require_identity(number, "number", identity.number == header.number)?;
    require_identity(number, "hash", identity.hash == header.hash_slow())?;
    require_identity(number, "parent_hash", identity.parent_hash == header.parent_hash)?;
    require_identity(number, "state_root", identity.state_root == header.state_root)?;

    require_env(number, "number", env.number == U256::from(header.number))?;
    require_env(number, "timestamp", env.timestamp == U256::from(header.timestamp))?;
    require_env(number, "fee_recipient", env.beneficiary == header.beneficiary)?;
    require_env(number, "gas_limit", env.gas_limit == header.gas_limit)?;
    if env.gas_limit == 0 {
        return Err(WireMappingError::ZeroGasLimit { block: number });
    }
    require_env(
        number,
        "base_fee_per_gas",
        env.basefee == header.base_fee_per_gas.unwrap_or_default(),
    )?;

    let post_merge = spec >= SpecId::MERGE;
    let expected_difficulty = if post_merge { U256::ZERO } else { header.difficulty };
    require_env(number, "difficulty", env.difficulty == expected_difficulty)?;
    let expected_randao = post_merge.then_some(header.mix_hash);
    require_env(number, "prev_randao", env.prevrandao == expected_randao)?;

    match header.slot_number {
        Some(slot) => require_env(number, "slot_number", env.slot_num == slot)?,
        None => require_env(number, "slot_number", env.slot_num == 0)?,
    }

    let blob = match (header.blob_gas_used, header.excess_blob_gas, env.blob_excess_gas_and_price) {
        (None, None, None) => None,
        (Some(used), Some(excess), Some(derived)) if derived.excess_blob_gas == excess => {
            Some((used, excess, derived.blob_gasprice))
        }
        _ => return Err(WireMappingError::BlobContextMismatch { block: number }),
    };

    Ok(BlockDescriptor {
        identity: BlockIdentity {
            number,
            hash: identity.hash.0,
            parent_hash: identity.parent_hash.0,
            state_root: identity.state_root.0,
        },
        execution: BlockExecutionContext {
            active_fork: map_execution_fork(spec),
            timestamp: header.timestamp,
            slot_number: header.slot_number,
            fee_recipient: env.beneficiary.into_array(),
            gas_limit: env.gas_limit,
            gas_used: header.gas_used,
            base_fee_per_gas: U256::from(env.basefee).to_be_bytes::<32>(),
            prev_randao: env.prevrandao.unwrap_or_default().0,
            difficulty: env.difficulty.to_be_bytes::<32>(),
            blob_gas_used: blob.map(|(used, _, _)| used),
            excess_blob_gas: blob.map(|(_, excess, _)| excess),
            blob_base_fee: blob.map(|(_, _, price)| U256::from(price).to_be_bytes::<32>()),
            parent_beacon_block_root: header.parent_beacon_block_root.map(|hash| hash.0),
            withdrawals_root: header.withdrawals_root.map(|hash| hash.0),
            requests_hash: header.requests_hash.map(|hash| hash.0),
        },
    })
}

const fn require_identity(
    block: u64,
    field: &'static str,
    matches: bool,
) -> Result<(), WireMappingError> {
    if matches {
        Ok(())
    } else {
        Err(WireMappingError::IdentityHeaderMismatch { block, field })
    }
}

const fn require_env(
    block: u64,
    field: &'static str,
    matches: bool,
) -> Result<(), WireMappingError> {
    if matches {
        Ok(())
    } else {
        Err(WireMappingError::EvmHeaderMismatch { block, field })
    }
}
