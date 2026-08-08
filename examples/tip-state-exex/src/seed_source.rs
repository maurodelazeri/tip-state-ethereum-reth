//! Exact persisted seed metadata captured while the awaited ExEx initializer gates progression.

use alloy_consensus::Header;
use alloy_eips::BlockNumHash;
use alloy_primitives::B256;
use reth_db::tables;
use reth_db_api::transaction::DbTx;
use reth_evm_ethereum::EthEvmConfig;
use reth_provider::{BlockHashReader, DatabaseProviderFactory, HeaderProvider};
use reth_storage_api::DBProvider;
use tip_state_wire::{
    bootstrap::{SeedRequest, BOOTSTRAP_SCHEMA_VERSION},
    DecodeLimits, RecentBlockHashes,
};

use crate::wire::map_seed_header;

/// Captures one complete bootstrap request from a quiescent, persisted Reth head.
///
/// This must run inside the awaited ExEx initializer, before pipeline or engine progression can
/// write a later state. The returned MDBX transaction ID is checked by every replica read
/// transaction during its scan. Dropping the short provider transaction before the scan is safe
/// only because node progression remains gated until the mandatory local fanout confirms that
/// every active cohort member acknowledged the seed.
pub fn capture_seed_request<P>(
    provider: &P,
    evm_config: &EthEvmConfig,
    head: BlockNumHash,
    request_id: B256,
    chain_id: u64,
    genesis_hash: B256,
) -> eyre::Result<SeedRequest>
where
    P: HeaderProvider<Header = Header>
        + BlockHashReader
        + DatabaseProviderFactory<DB = reth_db::DatabaseEnv>,
{
    eyre::ensure!(chain_id == 1, "tip-state seed currently supports mainnet chain ID 1 only");
    eyre::ensure!(request_id != B256::ZERO, "seed request ID must be nonzero");

    let database_provider = provider.database_provider_ro()?;
    let snapshot_transaction_id = database_provider.tx_ref().id()?;
    let finish = database_provider
        .tx_ref()
        .get::<tables::StageCheckpoints>("Finish".to_owned())?
        .ok_or_else(|| eyre::eyre!("missing Finish checkpoint while capturing seed"))?;
    eyre::ensure!(
        finish.block_number == head.number,
        "persisted Finish {} differs from ExEx launch head {}",
        finish.block_number,
        head.number
    );
    let sealed = provider
        .sealed_header(head.number)?
        .ok_or_else(|| eyre::eyre!("persisted header {} is missing", head.number))?;
    eyre::ensure!(
        sealed.hash() == head.hash,
        "persisted header hash {} differs from ExEx launch head {}",
        sealed.hash(),
        head.hash
    );
    let anchor = map_seed_header(sealed.header(), sealed.hash(), evm_config)?;

    let start_number = head.number.saturating_sub(256);
    let hashes = provider.canonical_hashes_range(start_number, head.number)?;
    let expected = usize::try_from(head.number - start_number)?;
    eyre::ensure!(
        hashes.len() == expected,
        "persisted BLOCKHASH window has {} entries, expected {expected}",
        hashes.len()
    );
    if let Some(parent) = hashes.last() {
        eyre::ensure!(
            *parent == sealed.parent_hash,
            "persisted BLOCKHASH window tip differs from anchor parent"
        );
    }
    if start_number == 0 && !hashes.is_empty() {
        eyre::ensure!(
            hashes.first() == Some(&genesis_hash),
            "persisted genesis hash differs from configured mainnet genesis"
        );
    }

    let request = SeedRequest {
        schema_version: BOOTSTRAP_SCHEMA_VERSION,
        request_id: request_id.0,
        chain_id,
        genesis_hash: genesis_hash.0,
        snapshot_transaction_id,
        anchor,
        recent_block_hashes: RecentBlockHashes {
            start_number,
            hashes: hashes.into_iter().map(|hash| hash.0).collect(),
        },
    };
    request.validate(&DecodeLimits::default())?;
    Ok(request)
}
