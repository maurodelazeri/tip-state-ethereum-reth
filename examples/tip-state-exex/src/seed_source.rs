//! Exact persisted seed metadata captured while the awaited ExEx initializer gates progression.

use alloy_eips::BlockNumHash;
use alloy_primitives::B256;
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::SealedBlock;
use reth_provider::{BlockHashReader, BlockReader, DatabaseProviderFactory};
use reth_stages_types::StageId;
use reth_storage_api::{DBProvider, StageCheckpointReader};
use tip_state_wire::{
    bootstrap::{SeedRequest, BOOTSTRAP_SCHEMA_VERSION},
    CanonicalBlockRlp, DecodeLimits, RecentBlockHashes,
};

use crate::wire::map_seed_header;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SeedFrontiers {
    finish: Option<u64>,
    execution: Option<u64>,
    account_hashing: Option<u64>,
    storage_hashing: Option<u64>,
    merkle_execute: Option<u64>,
}

impl SeedFrontiers {
    fn read(provider: &impl StageCheckpointReader) -> eyre::Result<Self> {
        Ok(Self {
            finish: provider.get_stage_checkpoint(StageId::Finish)?.map(|value| value.block_number),
            execution: provider
                .get_stage_checkpoint(StageId::Execution)?
                .map(|value| value.block_number),
            account_hashing: provider
                .get_stage_checkpoint(StageId::AccountHashing)?
                .map(|value| value.block_number),
            storage_hashing: provider
                .get_stage_checkpoint(StageId::StorageHashing)?
                .map(|value| value.block_number),
            merkle_execute: provider
                .get_stage_checkpoint(StageId::MerkleExecute)?
                .map(|value| value.block_number),
        })
    }

    fn validate(self, launch_head: u64) -> eyre::Result<()> {
        let diagnostic = || {
            format!(
                "head={launch_head} finish={:?} execution={:?} account_hashing={:?} \
                 storage_hashing={:?} merkle_execute={:?}",
                self.finish,
                self.execution,
                self.account_hashing,
                self.storage_hashing,
                self.merkle_execute
            )
        };

        let (
            Some(finish),
            Some(execution),
            Some(account_hashing),
            Some(storage_hashing),
            Some(merkle_execute),
        ) = (
            self.finish,
            self.execution,
            self.account_hashing,
            self.storage_hashing,
            self.merkle_execute,
        )
        else {
            eyre::bail!(
                "cannot capture tip-state seed because a required state checkpoint is missing: {}",
                diagnostic()
            );
        };
        eyre::ensure!(
            finish == launch_head,
            "persisted Finish differs from the ExEx launch head: {}",
            diagnostic()
        );
        eyre::ensure!(
            execution == finish && account_hashing == finish && storage_hashing == finish,
            "state-bearing pipeline checkpoints are not converged at Finish: {}",
            diagnostic()
        );
        eyre::ensure!(
            merkle_execute == finish,
            "MerkleExecute has not root-qualified the Finish state: {}",
            diagnostic()
        );
        Ok(())
    }
}

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
    P: DatabaseProviderFactory<DB = reth_db::DatabaseEnv>,
    P::Provider: BlockReader + StageCheckpointReader,
{
    eyre::ensure!(chain_id == 1, "tip-state seed currently supports mainnet chain ID 1 only");
    eyre::ensure!(request_id != B256::ZERO, "seed request ID must be nonzero");

    let database_provider = provider.database_provider_ro()?;
    SeedFrontiers::read(&database_provider)?.validate(head.number)?;
    let snapshot_transaction_id = database_provider.tx_ref().id()?;
    let anchor_block = database_provider
        .block_by_number(head.number)?
        .ok_or_else(|| eyre::eyre!("persisted block {} is missing", head.number))?;
    let anchor_block_rlp_bytes = alloy_rlp::encode(&anchor_block);
    let mut encoded = anchor_block_rlp_bytes.as_slice();
    let sealed = SealedBlock::<reth_ethereum_primitives::Block>::decode_sealed(&mut encoded)
        .map_err(|error| eyre::eyre!("persisted block {} RLP is invalid: {error}", head.number))?;
    eyre::ensure!(encoded.is_empty(), "persisted block {} RLP has trailing bytes", head.number);
    eyre::ensure!(
        sealed.hash() == head.hash,
        "persisted block hash {} differs from ExEx launch head {}",
        sealed.hash(),
        head.hash
    );
    eyre::ensure!(
        sealed.number == head.number,
        "persisted block number {} differs from ExEx launch head {}",
        sealed.number,
        head.number
    );
    eyre::ensure!(
        alloy_rlp::encode(&sealed) == anchor_block_rlp_bytes,
        "persisted block {} RLP is not canonical",
        head.number
    );
    reth_consensus_common::validation::validate_block_pre_execution(
        &sealed,
        evm_config.chain_spec().as_ref(),
    )
    .map_err(|error| {
        eyre::eyre!("persisted block {} failed pre-execution validation: {error}", head.number)
    })?;
    let anchor = map_seed_header(sealed.header(), sealed.hash(), evm_config)?;
    let anchor_block_rlp = CanonicalBlockRlp::new(anchor_block_rlp_bytes);

    let start_number = head.number.saturating_sub(256);
    let hashes = database_provider.canonical_hashes_range(start_number, head.number)?;
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
        anchor_block_rlp,
        recent_block_hashes: RecentBlockHashes {
            start_number,
            hashes: hashes.into_iter().map(|hash| hash.0).collect(),
        },
    };
    request.validate(&DecodeLimits::default())?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: u64 = 25_731_362;

    fn converged() -> SeedFrontiers {
        SeedFrontiers {
            finish: Some(HEAD),
            execution: Some(HEAD),
            account_hashing: Some(HEAD),
            storage_hashing: Some(HEAD),
            merkle_execute: Some(HEAD),
        }
    }

    #[test]
    fn converged_seed_frontiers_pass() {
        converged().validate(HEAD).unwrap();
    }

    #[test]
    fn every_missing_seed_frontier_fails_with_the_full_diagnostic() {
        for (name, frontiers) in [
            ("finish", SeedFrontiers { finish: None, ..converged() }),
            ("execution", SeedFrontiers { execution: None, ..converged() }),
            ("account_hashing", SeedFrontiers { account_hashing: None, ..converged() }),
            ("storage_hashing", SeedFrontiers { storage_hashing: None, ..converged() }),
            ("merkle_execute", SeedFrontiers { merkle_execute: None, ..converged() }),
        ] {
            let error = frontiers.validate(HEAD).unwrap_err().to_string();
            assert!(error.contains("required state checkpoint is missing"), "{name}: {error}");
            for field in [
                "head=",
                "finish=",
                "execution=",
                "account_hashing=",
                "storage_hashing=",
                "merkle_execute=",
            ] {
                assert!(error.contains(field), "{name}: missing {field} in {error}");
            }
        }
    }

    #[test]
    fn every_state_frontier_ahead_or_behind_finish_fails() {
        for (name, frontiers) in [
            ("execution_ahead", SeedFrontiers { execution: Some(HEAD + 1), ..converged() }),
            ("execution_behind", SeedFrontiers { execution: Some(HEAD - 1), ..converged() }),
            ("account_ahead", SeedFrontiers { account_hashing: Some(HEAD + 1), ..converged() }),
            ("account_behind", SeedFrontiers { account_hashing: Some(HEAD - 1), ..converged() }),
            ("storage_ahead", SeedFrontiers { storage_hashing: Some(HEAD + 1), ..converged() }),
            ("storage_behind", SeedFrontiers { storage_hashing: Some(HEAD - 1), ..converged() }),
            ("merkle_ahead", SeedFrontiers { merkle_execute: Some(HEAD + 1), ..converged() }),
            ("merkle_behind", SeedFrontiers { merkle_execute: Some(HEAD - 1), ..converged() }),
        ] {
            let error = frontiers.validate(HEAD).unwrap_err().to_string();
            assert!(
                error.contains("not converged") || error.contains("root-qualified"),
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn finish_must_equal_the_launch_head() {
        let error = converged().validate(HEAD + 1).unwrap_err().to_string();
        assert!(error.contains("Finish differs from the ExEx launch head"));
        assert!(error.contains(&format!("head={}", HEAD + 1)));
        assert!(error.contains(&format!("finish=Some({HEAD})")));
    }

    #[test]
    fn observed_clone_skew_fails_before_seed_capture() {
        let skewed = SeedFrontiers {
            execution: Some(HEAD + 764),
            account_hashing: Some(HEAD + 764),
            storage_hashing: Some(HEAD + 764),
            ..converged()
        };
        let error = skewed.validate(HEAD).unwrap_err().to_string();
        assert!(error.contains("state-bearing pipeline checkpoints are not converged"));
        assert!(error.contains(&format!("execution=Some({})", HEAD + 764)));
    }
}
