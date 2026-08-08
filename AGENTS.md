# Tip-State Producer Constraints

- This checkout is the repaired Reth 2.3 producer for the flat, current-tip runtime.
- The intended product branch is `main`; preserve the existing upstream Reth source unless a
  producer change explicitly requires it.
- Custom producer code lives under `examples/tip-state-exex/` and `crates/tip-state-wire/`, plus
  their required workspace/lockfile entries and the narrow fail-closed canonical-notification
  handling in `crates/node/builder/src/launch/exex.rs`.
- Active identities are bootstrap schema 1 and `TIPWIRE1`. The downstream proxy translates the
  producer bootstrap into `TIPSEED2` and the mandatory control protocol.
- The awaited ExEx initializer must gate canonical progression until one pinned storage-v2 scan is
  validated and acknowledged by every mandatory sink.
- A mandatory outbox write, publish, sink, checksum, sequence, ancestry, or rollback failure is
  fatal. Never degrade to best-effort delivery.
- The retained seed `BLOCKHASH` window is required for bounded post-seed reorg reconstruction.
  Crossing the seed anchor or retained history floor remains a full-reseed condition.
- Do not add an RPC, provider, MDBX, trie, history, or cache-miss fallback to the replica serving
  path. Reth is a producer and external correctness oracle only.
- Never run an unplanned writer or long-lived reader against `/mnt/blockchain/snapshot/reth`.
- Keep custom changes narrow. Do not expand the wire, artifact, or method surface without an
  explicit request and exact qualification.
- Use locked scoped release tests and strict Clippy for the custom producer before completion. Do
  not reformat unrelated upstream files.
- Never place endpoints, credentials, tokens, or live environment dumps in source or Git history.
