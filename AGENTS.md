# Tip-State Producer Constraints

- Canonical fork repository: `https://github.com/maurodelazeri/tip-state-ethereum-reth`;
  official Reth is the separate `upstream` remote.
- This checkout is the repaired Reth 2.3 producer for the flat, current-tip runtime.
- Read `TIP_STATE_FORK.md` before changing the fork. Preserve its upstream base tag and provenance.
- The intended product branch is `main`; preserve the existing upstream Reth source unless a
  producer change explicitly requires it.
- Custom producer code lives under `examples/tip-state-exex/` and `crates/tip-state-wire/`, plus
  their required workspace/lockfile entries and the narrow fail-closed canonical-notification
  handling in `crates/node/builder/src/launch/exex.rs`. `Dockerfile.tip-state` is the only producer
  image recipe; the generic upstream Dockerfile does not build the custom executable.
- Active identities are bootstrap schema 2 and `TIPWIRE2`. Bootstrap2 and every TIPWIRE2 added
  block carry bounded canonical full-block RLP. The downstream proxy translates bootstrap into
  unchanged `TIPSEED2` and the unchanged mandatory `TIPCTRL1` control protocol.
- Before scanning, the awaited ExEx initializer must verify in one read-only snapshot that
  `Finish`, `Execution`, `AccountHashing`, `StorageHashing`, and `MerkleExecute` all exist and are
  exactly equal to the launch head. It must then gate canonical progression until that pinned
  storage-v2 scan is validated and acknowledged by every mandatory sink.
- A mandatory outbox write, publish, sink, checksum, sequence, ancestry, or rollback failure is
  fatal. Never degrade to best-effort delivery.
- The retained seed `BLOCKHASH` window is required for bounded post-seed reorg reconstruction.
  Crossing the seed anchor or retained history floor remains a full-reseed condition.
- Do not add an RPC, provider, MDBX, trie, history, or cache-miss fallback to the replica serving
  path. Reth is a producer and external correctness oracle only.
- The paired runtime's 14th method is current-tip-only `eth_getBlockByNumber`. Every syntactically
  valid selector is normalized by the runtime to its one request-pinned generation; complete block
  responses must come only from the transported canonical RLP, with no historical lookup or
  request-path producer access.
- Never run an unplanned writer or long-lived reader against `/mnt/blockchain/snapshot/reth`.
- Keep custom changes narrow. Do not expand the wire, artifact, or method surface without an
  explicit request and exact qualification.
- Use locked scoped release tests and strict Clippy for the custom producer before completion. Do
  not reformat unrelated upstream files.
- Never place endpoints, credentials, tokens, or live environment dumps in source or Git history.
