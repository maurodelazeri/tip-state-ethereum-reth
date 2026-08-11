# Ethereum Tip-State Reth Fork

This repository is the Ethereum canonical producer fork for the tip-state runtime. Reth produces
the canonical seed and ordered live stream; it is not part of the runtime serving path.

## Upstream provenance

- Tip-state fork repository: `https://github.com/maurodelazeri/tip-state-ethereum-reth`
- Paired runtime repository: `https://github.com/maurodelazeri/tip-state-ethereum-runtime`
- Official upstream: `https://github.com/paradigmxyz/reth.git`
- Upstream release and workspace version: `v2.3.0`
- Fork-point commit: `9384bc53d8c0c77e59cac83fdaaf3b372c6d2216`
- Fork-point tree: `fd24663d6d1f39e082091121ec20cdac3adc83e3`
- Annotated base tag: `tipstate-upstream-reth-v2.3.0`
- Local paired runtime: sibling `../runtime`

The exact fork point must be recorded explicitly. Never infer it only from a crate version or a
moving upstream branch.

## Tip-state patch lineage

1. `237f3a5680725ca883ebc911115a82fe595f2a87` adds the flat producer, wire crate,
   awaited ExEx integration, durable transport/outbox, and fail-closed notification handling.
2. `5988f9f709daa9415c08afbec333d818ffaae37f` retains the immutable seed `BLOCKHASH`
   window required for bounded reorg reconstruction.
3. `710307bc13c1fb6f3c9cace5af3ec7d55265bf5d` centralizes producer documentation and
   comments without changing functional behavior.

The pre-bootstrap2 behavioral patch range was
`9384bc53d8c0c77e59cac83fdaaf3b372c6d2216..5988f9f709daa9415c08afbec333d818ffaae37f`.
Its functional tree was `372864c03601f1dce408cf1b7544d06020ed3776`. The current source additionally
implements bootstrap2/TIPWIRE2 canonical full-block transport for method 14; record the resulting
commit and tree with the paired runtime before qualification.

## Custom source boundary

- `examples/tip-state-exex/`
- `crates/tip-state-wire/`
- Their required workspace and lockfile entries
- Narrow fail-closed handling in `crates/node/builder/src/launch/exex.rs`
- `Dockerfile.tip-state` and `Dockerfile.tip-state.dockerignore`, the fork-owned image recipe and
  exact build-context policy that build the custom producer executable rather than the upstream
  `reth` binary

Current producer identities are bootstrap schema 2 and `TIPWIRE2`. Keep upstream source outside
this boundary unchanged unless an explicit producer requirement makes a narrow change necessary.

## Bootstrap2 and TIPWIRE2 block contract

The producer transports the complete canonical Ethereum block RLP so replicas can answer
current-tip `eth_getBlockByNumber` without Reth, MDBX, history, or another network service on the
request path:

- `SeedRequest.anchor_block_rlp` is the exact persisted anchor block encoded from the same
  read-only MDBX transaction used for the Finish checkpoint, sealed header, snapshot transaction
  ID, and `BLOCKHASH` window. Bootstrap JSON encodes it as lowercase, even-length, `0x`-prefixed
  hex.
- Before reading that anchor or scanning state, the producer reads `Finish`, `Execution`,
  `AccountHashing`, `StorageHashing`, and `MerkleExecute` from the same read-only provider snapshot.
  All five must exist and equal the ExEx launch head. Any missing or unequal frontier is fatal and
  reports all five values; this prevents labeling already-advanced storage-v2 flat state with an
  older Finish block.
- Every TIPWIRE2 `AddedBlock.block_rlp` is encoded directly from the canonical notification's
  `RecoveredBlock` and placed after its descriptor as `u32` big-endian length plus raw bytes,
  before the state-change count and changes.
- A block RLP is nonempty and at most 32 MiB. The sum of added-block RLP in one frame is at most
  48 MiB. The complete TIPWIRE2 frame remains at most 64 MiB. The bounded bootstrap message is at
  most 65 MiB.
- Bootstrap schema 2 uses digest domain `tip-state-bootstrap-message-v2`. TIPWIRE2 uses magic
  `TIPWIRE2`, schema 2, and checksum domain `tip-state-transition-wire-v2`. Schema 1 peers are
  rejected; producer, proxy, and replicas must move to schema 2 as one coordinated generation.
- `TIPSEED2` and `TIPCTRL1` are unchanged. They remain downstream proxy/runtime protocols and are
  not aliases for the producer bootstrap or transition frame.

The receiver must strictly decode the Ethereum block, reject trailing bytes, verify canonical
byte-identical re-encoding, and bind the decoded header number, hash, parent hash, state root, and
execution fields to the enclosing descriptor before atomically publishing the generation. The
transported signed transaction envelopes support both transaction-hash arrays and complete
transaction objects. A decode, descriptor, body-root, sender-recovery, limit, or version mismatch
fails the generation closed.

The paired runtime exposes this as method 14, current-tip-only `eth_getBlockByNumber`. Every
syntactically valid selector maps to the same tip pinned at request admission; there is no history,
selector lookup, null-on-old-selector behavior, producer fallback, or partial block response.

## Producer executable and image

The executable is the `example-tip-state-exex` binary from `examples/tip-state-exex`; it is not
the workspace's ordinary `reth` binary. `Dockerfile.tip-state` installs it as
`/usr/local/bin/reth-tip-state` and makes that path the image entrypoint. The generic `Dockerfile`
remains the upstream-oriented Reth recipe and must not be used for a tip-state producer image.

The Dockerfile's base-image defaults are pinned to the verified multi-platform index digests used
for this linux/amd64 candidate:

- `CARGO_CHEF_IMAGE=lukemathwalker/cargo-chef:latest-rust-1.93@sha256:a5dba3bcdb078c5e7697bbbc89d0ff8f6685c9720f7248299849249baea94673`;
- `RUNTIME_IMAGE=ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea`.

For a future rebuild or another architecture, re-resolve and verify the platform-appropriate
manifests instead of silently following either human-readable tag. Retain the exact input
references with the final image ID, executable SHA-256, producer commit, and producer tree.

Build only from a clean intended producer commit. `Dockerfile.tip-state.dockerignore` excludes only
build output; the final builder receives the complete clean checkout and `.git` metadata. The build
rejects a commit/tree argument that does not exactly match that checkout, and Vergen embeds the
same commit in the executable. The OCI labels record the same identities:

```bash
test -z "$(git status --porcelain)"
TIP_PRODUCER_COMMIT="$(git rev-parse HEAD)"
TIP_PRODUCER_TREE="$(git rev-parse 'HEAD^{tree}')"
TIP_IMAGE="tip-state-ethereum-reth:${TIP_PRODUCER_COMMIT}"

docker buildx build --load --pull \
  --file Dockerfile.tip-state \
  --build-arg PRODUCER_COMMIT="$TIP_PRODUCER_COMMIT" \
  --build-arg PRODUCER_TREE="$TIP_PRODUCER_TREE" \
  --tag "$TIP_IMAGE" \
  .
```

Before qualification, inspect and record the image configuration and executable hash. A successful
build is only a candidate; it does not replace a qualified producer identity:

```bash
docker image inspect "$TIP_IMAGE"
docker run --rm --entrypoint /usr/local/bin/reth-tip-state "$TIP_IMAGE" --version
docker run --rm --entrypoint /usr/bin/sha256sum \
  "$TIP_IMAGE" /usr/local/bin/reth-tip-state
```

The paired runtime owns the exact container, host-mount, systemd, and cohort configuration. The
producer's required in-container values are explicit and non-secret:

| Variable | Qualified layout value | Purpose |
| --- | --- | --- |
| `TIP_STATE_REPLICA_SOCKET` | `/data/tip-state.sock` | Mandatory local fan-out connection |
| `TIP_STATE_OUTBOX_DIR` | `/data/tip-state-outbox` | Fsynced per-generation transition outbox |
| `TIP_STATE_SEED_TIMEOUT_SECONDS` | `21600` | Awaited whole-seed connection/write/read deadline, including a cold cloned-volume scan |
| `TIP_STATE_IO_TIMEOUT_SECONDS` | `30` | Post-seed mandatory live-frame I/O deadline |

The host bind `/mnt/blockchain/snapshot/reth:/data:rw` provides both Reth's datadir and the local
transport namespace. The runtime proxy binds the mode-`0600` host socket
`/mnt/blockchain/snapshot/reth/tip-state.sock`; the same socket is visible to this executable as
`/data/tip-state.sock`. There is no second socket volume. The producer outbox similarly resolves
from `/data/tip-state-outbox` to `/mnt/blockchain/snapshot/reth/tip-state-outbox` and must survive
ordinary process restarts until the coordinated recovery procedure archives the prior generation.

Startup is intentionally fail closed: the real blockchain filesystem must be mounted, every
mandatory replica must be listening, and the proxy must bind the socket before systemd starts the
container. A missing socket makes the awaited ExEx initializer fail and shuts down Reth; it is not
a reason to retry without the mandatory fan-out. Never bypass those host guards with a direct
`docker start`, and never let Docker's own restart policy auto-start this volume-bound container.
The proxy and every stateful replica must also use `Restart=no`: any process loss invalidates the
in-memory cohort and requires a fresh membership epoch and complete reseed, never a same-epoch
automatic retry.

### Existing qualified-container warning

The currently qualified executable SHA-256
`d4b8d110d113f26a75df663486289c15d5e1e734c3c1404b96169353c9016b1d` is present in the existing
`reth` container's writable layer, not in its underlying image
`sha256:d9afe810e4a630f879911f5ae3e72a15339587dfa986497bd2fd424c7f29fb26`
(`reth-local:rpc-cache-020c6ab5dfb2`). The executable embeds Git SHA
`c79e896158410b587ecfe4c73a6a24787dcee52a`, which is not present in this canonical repository;
the checked-in generic Dockerfile also builds the ordinary `reth` binary. Treat that existing
container as a preserved recovery artifact: do not remove or recreate it during recovery. A new
image built from `Dockerfile.tip-state` may replace it only after its exact commit, tree, base-image
digests, image ID, executable hash, full empty-state reseed, oracle comparison, and coordinated
restart qualification have all been recorded.

## Upgrade rule

For every producer-client upgrade:

1. record the official upstream repository, release, exact base commit, and base tree;
2. create and push an annotated `tipstate-upstream-<client>-<version>` tag on that base;
3. reapply the smallest custom patch only in the declared source boundary;
4. update the paired runtime's producer commit/tree binding;
5. run locked producer and runtime gates, full empty-state reseed, exact-tip oracle comparison, and
   restart qualification before deployment.

Do not rebase away or move an already qualified base tag.

The fork origin retains only `main` and the explicit `tipstate-upstream-*` provenance tags.
Official upstream branches and release tags remain available through the separate `upstream`
remote and are not duplicated on this origin.
