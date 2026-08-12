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
- Annotated base tag: `tipstate-upstream-reth-v2.3.0`; tag object
  `56b185ad67941a1a84fa50c8fec5593122a38487`
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
4. `16e1c749b7e4dc4bc23279fc5114a105e2b0cdab` and
   `f08c392d6085dfe916f2c5a4f173a67e7e88f6a7` record exact fork provenance and the
   chain-qualified repository names.
5. `1e60bb69e7267f04bfffa1b385f6d95bbb67e386` through
   `3c0c2cf6c0fc10e774c3557bce645d370a4a688f` add, harden, and document the
   fork-owned immutable producer-image path.
6. `fa9439ad87d287dcf7acad05bc4be452be207476` adds canonical full-block transport,
   bootstrap schema 2, `TIPWIRE2`, exact forward-frame sizing, and the five-frontier
   state-snapshot guard required by current-tip `eth_getBlockByNumber`.

The pre-bootstrap2 behavioral patch range was
`9384bc53d8c0c77e59cac83fdaaf3b372c6d2216..5988f9f709daa9415c08afbec333d818ffaae37f`.
Its functional tree was `372864c03601f1dce408cf1b7544d06020ed3776`. The qualified Bootstrap2/TIPWIRE2
code range is
`9384bc53d8c0c77e59cac83fdaaf3b372c6d2216..fa9439ad87d287dcf7acad05bc4be452be207476`;
the qualified producer tree is `31ea0a8dee4bf34516d04d7afa91279c8b740c5f`. Later documentation-only commits
must be recorded separately and must never be substituted for the image input: Vergen embeds the
build commit in the executable.

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

The complete tracked delta from the official fork point through the current producer is limited
to the following paths. Do not broaden it without an explicit product change:

- `crates/node/builder/src/launch/exex.rs`: awaited/fail-closed ExEx integration only;
- `crates/tip-state-wire/{Cargo.toml,src/bootstrap.rs,src/lib.rs}`: bootstrap and transition
  wire identities, limits, checksums, and exact size accounting;
- `examples/tip-state-exex/{Cargo.toml,src/coordinator.rs,src/lib.rs,src/main.rs,
  src/producer_io.rs,src/seed_source.rs,src/wire.rs}`: producer capture, seed, outbox,
  notification normalization, and mandatory delivery;
- root `Cargo.toml` and `Cargo.lock`: only the workspace/dependency entries required by those
  custom crates;
- `Dockerfile.tip-state` and `Dockerfile.tip-state.dockerignore`: custom image build boundary;
- `AGENTS.md` and this provenance record.

## Bootstrap2 and TIPWIRE2 block contract

The producer transports the complete canonical Ethereum block RLP so replicas can answer
current-tip `eth_getBlockByNumber` without Reth, MDBX, history, or another network service on the
request path:

- `SeedRequest.anchor_block_rlp` is the exact persisted anchor block encoded from the same
  read-only MDBX transaction used for the Finish checkpoint, canonical header, snapshot transaction
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
same commit in the executable. The OCI labels record the same identities. This is a source-pinned
candidate build, not a promise of bit-for-bit image reproduction: the Dockerfile frontend
`docker/dockerfile:1.7-labs` is not digest-pinned and the builder installs live apt packages. Exact
bytes therefore require a pullable repository digest or a checksummed OCI/Docker archive. A newly
built candidate must repeat the complete seed, RPC, readiness, and load validation before routing.

The qualified image is linux/amd64. Always declare that platform rather than inheriting the build
host default:

```bash
test -z "$(git status --porcelain)"
TIP_PRODUCER_COMMIT="$(git rev-parse HEAD)"
TIP_PRODUCER_TREE="$(git rev-parse 'HEAD^{tree}')"
TIP_IMAGE="tip-state-ethereum-reth:${TIP_PRODUCER_COMMIT}"

docker buildx build --load --pull \
  --platform linux/amd64 \
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

Before building an image, qualify the custom source boundary from the clean producer commit. The
full-dependency nightly Clippy run currently reaches unrelated upstream `reth-era` lints, so the
strict fork-owned gate deliberately uses `--no-deps` after the locked all-target test:

```bash
cargo +nightly-2026-08-03 fmt --package tip-state-wire --package example-tip-state-exex -- --check
cargo +1.97.1 test --locked --release --all-targets \
  --package tip-state-wire --package example-tip-state-exex
cargo +nightly-2026-08-03 clippy --locked --release --all-targets --all-features --no-deps \
  --package tip-state-wire --package example-tip-state-exex -- -D warnings
cargo +1.97.1 build --locked --release --package tip-state-wire
cargo +1.97.1 build --locked --release --package example-tip-state-exex \
  --bin example-tip-state-exex
git diff --check
```

### Qualified immutable deployment

The first live-qualified Bootstrap2/TIPWIRE2 artifact ledger is exact:

| Binding | Qualified value |
| --- | --- |
| Producer build commit | `fa9439ad87d287dcf7acad05bc4be452be207476` |
| Producer build tree | `31ea0a8dee4bf34516d04d7afa91279c8b740c5f` |
| Paired runtime code commit | `de223ff777c652de0c76ce3678d1977a07e4a0de` |
| Paired runtime code tree | `70ef75c6f582ad0f0f820d9f572bad78dff36cc5` |
| Local image tag | `tip-state-ethereum-reth:fa9439ad87d287dcf7acad05bc4be452be207476` |
| Local image ID | `sha256:ab080d08d0b9ecd708e729881fc393eb4bd017772e4051b10251c49317d31c24` |
| Local RepoDigest metadata | `tip-state-ethereum-reth@sha256:ab080d08d0b9ecd708e729881fc393eb4bd017772e4051b10251c49317d31c24`; not a pullable registry guarantee |
| Installed entrypoint | `/usr/local/bin/reth-tip-state` |
| Entrypoint SHA-256 | `25dd42da5bb20ec36397fb1bd51737f8f3134a4bb5a95a0aec0a6fb9d03328a3` |
| Entrypoint size | `65,482,016` bytes |
| Embedded version/profile | commit `fa9439ad87d287dcf7acad05bc4be452be207476`; `maxperf` |
| Builder image | `lukemathwalker/cargo-chef:latest-rust-1.93@sha256:a5dba3bcdb078c5e7697bbbc89d0ff8f6685c9720f7248299849249baea94673` |
| Runtime image | `ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea` |

Epoch 13 completed the first live three-replica validation for this immutable artifact. For
total-host recovery, restore the exact image from a registry or checksummed archive, then verify
the image ID, labels, entrypoint bytes, and version before container creation.

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

### Historical writable-layer artifact

Epochs 9 and 10 used executable SHA-256
`d4b8d110d113f26a75df663486289c15d5e1e734c3c1404b96169353c9016b1d`, copied into the writable
layer of a container based on
`sha256:d9afe810e4a630f879911f5ae3e72a15339587dfa986497bd2fd424c7f29fb26`. It embedded untracked Git
identity `c79e896158410b587ecfe4c73a6a24787dcee52a`. That stopped container is historical only; it is
not the current producer, a build input, or a disaster-recovery path. The immutable artifact above
replaced it after a full empty-state seed, Reth comparison, and public validation. Epoch 14 was an
incomplete attempt and must not be resumed. Use a new common epoch for the next cohort.

### Ordinary Reth is a separate recovery tool

The custom image always installs `example-tip-state-exex`. A fresh Ethereum data rebuild must not
use that awaited ExEx while the execution database is still synchronizing from empty. Build the
ordinary non-ExEx node from the exact qualified fork commit instead:

```bash
cargo +1.97.1 build --locked --release --package reth --bin reth
```

Run that ordinary binary with the paired Lighthouse configuration until the execution database is
fully synchronized, then stop both cleanly. Before a custom cohort starts, `Finish`, `Execution`,
`AccountHashing`, `StorageHashing`, and `MerkleExecute` must all exist and equal one canonical
launch head. The custom seed source reads and validates those five checkpoints from one read-only
provider snapshot before connecting to a replica or scanning state; any mismatch is terminal and
must be converged with the ordinary node, never repaired by replaying transitions into replicas.
The paired runtime's disaster-recovery runbook owns the filesystem, JWT, Lighthouse, container,
membership, and validation steps.

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
