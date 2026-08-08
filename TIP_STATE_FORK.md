# Ethereum Tip-State Reth Fork

This repository is the Ethereum canonical producer fork for the tip-state runtime. Reth produces
the canonical seed and ordered live stream; it is not part of the runtime serving path.

## Upstream provenance

- Official upstream: `https://github.com/paradigmxyz/reth.git`
- Upstream release and workspace version: `v2.3.0`
- Fork-point commit: `9384bc53d8c0c77e59cac83fdaaf3b372c6d2216`
- Fork-point tree: `fd24663d6d1f39e082091121ec20cdac3adc83e3`
- Annotated base tag: `tipstate-upstream-reth-v2.3.0`
- Paired runtime repository: sibling `../runtime`

The exact fork point must be recorded explicitly. Never infer it only from a crate version or a
moving upstream branch.

## Tip-state patch lineage

1. `237f3a5680725ca883ebc911115a82fe595f2a87` adds the flat producer, wire crate,
   awaited ExEx integration, durable transport/outbox, and fail-closed notification handling.
2. `5988f9f709daa9415c08afbec333d818ffaae37f` retains the immutable seed `BLOCKHASH`
   window required for bounded reorg reconstruction.
3. `710307bc13c1fb6f3c9cace5af3ec7d55265bf5d` centralizes producer documentation and
   comments without changing functional behavior.

The behavioral patch range is
`9384bc53d8c0c77e59cac83fdaaf3b372c6d2216..5988f9f709daa9415c08afbec333d818ffaae37f`.
Its functional tree is `372864c03601f1dce408cf1b7544d06020ed3776`.

## Custom source boundary

- `examples/tip-state-exex/`
- `crates/tip-state-wire/`
- Their required workspace and lockfile entries
- Narrow fail-closed handling in `crates/node/builder/src/launch/exex.rs`

Current producer identities are bootstrap schema 1 and `TIPWIRE1`. Keep upstream source outside
this boundary unchanged unless an explicit producer requirement makes a narrow change necessary.

## Upgrade rule

For every producer-client upgrade:

1. record the official upstream repository, release, exact base commit, and base tree;
2. create and push an annotated `tipstate-upstream-<client>-<version>` tag on that base;
3. reapply the smallest custom patch only in the declared source boundary;
4. update the paired runtime's producer commit/tree binding;
5. run locked producer and runtime gates, full empty-state reseed, exact-tip oracle comparison, and
   restart qualification before deployment.

Do not rebase away or move an already qualified base tag.
