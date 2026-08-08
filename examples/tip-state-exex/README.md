# Flat tip-state producer

This package is the fail-closed Reth ExEx producer for one current canonical Ethereum tip. Its
durable state output is flat and contains only hashed accounts, hashed nonzero storage slots,
content-addressed bytecode, the scalar tip identity and descriptor, and bounded rollback
descriptors. Replicas derive their bounded inverse metadata locally from applied flat changes.

Every canonical notification is normalized into complete, block-aligned hashed flat deltas. When
Reth supplies one exact delta per block, the adapter validates and uses it directly. During
pipeline catch-up, the adapter reconstructs the same forward deltas by reverse-walking the aligned
aggregate bundle. Partial, misaligned, unsorted, discontinuous, or contradictory input fails
closed.

The canonical wire order is bytecode, account sets and deletes, then storage wipes and slot
changes. The redundant empty wipe paired with an account deletion is omitted because deletion
clears the namespace; any contradictory storage change beside that deletion fails closed. A wipe
precedes slot changes, and zero storage is an explicit clear on the wire and absence in durable
state. The wire mapper derives execution fields from Reth's EVM environment and cross-checks them
against the retained header.

The producer durably writes each ordered transition before sending it to every mandatory replica
and advances only after exact acknowledgements. Bootstrap pins one canonical frontier and one
read transaction, emits one checksummed seed stream, and keeps serving unavailable until the full
mandatory cohort validates and acknowledges that generation.

Serving is independent of Reth, RPC, and MDBX. A request pins one complete current-tip generation;
selectors do not select historical state. Reorg records are bounded ingestion metadata only, and
restart recovery is wipe, full reseed, contiguous catch-up, validation, and atomic admission.
