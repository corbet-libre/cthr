# cthr — Threads

Encrypted conversations and accepted history on member devices.

## Scope

Execute real OpenMLS direct conversations, immutable membership forks and living
rooms with ordered changes. Groups supplies verified membership, consent,
lineage and signed history/pace policy. Waves supplies first-contact release
permission. Keep candidate MLS/history separate from committed state, and share
one Vault checkpoint with Contacts, Wallet, Groups and pending Delivery outputs.

Never decide membership, wave permission, accounting, identity, network framing
or delivery acknowledgement. Never put history or rosters on operator servers.

**States.** Absent → Preparing → Active(epoch); each send or receive produces a
private Candidate, then Committed. Close/block stops live work while retained
history remains local; malformed or stale membership is refused.

**Ports.** Genuine Groups/Attend membership decisions, purpose-scoped Keys custody,
current Contacts, signed group policy, injected clock and encrypted Store. Public
operations cover direct/fork preparation, send/receive, accepted history and one
combined checkpoint. Ordered room changes and encrypted newcomer history import
remain implementation work.

**Invariants and tests.** No operator-held history or member identity derivation.
Required evidence is real OpenMLS direct/fork/room roundtrips, current/revoked peer
checks, tamper/stale epoch/replay refusal, signed pace/history limits, and atomic
Groups/MLS publication on native and actual Wasm. Unknown conversation types must
be ignored safely; text is the current content type, voice is later.

## Dependencies and reuse

Use [OpenMLS](https://github.com/openmls/openmls) and its RustCrypto provider;
Keys lends a purpose-scoped signer without exporting secrets. The old cmsg
WorkingProvider snapshot and staged Welcome mechanisms inform the extraction;
legacy issuer-only identity and root-derived member IDs are excluded.

Implementation is in progress. Device authority, release proof, ordered room
admission and composite persistence remain explicit integration obligations.
CI configuration does not establish implementation or acceptance.
