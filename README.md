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

## Dependencies and reuse

Use [OpenMLS](https://github.com/openmls/openmls) and its RustCrypto provider;
Keys lends a purpose-scoped signer without exporting secrets. The old cmsg
WorkingProvider snapshot and staged Welcome mechanisms inform the extraction;
legacy issuer-only identity and root-derived member IDs are excluded.

Implementation is in progress. Device authority, release proof, ordered room
admission and composite persistence remain explicit integration obligations.
CI configuration does not establish implementation or acceptance.
