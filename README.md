# cthr — Threads

Encrypted conversations and accepted history on member devices.

## Scope

### Purpose

cthr carries encrypted conversations and their accepted history for direct chats, immutable group forks, and living rooms.

### Owns

- Direct, group-fork, and room conversations; unknown conversation types are ignored safely.
- Execution of verified membership decisions from Groups and Attend, with lineage shown as one conversation.
- Send and receive pace limits, with receivers dropping excess.
- Newcomer history within policy, with history kept on member devices.
- Extensible content types, with text now and voice later.

### Never

- Does not decide who may wave, join, or reopen.
- Does not store history on servers.
- Does not treat a transport acknowledgement as an answer.
- Does not derive member identity from a key root.
- Does not keep the legacy issuer-only identity binding.

### States

Absent → Preparing → Active (epoch); each send or receive moves through Candidate to Committed; offline suspends the live session with history kept; close or block closes it; corrupt or stale membership input is refused.

### Test obligations

- Real OpenMLS round trips for direct, fork, and room conversations on native and Wasm builds with identical vectors.
- Rejection of foreign or revoked authority, stale epochs, and tampered ciphertext; duplicate or crash replay cannot advance state twice.
- Enforcement of pace limits, history window, and message cap; newcomers never receive excluded history.
- Atomic publication of consent, fork, and ordered-join decisions through Groups and Threads, with community isolation kept across keys, sessions, and stores.
- Full line and branch coverage with real round trips, injected delay, duplication, loss, cancellation, clock regression, corruption, and storage conflicts; bounded resource use with no identifiers, plaintext, or secrets in errors.

## Dependencies and reuse

Use [OpenMLS](https://github.com/openmls/openmls) and its RustCrypto provider;
Keys lends a purpose-scoped signer without exporting secrets. The old cmsg
WorkingProvider snapshot and staged Welcome mechanisms inform the extraction;
legacy issuer-only identity and root-derived member IDs are excluded.

Implementation is in progress. Device authority, release proof, ordered room
admission and composite persistence remain explicit integration obligations.
CI configuration does not establish implementation or acceptance.
