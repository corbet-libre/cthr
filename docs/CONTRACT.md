# Threads contract

OpenMLS owns encryption and epochs. Threads owns direct/fork_group/room execution,
accepted history and lineage display. Groups supplies verified decisions and
signed history/pace policy; raw frontend membership lists grant no authority.

Absent → Preparing → Active(epoch). Send/receive produces a Candidate; history,
epochs and outputs become visible only after the combined cwst checkpoint.
Offline suspends live delivery while retaining encrypted history. Block/close
refuses new traffic. Unknown conversation versions/types refuse safely.

Required acceptance: maintained OpenMLS roundtrips, wrong/revoked peers, tamper,
stale epochs, replay, crash/CAS, bounded newcomer history and pace on native and
actual Wasm. Production device authority, accounting release and ordered room
consent must be real owner capabilities. Implementation/evidence are pending.

## Direct engine

The first implementation stage uses upstream OpenMLS 0.9, Ed25519 purpose keys
lent by ckmg, exact authenticated device certificates in BasicCredential, and
ciphertext-only MLS messages. Every operation rechecks current certificates and
the exact direct-conversation authority port. Test authority signs a separate
fixture grant; it is never production G3 attestation or accepted Wave evidence.
The default unavailable adapter refuses.

KeyPackage creation, add/Welcome, send and receive mutate an isolated copy of
OpenMLS storage. A private Candidate has no event or history accessor. Commit
checks scope, previous record and Vault version and saves MLS state, accepted
recipient history, companion state and exact outbox bytes in one transaction.
Only the returned private-constructor Committed exposes events. Failed or
canceled writes require reopen/reconciliation; no ACK may precede success.
Native and browser tests exercise real encrypted round trips after restore,
tamper, revoked-device refusal, replay and competing candidates.

Sent plaintext remains pending until Delivery's verified ACK capability is
accepted in the same owner transaction. Durable Outgoing and Accepted capabilities
have no public constructors; Delivery consumes them instead of raw UI events.
The real Delivery implementation of Acceptance is still an integration seam.
Fork/room preparation is pending Groups' typed policy and asynchronous shared
checkpoint seam; ordered room authority belongs to Attend. No raw roster API,
second signer, replacement room policy or successful unavailable proof exists.
These are incomplete acceptance obligations, not implemented successes.

## Immutable forks

The fork API accepts only Groups' private-constructor PreparedEffect. Its exact
community, group, lineage, parents, roster, policy epoch, Band and original
consent expiry bind preparation. Every actual OpenMLS KeyPackage and member
certificate is checked against that roster and fresh Keys authority. Circle and
Ingroup execute immutable new groups; Opening/Public refuse until ordered room
proofs are available. Unknown membership content never edits the roster.

Fork publication requires the matching Groups Candidate and one actual cwst
transaction; the ordinary direct-candidate commit refuses it. Groups validates
original consent expiry again before persistence. No second Groups transition
machine, private-key export or clock-derived membership authority is present.

Governor owns GCRA pacing. Its arrival scalar is saved with the MLS checkpoint,
using a stable zero origin, trusted monotone owner clock and authenticated Band
quota/burst. Both send and receive enforce it; a dropped receive retains the old
ratchet so an exact retry remains possible. Contacts must be from the SAME Vault
publication version; blocked send recipients or receive senders refuse. Policy
expiry/epoch changes and clock regression refuse. Notifications come from Band.

History selection accepts the actual signed newcomer decision, requires parent
lineage and local membership, delegates the bounded window to Groups, then caps
the count from Band. Circle successors disclose none. Original accepted history
remains in the old encrypted checkpoint. Encrypted newcomer handover and ordered
room external commits remain integration work; local selection is not a claim
that those network/proof paths are implemented.

Publication rechecks the local unlocked Keys handle and every MLS device against
current owner authority. Direct publication repeats the exact operation grant;
group publication repeats current signed policy and reads Contacts from the
actual shared Store version. Prepared state is not an authorization lease.
The Groups companion is canonical Postcard 1, owner cgrp/key snapshot.v1.

Delivery may inspect only the sealed PreparedMessage description (scope, peer,
message digest, MLS epoch, direction and checkpoint version) before publication.
It contains no plaintext or ciphertext and is not a transmission/ACK capability.
Delivery retains the Threads Candidate and puts its journal/ACK bytes in a
companion change of that same cwst commit, then publishes only after success.

Groups' signed departure/policy decisions update active fan-out without rewriting
the immutable MLS roster. A departed local member retains historical plaintext
but cannot send or newly receive. Ordinary message publication also compares
active membership against the canonical Groups record in the same Vault view;
a separately updated Groups checkpoint requires its verified Threads transition.
