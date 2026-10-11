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
Delivery supplies the authenticated recipient Acceptance implementation and
persists it with this owner checkpoint. Immutable forks consume Groups' typed
policy and asynchronous shared checkpoint below. Ordered room authority belongs
to Attend and remains unavailable. No raw roster API, second signer, replacement
room policy or successful unavailable proof exists.

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

`Candidate::commit_groups` takes `(PolicySource, Groups Authority)` as its
governance argument and repeats the original Groups authorization after all
asynchronous custody checks. Expired/revoked consent, changed contacts or seed
authority, changed signed policy and elapsed opening deadlines refuse before
storage. The transaction also refuses membership effects for any second group:
a single MLS candidate cannot publish another group's unapplied transition.

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

Provider locks are private to one disposable OpenMLS working snapshot, with no
caller-held guard or callback under a guard. Their poison state is an internal
invariant, not a recoverable storage failure; scope and backend failures still
return typed errors. All accepted-history ACK tests derive their signed fixture
receipt from an actual committed recipient capability. That fixture establishes
engine behavior only; production receipt authentication remains Delivery-owned.

Each current thread checkpoint is bounded by Store's existing per-value limit.
Threads rejects an oversized candidate before publication; Store validates every
restored value before handing it to the owner. No independent larger storage
allowance, truncated history, or successful partial checkpoint is implied.

## Device continuation boundary

Current MLS leaf credentials bind one scoped device certificate per member.
Reopening the encrypted checkpoint with the same authorized certificate preserves
its accepted history and live ratchets. Another enrolled device certificate is
refused, even for the same member. Concurrent devices and authenticated MLS
continuation after device loss require the Keys/Groups owner capability; the
current engine does not claim either. Copying a ratchet between devices or
inventing a device lease is not a recovery mechanism.

Hostile-input vectors use actual upstream OpenMLS with the fixture's borrowed
Keys signer to produce empty/oversized application content and membership
proposals. Direct and immutable-fork receivers refuse those messages without
publishing a changed checkpoint. Fixtures do not establish production attestation.

## Authenticated Groups state

New Groups creation binds the original canonical GroupState commitment in MLS
GroupContext private-use extension 0xF701. Payload is big-endian u16 version1
followed by the original 32-byte Groups commitment. RequiredCapabilities and
every new KeyPackage advertise support. OpenMLS authenticates and checks the
extension; join_fork additionally requires exact application-state equality.
Unknown/missing versions, duplicate extension types and changed commitments
are refused; original direct conversation configuration remains independent.

parent_evidence exports signed GroupInfo, original ratchet tree and canonical
Groups bytes only from a committed Store view whose actual MLS roster, context
and Groups state match, after current Keys/policy checks. This serializable
transport value is not a globally latest assertion or an import capability.
A metadata-only update_fork departure cannot be exported as new parent evidence.
Newcomer import, an independently authenticated invitation and transport-ordered
MLS adoption remain separate owner work.

Existing members can call verify_parent_evidence against their exact committed
canonical Groups state and MLS GroupContext. PublicGroup::from_external validates
the original signed GroupInfo/tree in a fresh isolated OpenMLS provider; its
writes never touch the accepted checkpoint. Every imported device certificate
is checked again through current Keys custody, and the complete authenticated
context (including epoch/transcript/tree binding) must match the accepted one.
VerifiedParent has no public constructor or deserializer and is only an
existing-member check, not a newcomer anchor or a lasting authority lease.

Living-room genesis uses `create_room` and `join_room` with the original
Groups Opening/Public decision at group revision one. Complete signed consent,
current certified MLS keys, exact canonical Groups context and one shared
Groups/Threads checkpoint are required. A later Join decision cannot recreate
an MLS tree from its resulting roster. The original immutable-fork entrypoints
continue to refuse room decisions. Restored room genesis can authenticate its
actual current parent and exchange encrypted messages through the same owners.
This does not authorize ordered external joins, profile-key handover, or listing
transfer: those require their separate member-side ordered transition.

Existing survivors use `update_room` / `receive_room_update` for a consecutive
Opening/Public decision that retains or removes members. The accepted Groups
record and old MLS context must match before preparation. Maintained OpenMLS
commits exactly the required removals and replacement canonical context;
unrelated pending proposals, additions, skipped revisions and alternative
extensions refuse. Removed devices need not remain active, but every surviving
device is reverified before the shared Groups/Threads CAS. No application use or
output is released from the candidate before that checkpoint. The resulting
parent evidence represents the real updated MLS roster and Groups state.

This is transport-independent preparation, not an Assembly ordering receipt or
complete Attend admission. The original external-join path additionally needs
its private peer exchange and both ordered commits retained as one pending
operation. RFC 9420 section 12.2 does not permit GroupContextExtensions in an
external Commit; the canonical context update follows in a member commit.
Listing comparison and handover do not follow merely from this local checkpoint.

The candidate retains the commitment actually bound into MLS for genesis and
room updates. At the final shared transaction, the supplied Groups candidate
must have that exact canonical commitment, not merely matching membership
fields or revision. Signed decisions with different effective times cannot be
mixed to publish inconsistent owner checkpoints.
