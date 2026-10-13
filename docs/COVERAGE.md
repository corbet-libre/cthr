# Coverage

Every emitted production source line and branch must execute. CI retains raw
LLVM JSON and LCOV from the same actual test execution, using floating nightly
only for branch instrumentation. Stable native and actual Chrome/Wasm vectors
remain mandatory. The two narrow exception proposals below require independent
review; no threshold is lowered and no function or file is excluded.

The shared source checker requires exact JSON/LCOV file and branch inventories,
agreed raw summaries, nonempty source lines and positive DA/BRDA counts. Original
JSON generic-instantiation totals remain visible diagnostics; source coverage
does not claim every possible generic instantiation. Tests are under tests/ and
excluded from production counts. Cargo.lock is resolved once and reused locked.

PreparedMessage's public peer certificate is extracted from the just-validated
private candidate MLS tree. Its internal assertions cover immutable construction
invariants, not I/O or verification failures. Invalid input and current authority
checks are ordinary fallible operations before construction/publication.

## Groups revision invariant

Membership effects now carry the per-group revision. The shared adapter matches
the complete effect and the canonical target GroupState revision; the independent
Snapshot revision remains the local Store CAS fence. The former claim that every
effect equals the device-wide revision is superseded. New per-group transcript
and MLS context paths require actual coverage qualification; no new exclusion
or accepted coverage claim is introduced by this source change.

## Read from the validated Store

Only the error mapper on `src/fork.rs:573` is proposed for exclusion.
`commit_groups` first loads Contacts from the exclusively borrowed Store and
checks its version. This establishes that the Store is open. Before the later
`read("cgrp", b"snapshot.v1")`, the concrete Groups candidate checks its own
times and calls this adapter. No intervening operation mutates/closes the Store,
awaits a backend, or hands it to an external callback. The current Storage read
can fail only for a closed Store or invalid owner/key; both constant identifiers
are nonempty and shorter than its 256-byte limit. Missing records return None.
Corrupt record content, mismatched predecessor revision, and a later backend CAS
loss remain reachable refusals and execute against real encrypted Stores.

Reference owners: cwst `f1681ebb167f3d3328f994a6e5d8d5c44f5e68ea`
`src/store.rs`/`src/lib.rs`, ctcs `5a66c1f9fe6b9e0476c1e82660bd5818f59e5a28`
`src/lib.rs`, and the Groups implementation above.

## Proof invalidation

The exception manifest pins exact native line/branch coordinates, source text
and complete local invariant-source hashes. The shared checker compares the
complete JSON/LCOV/annotated inventories before applying an exception and rejects
missing, changed, duplicate or executed exceptions. Thirteen regression tests
exercise those checks.

The proof also depends on owner behavior. CI checks the actual resolved owner
sources against `.github/coverage-owner-contracts.json`; changing any relevant
owner module invalidates the proof until reviewed. Six regressions test missing,
duplicate, foreign, changed and escaping metadata/source inputs. Dependencies
still resolve from branch main; an unchanged owner implementation at a newer
revision passes. These hashes restrict the validity of an exclusion, not Cargo
resolution, and do not turn pending review into acceptance.
