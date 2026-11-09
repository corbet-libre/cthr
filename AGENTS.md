# cthr agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cthr` — lib `0`, `invitations`
  `12`, `threads` `10` passed, exit 0
- `~/agents/scratch/cbuild <lane> fmt -p cthr -- --check` — must be clean
- Full gate (clippy `--locked`, native + actual wasm vectors, 100% reachable
  line and branch coverage, dependency policy) runs in CI: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Real OpenMLS roundtrip is durable; tamper consumes no ratchets
  -> `tests/it/threads.rs::real_roundtrip_is_durable_and_tamper_does_not_consume_ratchets`
- Candidates refuse cross-scope and changed-checkpoint commits
  -> `tests/it/threads.rs::candidates_refuse_cross_scope_and_changed_checkpoint`
- Fork membership, policy and checkpoint publish as one transition
  -> `tests/it/threads.rs::real_fork_membership_policy_and_checkpoint_are_one_transition`
- Malformed checkpoints and locked keys fail without output
  -> `tests/it/threads.rs::malformed_owned_checkpoints_and_locked_keys_fail_without_output`
- Invitation needs the same authorized device and current publication
  -> `tests/it/invitations.rs::genuine_invitation_uses_same_authorized_device_and_current_publication`
- Certificate substitution never reuses consent or device proof
  -> `tests/it/invitations.rs::certificate_substitution_never_reuses_original_consent_or_device_proof`
- Signed revocations and policy epochs refuse old invitations
  -> `tests/it/invitations.rs::fresh_signed_revocations_and_policy_epoch_refuse_old_invitation`
- Wire framing is exact; signature damage never creates a capability
  -> `tests/it/invitations.rs::wire_has_exact_framing_and_signature_damage_never_creates_capability`
- Never accept raw UI rosters; Groups owns membership, Waves owns release
  -> `tests/it/threads.rs::fork_owner_checkpoint_boundaries`,
  `tests/it/invitations.rs::current_contact_scanner_is_required_even_with_genuine_publication`

Pointers: `src/fork.rs`, `src/invitation.rs`, `src/room.rs`,
`docs/CONTRACT.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking exception; no GPL/AGPL-only deps.
