# Agent instructions

Write comments and documentation in English. Follow README Scope and CONTRACT.
Threads owns maintained OpenMLS execution and accepted history. Groups owns
membership, Waves owns release, Delivery owns retries/ACKs, Keys owns signing,
and Storage owns atomic persistence. Never accept raw UI rosters as authority.
No own crypto, identity binding, ledger or network framing. Candidate state and
outputs become visible only after one shared durable checkpoint.

No workstation Cargo, including fmt/metadata. Run strict stable checks, native
and actual Wasm vectors, dependency policy, and 100% reachable line AND branch
coverage on public CI. Document only justified unreachable exclusions. Expensive
load/churn uses the established owned scheduler. First-party git dependencies
follow main, exactly one locked revision per crate. Keep reproducible locks.

Plain-English commits, explicit-path staging, pull --rebase before main pushes.
No force push, registry publication, paid operations, AI attribution or secrets.
LGPL-3.0-only WITH LGPL-3.0-linking-exception. No GPL/AGPL-only dependencies.
