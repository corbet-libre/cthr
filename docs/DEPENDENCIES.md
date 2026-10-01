# Maintained OpenMLS provider and current audit blocker

Threads uses OpenMLS 0.9 with its maintained RustCrypto 0.6 provider rather than
implementing a cryptographic provider. The resolver keeps semver ranges and a
reproducible complete lock snapshot; no version is downgraded to evade an audit.

Current dependency policy refuses RUSTSEC-2026-0173: proc-macro-error2 2.0.1 is
unmaintained. It arrives through hax-lib-macros 0.3.7 / hax-lib 0.3.7, libcrux-sha3
0.0.10 and hpke-rs 0.7.0. RustSec classifies it as informational unmaintained,
with no patched proc-macro-error2 release. The newer hax 0.4 line is outside the
upstream compatible requirement. This crate has not suppressed the advisory or
substituted its own crypto. Full green acceptance waits upstream resolution or
an explicitly reviewed dependency disposition; functional tests alone do not pass
that gate.

Primary evidence:

- https://rustsec.org/advisories/RUSTSEC-2026-0173
- https://github.com/openmls/openmls/tree/main/openmls_rust_crypto
- https://github.com/cryspen/hax

Governor 0.10 owns the GCRA arithmetic. Its documented StateStore/Clock ports
store only the virtual-arrival scalar with the encrypted MLS checkpoint, with a
stable zero origin across restores. The owner supplies signed quota/burst and
current time. No custom quota algorithm or refill policy is implemented.
https://docs.rs/governor/0.10.4/governor/state/trait.StateStore.html
https://docs.rs/governor/0.10.4/governor/struct.RateLimiter.html

Postcard 1 with defaults disabled and alloc enabled is Groups' canonical local
codec. The unused default heapless feature is disabled, removing its deprecated
atomic-polyfill dependency without changing Group encoding or advisory policy.
