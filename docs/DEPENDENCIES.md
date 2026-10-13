# Maintained OpenMLS provider and advisory policy

Threads uses OpenMLS 0.9 with its maintained RustCrypto 0.6 provider rather than
implementing a cryptographic provider. The resolver keeps semver ranges and a
reproducible complete lock snapshot; no version is downgraded to evade an audit.

On 2026-10-02, RustSec classified RUSTSEC-2026-0173 for proc-macro-error2
2.0.1 as informational unmaintained, with no patched version. The dependency
arrives through hax-lib-macros 0.3.7 / hax-lib 0.3.7, libcrux-sha3 0.0.10 and
hpke-rs 0.7.0. The newer hax 0.4 line is outside the compatible requirement.

The dated, advisory-specific exception in deny.toml permits this informational
notice only. Vulnerabilities are never excepted. The upstream tracking issue is
https://github.com/GnomedDev/proc-macro-error-2/issues/17. Dependabot continues
refreshing compatible dependencies and cargo-deny checks the advisory database;
unused exceptions fail the policy gate, requiring removal when upstream fixes
the chain. No dependency was downgraded and no crypto provider was forked.

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
