This workspace contains the crates webpki-roots and webpki-ccadb.

The webpki-roots crate contains Mozilla's root certificates for use with
the [webpki](https://github.com/rustls/webpki) or
[rustls](https://github.com/rustls/rustls) crates.

The webpki-ccadb crate populates the root certificates for the webpki-roots crate
using the data provided by the [Common CA Database (CCADB)](https://www.ccadb.org/).
Inspired by [certifi.io](https://certifi.io/en/latest/).

[![webpki-roots](https://github.com/rustls/webpki-roots/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rustls/webpki-roots/actions/workflows/build.yml)
[![Crate](https://img.shields.io/crates/v/webpki-roots.svg)](https://crates.io/crates/webpki-roots)

# Warning

This library is suitable for use in applications that can always be recompiled and instantly deployed.
For applications that are deployed to end-users and cannot be recompiled, or which need certification
before deployment, consider a library that uses the platform native certificate verifier such as
[rustls-platform-verifier]. This has the additional benefit of supporting OS provided CA constraints
and revocation data.

[rustls-platform-verifier]: https://docs.rs/rustls-platform-verifier

# License
The underlying data is MPL-licensed, and `webpki-roots/src/lib.rs`
is therefore a derived work.

# Regenerating sources
Sources are generated in an integration test, in `webpki-roots/tests/codegen.rs`. The test
will fail if the sources are out of date relative to upstream, and update
`webpki-roots/src/lib.rs` if so. The code is generated in deterministic order so changes
to the source should only result from upstream changes.
