This workspace contains the crates `webpki-roots`, `webpki-root-certs` and `webpki-ccadb`.

The `webpki-roots` crate contains Mozilla's trusted root certificates for use with
the [webpki](https://github.com/rustls/webpki) or [rustls](https://github.com/rustls/rustls) crates.

The `webpki-root-certs` is similar to `webpki-roots`, but for use with other projects
that require the full self-signed X.509 certificate for each trusted root. This is
unnecessary overhead for `webpki` and `rustls` and you should prefer using
`webpki-roots` for these projects.

The `webpki-ccadb` crate populates the root certificates for the webpki-roots crate
using the data provided by the [Common CA Database (CCADB)](https://www.ccadb.org/).
Inspired by [certifi.io](https://certifi.io/en/latest/).

[![webpki-roots](https://github.com/rustls/webpki-roots/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rustls/webpki-roots/actions/workflows/build.yml)
[![Crate](https://img.shields.io/crates/v/webpki-roots.svg)](https://crates.io/crates/webpki-roots)

# Warning

These libraries are suitable for use in applications that can always be recompiled and instantly deployed.
For applications that are deployed to end-users and cannot be recompiled, or which need certification
before deployment, consider a library that uses the platform native certificate verifier such as
[rustls-platform-verifier]. This has the additional benefit of supporting OS provided CA constraints
and revocation data.

[rustls-platform-verifier]: https://docs.rs/rustls-platform-verifier

# License

The underlying data is MPL-licensed, and the data in `webpki-roots` and `webpki-root-certs`
is therefore a derived work. The tooling in `webpki-ccadb` is licensed under
both MIT and Apache licenses.
