# webpki-ccadb
This is a crate to fetch Mozilla's root certificates for use with
[webpki-roots](https://github.com/rustls/webpki-roots) crate.

This crate is inspired by [certifi.io](https://certifi.io/en/latest/) and
uses the data provided by the [Common CA Database (CCADB)](https://www.ccadb.org/).

[![webpki-ccadb](https://github.com/rustls/webpki-roots/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rustls/webpki-roots/actions/workflows/build.yml)
[![Crate](https://img.shields.io/crates/v/webpki-ccadb.svg)](https://crates.io/crates/webpki-ccadb)
