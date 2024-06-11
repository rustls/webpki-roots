use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};

use chrono::NaiveDate;
use num_bigint::BigUint;
use pki_types::CertificateDer;
use serde::Deserialize;

// Fetch root certificate data from the CCADB server.
//
// Returns an ordered BTreeMap of the root certificates, keyed by the SHA256 fingerprint of the
// certificate. Panics if there are any duplicate fingerprints.
pub async fn fetch_ccadb_roots() -> BTreeMap<String, CertificateMetadata> {
    // Configure a Reqwest client that only trusts the CA certificate expected to be the
    // root of trust for the CCADB server.
    //
    // If we see Unknown CA TLS validation failures from the Reqwest client in the future it
    // likely indicates that the upstream service has changed certificate authorities. In this
    // case the vendored root CA will need to be updated. You can find the current root in use with
    // Chrome by:
    //  1. Navigating to `https://ccadb-public.secure.force.com/mozilla/`
    //  2. Clicking the lock icon.
    //  3. Clicking "Connection is secure"
    //  4. Clicking "Certificate is valid"
    //  5. Clicking the "Details" tab.
    //  6. Selecting the topmost "System Trust" entry.
    //  7. Clicking "Export..." and saving the certificate to `webpki-roots/webpki-ccadb/src/data/`.
    //  8. Committing the updated .pem root CA, and updating the `include_bytes!` path.
    let root = include_bytes!("data/DigiCertGlobalRootCA.pem");
    let root = reqwest::Certificate::from_pem(root).unwrap();
    let client = reqwest::Client::builder()
        .user_agent(format!("webpki-ccadb/v{}", env!("CARGO_PKG_VERSION")))
        .add_root_certificate(root)
        .build()
        .unwrap();

    let ccadb_url =
        "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV";
    eprintln!("fetching {ccadb_url}...");

    let req = client.get(ccadb_url).build().unwrap();
    let csv_data = client
        .execute(req)
        .await
        .expect("failed to fetch CSV")
        .text()
        .await
        .unwrap();

    // Parse the CSV metadata.
    let metadata = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_data.as_bytes())
        .into_deserialize::<CertificateMetadata>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Filter for just roots with the TLS trust bit that are not distrusted as of today's date.
    let trusted_tls_roots = metadata
        .into_iter()
        .filter(CertificateMetadata::trusted_for_tls)
        .collect::<Vec<CertificateMetadata>>();

    // Create an ordered BTreeMap of the roots, panicking for any duplicates.
    let mut tls_roots_map = BTreeMap::new();
    for root in trusted_tls_roots {
        match tls_roots_map.get(&root.sha256_fingerprint) {
            Some(_) => {
                panic!("duplicate fingerprint {}", root.sha256_fingerprint);
            }
            None => {
                tls_roots_map.insert(root.sha256_fingerprint.clone(), root);
            }
        }
    }

    tls_roots_map
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
pub struct CertificateMetadata {
    #[serde(rename = "Common Name or Certificate Name")]
    pub common_name_or_certificate_name: String,

    #[serde(rename = "Certificate Serial Number")]
    pub certificate_serial_number: String,

    #[serde(rename = "SHA-256 Fingerprint")]
    pub sha256_fingerprint: String,

    #[serde(rename = "Trust Bits")]
    pub trust_bits: String,

    #[serde(rename = "Distrust for TLS After Date")]
    pub distrust_for_tls_after_date: String,

    #[serde(rename = "Mozilla Applied Constraints")]
    pub mozilla_applied_constraints: String,

    #[serde(rename = "PEM Info")]
    pub pem_info: String,
}

impl CertificateMetadata {
    /// Returns true iff the certificate has valid TrustBits that include TrustBits::Websites,
    /// and the certificate has no distrust for TLS after date. In all other cases this function
    /// returns false.
    ///
    /// Notably this means a trust anchor with a distrust after date _in the future_ is treated
    /// as untrusted irrespective of the distrust after date. An end-to-end distrust after solution
    /// is NYI: https://github.com/rustls/webpki/issues/259
    fn trusted_for_tls(&self) -> bool {
        let has_tls_trust_bit = self.trust_bits().contains(&TrustBits::Websites);

        match (has_tls_trust_bit, self.tls_distrust_after()) {
            // No website trust bit - not trusted for tls.
            (false, _) => false,
            // Trust bit, populated distrust after - not trusted for tls.
            (true, Some(_)) => false,
            // Has website trust bit, no distrust after - trusted for tls.
            (true, None) => true,
        }
    }

    /// Return the Mozilla applied constraints for the certificate (if any). The constraints
    /// will be encoded in the DER form expected by the webpki crate's TrustAnchor representation.
    pub fn mozilla_applied_constraints(&self) -> Option<Vec<u8>> {
        if self.mozilla_applied_constraints.is_empty() {
            return None;
        }

        // NOTE: To date there's only one CA with a applied constraints value, and it has only one
        // permitted subtree constraint imposed. It's not clear how multiple constraints would be
        // expressed. This method makes a best guess but may need to be revisited in the future.
        // https://groups.google.com/a/ccadb.org/g/public/c/TlDivISPVT4/m/jbWGuM4YAgAJ
        let included_subtrees = self.mozilla_applied_constraints.split(',');

        // Important: the webpki representation of name constraints elides:
        //   - the outer BITSTRING of the X.509 extension value.
        //   - the outer NameConstraints SEQUENCE over the permitted/excluded subtrees.
        //
        // See https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10
        let der = yasna::construct_der(|writer| {
            // permittedSubtrees [0]
            writer.write_tagged_implicit(yasna::Tag::context(0), |writer| {
                // GeneralSubtrees
                writer.write_sequence(|writer| {
                    for included_subtree in included_subtrees {
                        // base GeneralName
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                // DnsName
                                .write_tagged_implicit(yasna::Tag::context(2), |writer| {
                                    writer
                                        .write_ia5_string(included_subtree.trim_start_matches('*'))
                                })
                        })
                        // minimum [0] (absent, 0 default)
                        // maximum [1] (must be omitted).
                    }
                })
            })
        });

        Some(der)
    }

    /// Return the NaiveDate after which this certificate should not be trusted for TLS (if any).
    /// Panics if there is a distrust for TLS after date value that can not be parsed.
    fn tls_distrust_after(&self) -> Option<NaiveDate> {
        match &self.distrust_for_tls_after_date {
            date if date.is_empty() => None,
            date => Some(
                NaiveDate::parse_from_str(date, "%Y.%m.%d")
                    .unwrap_or_else(|_| panic!("invalid distrust for tls after date: {:?}", date)),
            ),
        }
    }

    /// Returns the DER encoding of the certificate contained in the metadata PEM. Panics if
    /// there is an error, or no certificate in the PEM content.
    pub fn der(&self) -> CertificateDer<'static> {
        rustls_pemfile::certs(&mut self.pem().as_bytes())
            .next()
            .unwrap()
            .expect("invalid PEM")
    }

    /// Returns the serial number for the certificate. Panics if the certificate serial number
    /// from the metadata can not be parsed as a base 16 unsigned big integer.
    pub fn serial(&self) -> BigUint {
        BigUint::parse_bytes(self.certificate_serial_number.as_bytes(), 16)
            .expect("invalid certificate serial number")
    }

    /// Returns the colon separated string with the metadata SHA256 fingerprint for the
    /// certificate. Panics if the sha256 fingerprint from the metadata can't be decoded.
    pub fn sha256_fp(&self) -> String {
        x509_parser::utils::format_serial(
            &hex::decode(&self.sha256_fingerprint).expect("invalid sha256 fingerprint"),
        )
    }

    /// Returns the set of trust bits expressed for this certificate. Panics if the raw
    /// trust bits are invalid/unknown.
    fn trust_bits(&self) -> HashSet<TrustBits> {
        self.trust_bits.split(';').map(TrustBits::from).collect()
    }

    /// Returns the PEM metadata for the certificate with the leading/trailing single quotes
    /// removed.
    pub fn pem(&self) -> &str {
        self.pem_info.as_str().trim_matches('\'')
    }
}

impl PartialOrd for CertificateMetadata {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.sha256_fingerprint.cmp(&other.sha256_fingerprint))
    }
}

impl Ord for CertificateMetadata {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sha256_fingerprint.cmp(&other.sha256_fingerprint)
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
#[non_exhaustive]
/// TrustBits describe the possible Mozilla root certificate trust bits.
pub enum TrustBits {
    /// certificate is trusted for Websites (e.g. TLS).
    Websites,
    /// certificate is trusted for Email (e.g. S/MIME).
    Email,
}

impl From<&str> for TrustBits {
    fn from(value: &str) -> Self {
        match value {
            "Websites" => TrustBits::Websites,
            "Email" => TrustBits::Email,
            val => panic!("unknown trust bit: {:?}", val),
        }
    }
}
