fn main() {
    println!("cargo:rerun-if-env-changed=NO_EMBEDDED_WEBPKI_ROOTS");
    println!("cargo:rustc-check-cfg=cfg(no_embedded_webpki_roots)");

    if std::env::var("NO_EMBEDDED_WEBPKI_ROOTS").is_ok_and(|value| !value.is_empty()) {
        println!("cargo:rustc-cfg=no_embedded_webpki_roots");
    }
}
