//! `uniffi-bindgen` CLI binary.
//!
//! This binary is consumed by the Android AAR build pipeline (see
//! `privacysuite-ffi/android/build-aar.sh`) to generate Kotlin bindings
//! from the compiled `libprivacysuite_ffi.so` using the library-mode
//! bindgen flow. Running via the crate-local binary (instead of installing
//! `uniffi-bindgen-cli` from crates.io) keeps the bindgen version lock-step
//! with whatever `privacysuite-ffi` depends on, so the generated Kotlin
//! always matches the procmacro scaffolding shipped in `lib.rs`.
fn main() {
    uniffi::uniffi_bindgen_main()
}
