#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# build-aar.sh — reproducibly produce the privacysuite-ffi Android AAR.
#
# Pipeline:
#   1. Ensure all four Android Rust targets are installed.
#   2. Build the `uniffi-bindgen` host binary (release).
#   3. Use cargo-ndk to cross-compile `libprivacysuite_ffi.so` for
#      arm64-v8a, armeabi-v7a, x86_64, and x86, placing the resulting
#      shared objects directly into the Gradle module's
#      `ffi/src/main/jniLibs/<abi>/` tree.
#   4. Run uniffi-bindgen in library mode against the arm64 .so to emit
#      Kotlin bindings into `ffi/src/main/kotlin/`.
#   5. Invoke Gradle to assemble the release AAR.
#
# Environment expectations (see the SDK README / boomleft-env):
#   ANDROID_NDK_HOME → r27c (/home/mike/Android/Sdk/ndk/27.2.12479018)
#   JAVA_HOME        → JDK 17
#   PATH             → includes `cargo`, `cargo-ndk`, `rustup`, `gradle`.
#
# Output:
#   privacysuite-ffi/android/ffi/build/outputs/aar/ffi-release.aar
#   copied to
#   privacysuite-ffi/android/build/privacysuite-ffi-<version>.aar
# -----------------------------------------------------------------------------

set -euo pipefail

# --- resolve locations --------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFI_CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SDK_ROOT="$(cd "${FFI_CRATE_DIR}/.." && pwd)"
GRADLE_ROOT="${SCRIPT_DIR}"

# Version tag for the output AAR. Matches `privacysuite-ffi` crate version
# extracted from its Cargo.toml so the artifact filename tracks the SDK tag.
FFI_VERSION="$(
    awk -F' *= *' '/^version/ { gsub(/"/, "", $2); print $2; exit }' \
        "${FFI_CRATE_DIR}/Cargo.toml"
)"
if [[ -z "${FFI_VERSION}" ]]; then
    echo "ERROR: could not detect privacysuite-ffi version from Cargo.toml" >&2
    exit 1
fi

echo "================================================================="
echo " privacysuite-ffi Android AAR build"
echo " SDK root:       ${SDK_ROOT}"
echo " FFI crate:      ${FFI_CRATE_DIR}"
echo " Gradle root:    ${GRADLE_ROOT}"
echo " Output version: ${FFI_VERSION}"
echo "================================================================="

# --- sanity checks ------------------------------------------------------------
if [[ -z "${ANDROID_NDK_HOME:-}" ]] || [[ ! -d "${ANDROID_NDK_HOME}" ]]; then
    echo "ERROR: ANDROID_NDK_HOME is not set or does not exist." >&2
    echo "       Source ~/.boomleft-env or export ANDROID_NDK_HOME manually." >&2
    exit 1
fi

command -v cargo >/dev/null 2>&1 || {
    echo "ERROR: cargo not on PATH. Install Rust via rustup." >&2
    exit 1
}

command -v cargo-ndk >/dev/null 2>&1 || {
    echo "ERROR: cargo-ndk not on PATH. Install with: cargo install cargo-ndk" >&2
    exit 1
}

# --- 1. ensure Rust targets are installed -------------------------------------
echo ""
echo "[1/5] Ensuring Android Rust targets are installed..."
REQUIRED_TARGETS=(
    aarch64-linux-android
    armv7-linux-androideabi
    x86_64-linux-android
    i686-linux-android
)
INSTALLED_TARGETS="$(rustup target list --installed)"
for t in "${REQUIRED_TARGETS[@]}"; do
    if ! echo "${INSTALLED_TARGETS}" | grep -q "^${t}$"; then
        echo "  - adding ${t}"
        rustup target add "${t}"
    else
        echo "  - ${t} already installed"
    fi
done

# --- 2. build uniffi-bindgen host binary --------------------------------------
echo ""
echo "[2/5] Building uniffi-bindgen host binary..."
cargo build --release \
    --manifest-path "${SDK_ROOT}/Cargo.toml" \
    -p privacysuite-ffi \
    --bin uniffi-bindgen

UNIFFI_BINDGEN="${SDK_ROOT}/target/release/uniffi-bindgen"
if [[ ! -x "${UNIFFI_BINDGEN}" ]]; then
    echo "ERROR: uniffi-bindgen binary was not produced at ${UNIFFI_BINDGEN}" >&2
    exit 1
fi

# --- 3. cross-compile cdylib for all four ABIs --------------------------------
echo ""
echo "[3/5] Cross-compiling libprivacysuite_ffi.so for all Android ABIs..."
JNI_LIBS_DIR="${GRADLE_ROOT}/ffi/src/main/jniLibs"
mkdir -p "${JNI_LIBS_DIR}"

(
    cd "${SDK_ROOT}"
    cargo ndk \
        -t arm64-v8a \
        -t armeabi-v7a \
        -t x86_64 \
        -t x86 \
        -o "${JNI_LIBS_DIR}" \
        build --profile release-ffi \
        -p privacysuite-ffi \
        --manifest-path "${SDK_ROOT}/Cargo.toml"
)

# --- 4. generate Kotlin bindings ----------------------------------------------
echo ""
echo "[4/5] Generating Kotlin bindings via uniffi-bindgen..."
KOTLIN_OUT_DIR="${GRADLE_ROOT}/ffi/src/main/kotlin"
mkdir -p "${KOTLIN_OUT_DIR}"

ARM64_SO="${SDK_ROOT}/target/aarch64-linux-android/release-ffi/libprivacysuite_ffi.so"
if [[ ! -f "${ARM64_SO}" ]]; then
    echo "ERROR: expected arm64 cdylib not found at ${ARM64_SO}" >&2
    exit 1
fi

# uniffi 0.31 takes the library path as a positional argument; --library
# is deprecated and library mode is auto-detected from the file header.
# --config points at the FFI crate's uniffi.toml so the generated Kotlin
# lands in `com.boomleft.privacysuite.*` instead of `uniffi.privacysuite_ffi.*`.
"${UNIFFI_BINDGEN}" generate \
    "${ARM64_SO}" \
    --language kotlin \
    --config "${FFI_CRATE_DIR}/uniffi.toml" \
    --out-dir "${KOTLIN_OUT_DIR}"

# Post-bindgen strip: the AAR ships production-sized .so files. The
# release-ffi profile preserved .symtab so uniffi-bindgen could read
# UniFFI metadata; now that we've consumed it, strip .symtab to match
# the regular release profile's footprint.
echo ""
echo "[4b/5] Stripping .so files to production size (post-bindgen)..."
STRIP_BIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
if [[ ! -x "${STRIP_BIN}" ]]; then
    echo "WARNING: llvm-strip not found at ${STRIP_BIN} — AAR will ship unstripped .so files." >&2
else
    for so in "${JNI_LIBS_DIR}"/*/libprivacysuite_ffi.so; do
        "${STRIP_BIN}" --strip-unneeded "${so}" 2>/dev/null || true
    done
fi

# --- 5. assemble AAR via Gradle -----------------------------------------------
echo ""
echo "[5/5] Assembling AAR via Gradle..."
cd "${GRADLE_ROOT}"

# Prefer the Gradle wrapper if present; otherwise fall back to system Gradle.
if [[ -x "./gradlew" ]]; then
    GRADLE_CMD="./gradlew"
else
    GRADLE_CMD="gradle"
fi

"${GRADLE_CMD}" :ffi:assembleRelease

# --- locate + rename the output -----------------------------------------------
RAW_AAR="${GRADLE_ROOT}/ffi/build/outputs/aar/ffi-release.aar"
if [[ ! -f "${RAW_AAR}" ]]; then
    echo "ERROR: Gradle finished but ${RAW_AAR} was not produced." >&2
    exit 1
fi

DIST_DIR="${GRADLE_ROOT}/build"
mkdir -p "${DIST_DIR}"
VERSIONED_AAR="${DIST_DIR}/privacysuite-ffi-${FFI_VERSION}.aar"
cp "${RAW_AAR}" "${VERSIONED_AAR}"

echo ""
echo "================================================================="
echo " Build complete."
echo ""
echo "   Raw AAR      : ${RAW_AAR}"
echo "   Versioned AAR: ${VERSIONED_AAR}"
echo ""
echo " SHA-256:"
sha256sum "${VERSIONED_AAR}" || true
echo ""
echo " To consume from boomleft-voice / boomleft-scratchpad, copy"
echo " the versioned AAR into the app's app/libs/ directory and"
echo " ensure the implementation(...) coordinate matches the filename"
echo " (without the .aar suffix), e.g."
echo "   implementation(name = \"privacysuite-ffi-${FFI_VERSION}\", ext = \"aar\")"
echo "================================================================="
