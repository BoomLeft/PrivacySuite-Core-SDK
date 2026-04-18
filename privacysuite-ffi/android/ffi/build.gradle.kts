// Android library module for privacysuite-ffi.
//
// Pipeline:
//   1. `preBuild` runs `cargo ndk` against the parent SDK workspace to build
//      `libprivacysuite_ffi.so` for every target ABI. cargo-ndk's
//      `-o ./src/main/jniLibs` places the .so files exactly where the
//      Android Gradle Plugin expects them, so no extra packaging step is
//      needed — AGP picks them up automatically and bundles them into the
//      AAR.
//   2. `preBuild` then invokes the `uniffi-bindgen` CLI binary (from
//      `cargo build -p privacysuite-ffi --bin uniffi-bindgen --release`)
//      against one of the produced .so files to generate Kotlin bindings
//      into `./src/main/kotlin`. Running against the .so (library-mode
//      bindgen) guarantees the Kotlin matches the ABI actually shipped.
//   3. `android.library` plugin assembles the AAR containing classes.jar
//      (compiled Kotlin bindings), AndroidManifest.xml, and jniLibs/ (the
//      four architecture .so files).
//
// All path resolution is relative to `android/ffi/` — the parent crate
// lives at `../../` relative to this file.

import org.gradle.api.tasks.Exec

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.boomleft.privacysuite"
    compileSdk = 34

    defaultConfig {
        minSdk = 29          // GrapheneOS baseline (Android 10+)
        @Suppress("DEPRECATION")
        targetSdk = 34
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Explicitly declare jniLibs source dir — cargo-ndk emits to this
    // exact path in Phase 1 of the build pipeline.
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    // UniFFI-generated Kotlin depends on JNA to reach the cdylib.
    // Version MUST match what consumer apps declare; both Voice and
    // Scratchpad pin jna 5.15.0 @aar, so this AAR's JNA dep will
    // resolve to the same artifact at consumer-app link time.
    implementation("net.java.dev.jna:jna:5.15.0@aar")

    // kotlinx-coroutines-core is imported by UniFFI-generated Kotlin
    // for the async-callback plumbing even on synchronous-only APIs.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
}

// ---------------------------------------------------------------------------
// Rust build pipeline (cargo-ndk → jniLibs/, then uniffi-bindgen → kotlin/)
// ---------------------------------------------------------------------------

// Resolve the SDK workspace root: `android/ffi/build.gradle.kts` →
// `../../` is the `privacysuite-ffi` crate, and `../../../` is the
// `privacysuite-core-sdk` workspace root that owns `Cargo.toml` and
// the shared `target/` directory.
val sdkWorkspaceDir = project.layout.projectDirectory.dir("../../..").asFile
val cargoManifest = file("$sdkWorkspaceDir/Cargo.toml")
val jniLibsDir = project.layout.projectDirectory.dir("src/main/jniLibs").asFile
val kotlinOutDir = project.layout.projectDirectory.dir("src/main/kotlin").asFile

// Detect the uniffi-bindgen binary path — `cargo build --release` puts it
// under the workspace's target/release/ directory.
val uniffiBindgenBin = file("$sdkWorkspaceDir/target/release/uniffi-bindgen")

// 1. Cross-compile the cdylib for all four Android ABIs via cargo-ndk.
tasks.register<Exec>("cargoNdkBuild") {
    group = "rust"
    description = "Cross-compile libprivacysuite_ffi.so for aarch64 / armv7 / x86_64 / x86."
    workingDir = sdkWorkspaceDir

    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "armeabi-v7a",
        "-t", "x86_64",
        "-t", "x86",
        "-o", jniLibsDir.absolutePath,
        "build", "--release",
        "-p", "privacysuite-ffi",
        "--manifest-path", cargoManifest.absolutePath,
    )

    inputs.file(cargoManifest)
    inputs.dir(file("$sdkWorkspaceDir/privacysuite-ffi/src"))
    inputs.dir(file("$sdkWorkspaceDir/src"))
    outputs.dir(jniLibsDir)
}

// 2. Build the uniffi-bindgen binary itself (host-native, not for Android).
tasks.register<Exec>("cargoBuildBindgen") {
    group = "rust"
    description = "Build the uniffi-bindgen CLI binary for host."
    workingDir = sdkWorkspaceDir

    commandLine(
        "cargo", "build",
        "--release",
        "-p", "privacysuite-ffi",
        "--bin", "uniffi-bindgen",
        "--manifest-path", cargoManifest.absolutePath,
    )

    inputs.file(file("$sdkWorkspaceDir/privacysuite-ffi/src/bin/uniffi-bindgen.rs"))
    outputs.file(uniffiBindgenBin)
}

// 3. Generate Kotlin bindings from the compiled .so (library-mode bindgen).
//    Running against the .so — not the .udl — means the generated Kotlin
//    is derived from the exact ABI shipped in the AAR.
tasks.register<Exec>("uniffiBindgenKotlin") {
    group = "rust"
    description = "Generate Kotlin bindings from libprivacysuite_ffi.so."
    workingDir = sdkWorkspaceDir

    // The arm64 .so is produced by cargoNdkBuild; feed it to bindgen.
    val soPath = file("$sdkWorkspaceDir/target/aarch64-linux-android/release/libprivacysuite_ffi.so")

    dependsOn("cargoBuildBindgen", "cargoNdkBuild")
    commandLine(
        uniffiBindgenBin.absolutePath,
        "generate",
        "--library", soPath.absolutePath,
        "--language", "kotlin",
        "--out-dir", kotlinOutDir.absolutePath,
    )

    inputs.file(soPath)
    outputs.dir(kotlinOutDir)
}

// Wire the pipeline into the standard preBuild hook so `assembleRelease`
// triggers Rust compilation automatically.
tasks.named("preBuild") {
    dependsOn("uniffiBindgenKotlin")
}
