// Android Gradle settings for the privacysuite-ffi AAR build.
//
// The AAR wraps the cdylib produced by `cargo ndk ... -p privacysuite-ffi`
// plus UniFFI-generated Kotlin bindings. This project is invoked by
// `build-aar.sh` to produce `ffi/build/outputs/aar/ffi-release.aar`,
// which the consumer apps (boomleft-voice, boomleft-scratchpad) copy
// into their own `app/libs/` directory.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "privacysuite-ffi-android"
include(":ffi")
