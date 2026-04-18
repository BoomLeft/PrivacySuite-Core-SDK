// Root Gradle build for the privacysuite-ffi AAR project.
//
// Plugin versions are pinned: AGP 8.7.3 and Kotlin 2.1.0 match what the
// downstream consumer apps (boomleft-voice, boomleft-scratchpad) use, so
// the AAR produced here won't introduce plugin-version drift when linked
// into those apps.
plugins {
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.1.0" apply false
}
