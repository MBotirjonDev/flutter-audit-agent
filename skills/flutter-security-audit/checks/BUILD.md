# Build and release

Hardening, mostly. These rarely create a vulnerability alone, but they decide how cheap
it is to reverse-engineer the app and to abuse everything else in this audit.

## Checklist

- [ ] release builds use `--obfuscate --split-debug-info=<dir>` (and symbols are not committed)
- [ ] Android release: `minifyEnabled`/`isMinifyEnabled = true`, `shrinkResources true`, ProGuard rules for plugins
- [ ] release is signed with the release key, not `signingConfigs.debug`
- [ ] `key.properties`, `*.jks`, `*.keystore`, `google-services.json` for prod are git-ignored where intended
- [ ] debug-only code paths (`kDebugMode`, dev menus, mock auth, "skip login") cannot be reached in release
- [ ] Flutter web: no source maps or `.env` deployed, CSP set in `web/index.html`, Firebase hosting headers
- [ ] CI (GitHub Actions/Codemagic): secrets not echoed in logs, `pull_request_target` workflows don't run untrusted code with secrets
- [ ] dependencies: `flutter pub outdated`, known-vulnerable packages, git dependencies pinned to a commit

### Obfuscation and shrinking

```bash
flutter build apk --release --obfuscate --split-debug-info=build/symbols
flutter build ipa --release --obfuscate --split-debug-info=build/symbols
```

```kotlin
// android/app/build.gradle.kts
buildTypes {
    release {
        isMinifyEnabled = true
        isShrinkResources = true
        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        signingConfig = signingConfigs.getByName("release")
    }
}
```

Never present obfuscation as a fix for a leaked secret or a missing server check — it
only slows an attacker down. Rate missing obfuscation as **low / hardening**.

A release `buildType` that uses `signingConfigs.debug` is worth flagging: the debug key
is shared and public-ish, so updates could be signed by anyone who has it (for apps not
using Play App Signing or distributed outside Play).
