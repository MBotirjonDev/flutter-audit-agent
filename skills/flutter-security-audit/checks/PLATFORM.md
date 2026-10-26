# Android and iOS platform

Flutter apps still ship a native shell. Most platform bugs live in
`AndroidManifest.xml`, `Info.plist`, entitlements and hand-written Kotlin/Swift
(platform channels, plugins).

## Checklist

- [ ] release manifest: no `debuggable`, sane `allowBackup` / `dataExtractionRules`
- [ ] every `exported="true"` component and every `<intent-filter>`
- [ ] `MethodChannel` handlers on the native side: what do they do with arguments from Dart?
- [ ] `FileProvider` paths (`res/xml/file_paths.xml`): no `root-path` or whole-`files-path` sharing
- [ ] sensitive screens (card entry, OTP, documents) use `FLAG_SECURE` / hide content in the iOS app switcher
- [ ] iOS: `*.entitlements` associated domains, keychain sharing groups, URL types in `Info.plist`
- [ ] Android `minSdkVersion` — very old values lose platform protections (e.g. < 24)

### Android manifest

- `android:debuggable="true"` in the main manifest ships a debuggable release.
  Anyone can `run-as` the package, read its files and attach a debugger. High.
- `android:allowBackup="true"` (the default before Android 12 if unset) lets
  `adb backup` / device-transfer tools copy the app's private data. Low on its own, but
  raises the severity of anything weak in `STORAGE.md`.

```xml
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="false">
```

### Exported components

An exported activity, service, receiver or provider can be started by **any** app on the
device. `MainActivity` with the `LAUNCHER` intent filter must be exported — ignore it.

Investigate the rest:

- What intent extras or data URIs does it read? Do they reach a WebView, a file path, a
  payment confirmation, an auth callback?
- Payment SDK result activities (`PaymentResultActivity`, `ReturnActivity`) that accept
  "success" from an intent extra → an attacker app can fake a successful payment if the
  server does not verify it. High.
- Content providers without `android:permission` or with `grantUriPermissions` +
  path traversal.

Fix: `android:exported="false"` when no other app needs it; otherwise require a
signature-level permission and validate every input.
