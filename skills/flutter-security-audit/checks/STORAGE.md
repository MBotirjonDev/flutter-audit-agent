# Data at rest

Threat model: a stolen or rooted device, a malicious backup/restore, a shared device,
forensic extraction, or another app exploiting a file-sharing bug.

## Checklist

- [ ] list every place the app persists data: SharedPreferences, Hive, Isar, sqflite/drift, files (`path_provider`), cache, secure storage
- [ ] for each: what is stored? tokens, PII, chat history, documents, paid content?
- [ ] are auth tokens and refresh tokens in `flutter_secure_storage`?
- [ ] is data cleared on logout (including secure storage, which survives app reinstall on iOS)?
- [ ] are sensitive files written to external/shared storage or `getTemporaryDirectory()` and shared?
- [ ] are logs, crash reports and analytics events free of tokens and PII?

### SharedPreferences and NSUserDefaults

`shared_preferences` writes an XML file (Android) or plist (iOS) in the app sandbox.
Not encrypted. Readable with root/jailbreak, and on Android included in backups when
`allowBackup` is on (see `PLATFORM.md`).

High-impact when it holds: access tokens, **refresh tokens** (long-lived account
takeover), passwords, PIN codes, OTP secrets, card data.

```dart
// ❌
await prefs.setString('refresh_token', token);
// ✅
const storage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
  iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
);
await storage.write(key: 'refresh_token', value: token);
```

Theme, locale and onboarding flags in SharedPreferences are fine — do not report them.

#### Local PIN / app lock

If the app stores a PIN (or its hash) locally and compares it in Dart, the lock is
bypassable on a rooted device. A 4–6 digit PIN hashed with SHA-256 is brute-forced in
milliseconds. This is acceptable as a UX lock; it is a finding only if the app presents it
as protecting data that is not otherwise encrypted with a key held in Keystore/Keychain.

### Hive, Isar, sqflite

Unencrypted by default. Report only when the content is sensitive. Fix options:
`HiveAesCipher` with a key in secure storage, `sqlcipher_flutter_libs` for sqflite/drift,
or not caching the data at all. Hardcoding the cipher key defeats the purpose
(`CRYPTO.md#hardcoded-keys`).

### Logs

`print()` and `debugPrint()` run in release builds and go to logcat / Xcode console.
Crash reporters (Crashlytics, Sentry) upload breadcrumbs. Dio `LogInterceptor` with
`requestHeader: true` logs the `Authorization` header.

```dart
// ❌ release builds log every bearer token
dio.interceptors.add(LogInterceptor(requestHeader: true, responseBody: true));
// ✅
if (kDebugMode) dio.interceptors.add(LogInterceptor(responseBody: true));
```
