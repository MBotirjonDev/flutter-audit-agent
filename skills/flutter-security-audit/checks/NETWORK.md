# Network

Threat model: an attacker on the same Wi-Fi (cafés, universities, coworkings), a
malicious hotspot, or a compromised router can read and modify traffic that is not
properly protected by TLS.

## Checklist

- [ ] every remote base URL uses `https://` (check flavors/env configs, not just one file)
- [ ] no `badCertificateCallback` returning true, no `HttpOverrides.global` that disables validation in release
- [ ] Dio `IOHttpClientAdapter` / `createHttpClient` overrides reviewed
- [ ] Android `usesCleartextTraffic` and `network_security_config.xml` (`cleartextTrafficPermitted`, user CAs trusted in release?)
- [ ] iOS ATS exceptions in `Info.plist`
- [ ] tokens or PII never in URL query strings (they end up in server and proxy logs)
- [ ] WebSocket URLs use `wss://`
- [ ] if certificate pinning is used: is there a backup pin and an expiry plan?

### Certificate validation

```dart
// ❌ accepts any certificate — classic "it worked with my dev server" leftover
HttpOverrides.global = MyOverrides(); // with badCertificateCallback => true
(dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () =>
    HttpClient()..badCertificateCallback = (c, h, p) => true;
```

Critical when reachable in release builds. Validate: is the override inside
`if (kDebugMode)` or a dev-only flavor `main_dev.dart`? If the release entry point never
installs it, downgrade to hardening (remove dead code) — still worth noting.

Pinning (`http_certificate_pinning`, Dio `badCertificateCallback` with a fingerprint
check that returns **false** on mismatch) is defense-in-depth; its absence is not a
vulnerability on its own.

### Cleartext traffic

- Dart: `http://` URLs to non-local hosts.
- Android: `android:usesCleartextTraffic="true"` or a network security config with
  `cleartextTrafficPermitted="true"` in `<base-config>`. Since Android 9 cleartext is
  blocked by default, so this attribute is usually an explicit opt-in to insecurity.
- iOS: `NSAllowsArbitraryLoads` = true.

Local dev hosts (`10.0.2.2`, `localhost`, `127.0.0.1`) are fine in debug configs.

Impact depends on what travels over HTTP: login, tokens, payments → high; public
catalogue images → low.

```xml
<!-- android/app/src/debug/res/xml/network_security_config.xml (debug only) -->
<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">10.0.2.2</domain>
  </domain-config>
</network-security-config>
```
