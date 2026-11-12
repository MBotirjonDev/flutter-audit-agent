'use strict';
/**
 * Triage rules for flutter-security-audit.
 *
 * Every hit is a LEAD, not a finding. The skill workflow requires an agent
 * (or a human) to trace each lead before it becomes a confirmed finding.
 *
 * Adding a rule:
 *   - id:        FSA-<AREA>-<NNN>  (AREA: SEC, STO, NET, AND, IOS, WEB, CRY, BE, BLD, LOG)
 *   - files:     file-name test (RegExp against the path, forward slashes)
 *   - pattern:   RegExp. Use the `g` flag. Use `m` when you anchor with ^/$.
 *   - exclude:   optional RegExp; dropped if the file PATH or the matched LINE matches it
 *   - matchExclude: optional RegExp; dropped if the full matched TEXT matches it
 *                (useful for multi-line XML elements)
 *   - severity:  critical | high | medium | low | info  (triage guess only)
 *   - masvs:     OWASP MASVS v2 control the rule maps to
 *   - guide:     checks/<FILE>.md section an agent should read to validate it
 *   - fixture:   add a positive case to tests/fixtures/vuln_app and make sure
 *                tests/fixtures/clean_app stays clean. `npm test` must pass.
 */

const DART = /\.dart$/;
const MANIFEST = /AndroidManifest\.xml$/;
const PLIST = /Info\.plist$/;
const GRADLE = /build\.gradle(\.kts)?$/;
const PUBSPEC = /(^|\/)pubspec\.yaml$/;
const FIREBASE_RULES = /(firestore\.rules|storage\.rules|database\.rules\.json)$/;
const ANY_TEXT = /\.(dart|ya?ml|json|xml|plist|gradle|kts|properties|env|js|ts|swift|kt|java|m|h)$|(^|\/)\.env(\.[\w-]+)?$/;

module.exports = [
  // ---------------------------------------------------------------- secrets
  {
    id: 'FSA-SEC-001',
    title: 'Google / Firebase API key in source',
    severity: 'medium',
    files: ANY_TEXT,
    exclude: /google-services\.json|GoogleService-Info\.plist|firebase_options\.dart/,
    pattern: /AIza[0-9A-Za-z_\-]{35}/g,
    masvs: 'MASVS-STORAGE-2',
    guide: 'SECRETS.md#google-and-firebase-keys',
    message: 'Google API key embedded in the app. Firebase client keys are expected to be public, but Maps/Places/Gemini/other paid keys are not.',
    fix: 'Check which APIs the key can call in Google Cloud Console. Restrict it to your package name / bundle ID + SHA-1, or move paid calls behind your backend.',
  },
  {
    id: 'FSA-SEC-002',
    title: 'Supabase service_role key referenced in the client',
    severity: 'critical',
    files: ANY_TEXT,
    pattern: /service_role|SERVICE_ROLE/g,
    masvs: 'MASVS-STORAGE-2',
    guide: 'SECRETS.md#backend-admin-keys',
    message: 'The service_role key bypasses Row Level Security. Shipping it in a mobile app gives every user full database access.',
    fix: 'Remove it from the app, rotate it in Supabase, and use the anon/publishable key + RLS policies. Admin work belongs in an Edge Function.',
  },
  {
    id: 'FSA-SEC-003',
    title: 'Hardcoded secret-looking string',
    severity: 'high',
    files: DART,
    pattern: /\b\w*(?:api_?key|apikey|secret|client_?secret|access_?token|auth_?token|password|passwd|private_?key)\w*\s*[:=]\s*['"][^'"\s$]{12,}['"]/gi,
    exclude: /(hint|label|title|errorText|validator|tr\(|\.tr\b|TextField|InputDecoration|example|placeholder|fsa-ignore)/i,
    masvs: 'MASVS-STORAGE-2',
    guide: 'SECRETS.md#hardcoded-credentials',
    message: 'A credential-like value is hardcoded. Anything in a Flutter binary can be extracted with `strings` or reFlutter, even with --obfuscate.',
    fix: 'Move the secret to the server. If the client must hold a key, scope it to the minimum permissions and treat it as public.',
  },
  {
    id: 'FSA-SEC-004',
    title: 'Private key material in the repository',
    severity: 'critical',
    files: ANY_TEXT,
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    masvs: 'MASVS-CRYPTO-2',
    guide: 'SECRETS.md#private-keys',
    message: 'A private key is committed. Treat it as compromised.',
    fix: 'Rotate the key, remove it from git history (git filter-repo), and load it from a secret manager on the server.',
  },
  {
    id: 'FSA-SEC-005',
    title: 'Live payment provider secret key',
    severity: 'critical',
    files: ANY_TEXT,
    pattern: /\b(?:sk_live_[0-9A-Za-z]{16,}|rk_live_[0-9A-Za-z]{16,})/g,
    masvs: 'MASVS-STORAGE-2',
    guide: 'SECRETS.md#payment-keys',
    message: 'A live secret payment key (e.g. Stripe sk_live_) lets anyone issue refunds, read customers and create charges.',
    fix: 'Rotate immediately. Only publishable keys belong in the app; secret keys stay on the server. The same applies to Payme/Click merchant secrets.',
  },
  {
    id: 'FSA-SEC-006',
    title: 'Telegram bot token in source',
    severity: 'high',
    files: ANY_TEXT,
    pattern: /\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b/g,
    masvs: 'MASVS-STORAGE-2',
    guide: 'SECRETS.md#telegram-bot-tokens',
    message: 'Anyone with the bot token fully controls the bot: read updates, send messages as the bot, change webhooks.',
    fix: 'Revoke the token via @BotFather (/revoke) and call the Bot API only from your backend.',
  },
  {
    id: 'FSA-SEC-007',
    title: '.env file bundled as a Flutter asset',
    severity: 'high',
    files: PUBSPEC,
    pattern: /^\s*-\s*['"]?\.env(?:\.[\w-]+)?['"]?\s*$/gm,
    masvs: 'MASVS-STORAGE-2',
    guide: 'SECRETS.md#env-files-are-not-secret',
    message: 'flutter_dotenv-style .env assets are packed into the APK/IPA as plain text. They are configuration, not a secret store.',
    fix: 'Keep only public config in the asset. Anything secret must live on the server.',
  },

  // ---------------------------------------------------------------- storage
  {
    id: 'FSA-STO-001',
    title: 'Sensitive value stored in SharedPreferences',
    severity: 'high',
    files: DART,
    pattern: /\.set(?:String|StringList)\(\s*['"][^'"]*(?:token|jwt|session|password|passwd|secret|pin|otp|refresh|credential)[^'"]*['"]/gi,
    masvs: 'MASVS-STORAGE-1',
    guide: 'STORAGE.md#sharedpreferences-and-nsuserdefaults',
    message: 'SharedPreferences / NSUserDefaults are plain files. On rooted/jailbroken devices and in some backups they can be read directly.',
    fix: 'Use flutter_secure_storage (Keystore / Keychain) for tokens and credentials.',
  },
  {
    id: 'FSA-STO-002',
    title: 'Hive box opened without encryption',
    severity: 'low',
    files: DART,
    pattern: /Hive\.open(?:Lazy)?Box(?:<[^>]*>)?\(\s*['"][^'"]+['"]\s*\)/g,
    masvs: 'MASVS-STORAGE-1',
    guide: 'STORAGE.md#hive-isar-sqflite',
    message: 'Unencrypted Hive box. Fine for non-sensitive cache; a problem if it holds tokens, PII or paid content.',
    fix: 'If the box holds sensitive data, pass encryptionCipher: HiveAesCipher(key) with the key kept in flutter_secure_storage.',
  },
  {
    id: 'FSA-LOG-001',
    title: 'Sensitive value written to logs',
    severity: 'medium',
    files: DART,
    pattern: /\b(?:print|debugPrint|log|logger\.\w+|Logger\(\)\.\w+)\s*\([^;\n]*\b(?:token|jwt|password|passwd|otp|secret|cardNumber|cvv|pinfl|passport)\b/gi,
    masvs: 'MASVS-STORAGE-2',
    guide: 'STORAGE.md#logs',
    message: 'Logs are readable via `adb logcat`, crash reporters and device consoles. print() also runs in release builds.',
    fix: 'Remove the log, or guard it with `if (kDebugMode)` and redact the value.',
  },

  // ---------------------------------------------------------------- network
  {
    id: 'FSA-NET-001',
    title: 'TLS certificate validation disabled',
    severity: 'critical',
    files: DART,
    pattern: /badCertificateCallback\s*=\s*\([^)]*\)\s*(?:=>\s*true|\{\s*return\s+true\s*;?\s*\})/g,
    masvs: 'MASVS-NETWORK-1',
    guide: 'NETWORK.md#certificate-validation',
    message: 'Every certificate is accepted, so anyone on the same Wi-Fi can read and modify traffic (including tokens).',
    fix: 'Remove the callback. For self-signed dev servers, guard it with kDebugMode and a specific host check; for production consider certificate pinning.',
  },
  {
    id: 'FSA-NET-002',
    title: 'Cleartext HTTP endpoint',
    severity: 'medium',
    files: DART,
    pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|schemas\.|www\.w3\.org)[^'"]+['"]/g,
    masvs: 'MASVS-NETWORK-1',
    guide: 'NETWORK.md#cleartext-traffic',
    message: 'Requests over http:// can be read and modified in transit.',
    fix: 'Use https:// for every remote endpoint.',
  },
  {
    id: 'FSA-NET-003',
    title: 'Android allows cleartext traffic',
    severity: 'medium',
    files: MANIFEST,
    pattern: /android:usesCleartextTraffic\s*=\s*"true"/g,
    masvs: 'MASVS-NETWORK-1',
    guide: 'NETWORK.md#cleartext-traffic',
    message: 'Cleartext HTTP is allowed app-wide.',
    fix: 'Remove the attribute or use a network_security_config that allows cleartext only for debug/dev hosts.',
  },
  {
    id: 'FSA-IOS-001',
    title: 'iOS App Transport Security disabled',
    severity: 'medium',
    files: PLIST,
    pattern: /<key>NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>/g,
    masvs: 'MASVS-NETWORK-1',
    guide: 'NETWORK.md#cleartext-traffic',
    message: 'ATS is turned off globally, allowing insecure HTTP and weak TLS.',
    fix: 'Remove NSAllowsArbitraryLoads; add per-domain NSExceptionDomains only where unavoidable.',
  },

  // ---------------------------------------------------------------- android platform
  {
    id: 'FSA-AND-001',
    title: 'Android app marked debuggable',
    severity: 'high',
    files: MANIFEST,
    pattern: /android:debuggable\s*=\s*"true"/g,
    masvs: 'MASVS-RESILIENCE-4',
    guide: 'PLATFORM.md#android-manifest',
    message: 'A debuggable release lets anyone attach a debugger and run code as the app (run-as).',
    fix: 'Remove the attribute; Gradle sets it correctly per build type.',
  },
  {
    id: 'FSA-AND-002',
    title: 'Android backups enabled',
    severity: 'low',
    files: MANIFEST,
    pattern: /android:allowBackup\s*=\s*"true"/g,
    masvs: 'MASVS-STORAGE-2',
    guide: 'PLATFORM.md#android-manifest',
    message: 'App data (including SharedPreferences and databases) can be extracted with backup tools.',
    fix: 'Set android:allowBackup="false" or add dataExtractionRules that exclude sensitive files.',
  },
  {
    id: 'FSA-AND-003',
    title: 'Exported Android component (review)',
    severity: 'info',
    files: MANIFEST,
    pattern: /<(activity|activity-alias|service|receiver|provider)\b[^>]*android:exported\s*=\s*"true"[^>]*?(?:\/>|>[\s\S]*?<\/\1>)/g,
    // The launcher activity must be exported; it is not a lead.
    matchExclude: /android\.intent\.category\.LAUNCHER|android:name="\.MainActivity"/,
    masvs: 'MASVS-PLATFORM-1',
    guide: 'PLATFORM.md#exported-components',
    message: 'Other apps can start this component. Check what intent extras it trusts and whether it needs a permission.',
    fix: 'Set exported="false" if not needed, or protect it with android:permission and validate all extras.',
  },
  {
    id: 'FSA-BLD-001',
    title: 'Release build without code shrinking',
    severity: 'low',
    files: GRADLE,
    pattern: /(?:minifyEnabled\s+false|isMinifyEnabled\s*=\s*false)/g,
    masvs: 'MASVS-RESILIENCE-3',
    guide: 'BUILD.md#obfuscation-and-shrinking',
    message: 'Java/Kotlin plugin code ships unshrunk. Dart code also needs --obfuscate --split-debug-info.',
    fix: 'Enable minify + shrinkResources for release and build Flutter with --obfuscate --split-debug-info=build/symbols.',
  },

  // ---------------------------------------------------------------- webview
  {
    id: 'FSA-WEB-001',
    title: 'JavaScript bridge exposed to a WebView',
    severity: 'medium',
    files: DART,
    pattern: /\.addJavaScriptChannel\s*\(|addJavascriptInterface\s*\(|addJavaScriptHandler\s*\(/g,
    masvs: 'MASVS-PLATFORM-2',
    guide: 'WEBVIEW-DEEPLINKS.md#javascript-bridges',
    message: 'Any page loaded in this WebView can call the bridge. If navigation is not restricted, a malicious page can invoke native functionality.',
    fix: 'Restrict navigation to an allow-list (NavigationDelegate) and validate every message on the Dart side.',
  },
  {
    id: 'FSA-WEB-002',
    title: 'WebView loads a URL from a variable',
    severity: 'medium',
    files: DART,
    pattern: /(?:loadRequest\s*\(\s*Uri\.parse\s*\(|loadUrl\s*\(\s*(?:urlRequest:\s*URLRequest\s*\(\s*url:\s*WebUri\s*\()?|initialUrl\s*:\s*)(?!['"])[A-Za-z_$][\w.$!?]*/g,
    masvs: 'MASVS-PLATFORM-2',
    guide: 'WEBVIEW-DEEPLINKS.md#untrusted-urls',
    message: 'If the URL comes from a deep link, push payload or API response, an attacker can load their own page inside your app.',
    fix: 'Validate the scheme (https) and host against an allow-list before loading.',
  },
  {
    id: 'FSA-WEB-003',
    title: 'WebView allows file URLs to access other local files',
    severity: 'high',
    files: DART,
    pattern: /\ballowFileAccessFromFileURLs\s*(?::|=)\s*true\b/g,
    masvs: 'MASVS-PLATFORM-2',
    guide: 'WEBVIEW-DEEPLINKS.md#file-url-access',
    message: 'Enabling this can let file:// pages read other local files. If attacker-controlled content reaches the WebView, local data may be exposed; validate the platform, content source and reachable files.',
    fix: 'Set allowFileAccessFromFileURLs to false or omit it, avoid untrusted file:// content, and restrict navigation to trusted HTTPS origins.',
  },

  // ---------------------------------------------------------------- crypto
  {
    id: 'FSA-CRY-001',
    title: 'Weak hash (MD5/SHA-1)',
    severity: 'medium',
    files: DART,
    pattern: /\b(?:md5|sha1)\.convert\s*\(/g,
    masvs: 'MASVS-CRYPTO-1',
    guide: 'CRYPTO.md#weak-hashes',
    message: 'MD5/SHA-1 are broken for security use (passwords, signatures, integrity against attackers).',
    fix: 'Use SHA-256 for integrity; never hash passwords on the client as a substitute for TLS + server-side Argon2/bcrypt.',
  },
  {
    id: 'FSA-CRY-002',
    title: 'Non-cryptographic Random used',
    severity: 'low',
    files: DART,
    pattern: /\bRandom\s*\(\s*\d*\s*\)/g,
    exclude: /Random\.secure|fsa-ignore/,
    masvs: 'MASVS-CRYPTO-1',
    guide: 'CRYPTO.md#randomness',
    message: 'dart:math Random() is predictable. It must not generate tokens, nonces, OTPs, keys or IDs that need to be unguessable.',
    fix: 'Use Random.secure() for anything security-relevant.',
  },
  {
    id: 'FSA-CRY-003',
    title: 'Hardcoded encryption key or IV',
    severity: 'high',
    files: DART,
    pattern: /\b(?:Key|IV)\.(?:fromUtf8|fromBase64|fromBase16)\s*\(\s*['"]/g,
    masvs: 'MASVS-CRYPTO-2',
    guide: 'CRYPTO.md#hardcoded-keys',
    message: 'A key or IV baked into the binary protects nothing: whoever has the app has the key.',
    fix: 'Generate keys at runtime with Random.secure(), store them in flutter_secure_storage, and use a fresh IV per encryption.',
  },

  // ---------------------------------------------------------------- backend rules
  {
    id: 'FSA-BE-001',
    title: 'Firebase rules open to everyone',
    severity: 'critical',
    files: FIREBASE_RULES,
    pattern: /allow\s+(?:read|write|read\s*,\s*write|write\s*,\s*read|get|list|create|update|delete)\s*(?::\s*if\s+true\s*;|;)|"\.(?:read|write)"\s*:\s*(?:true|"true")/g,
    masvs: 'MASVS-AUTH-1',
    guide: 'BACKEND.md#firebase-security-rules',
    message: 'Anyone with the project ID (it is in the app) can read or write this data without logging in.',
    fix: 'Require request.auth != null at minimum and check ownership, e.g. request.auth.uid == resource.data.ownerId.',
  },
  {
    id: 'FSA-BE-002',
    title: 'Client-side authorization flag',
    severity: 'medium',
    files: DART,
    pattern: /\b(?:isAdmin|isPremium|isPro|isVip|hasSubscription|isPaid|isVerified)\s*=\s*true\b/g,
    masvs: 'MASVS-AUTH-2',
    guide: 'BACKEND.md#trust-the-server-not-the-client',
    message: 'If this flag gates paid features or admin actions only in the app, a patched build or a proxied response unlocks them.',
    fix: 'Enforce entitlements and roles on the server (RLS, Cloud Functions, backend checks); the client flag is only for UI.',
  },
];
