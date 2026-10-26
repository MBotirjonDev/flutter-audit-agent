# Secrets in the app

**Rule of thumb:** everything inside an APK, AAB, IPA or Flutter web bundle is public.
`--obfuscate` renames symbols; it does not hide string literals. Tools such as `strings`,
`blutter` and `reFlutter` recover Dart constants and assets from release builds.

So the question is never "is the key hidden?" but **"what can someone do with it?"**

## Checklist

- [ ] grep Dart, assets, `.env*`, `*.json`, native code and `build.gradle` for keys, tokens, passwords
- [ ] for every key found: what API does it unlock, and is it restricted?
- [ ] `pubspec.yaml` `assets:` — does it ship `.env`, `config.json`, certificates?
- [ ] `envied` / `--dart-define` values: still end up in the binary (obfuscation is not encryption)
- [ ] git history: `git log -p -S 'sk_live' --all` style searches for rotated-but-committed keys

### Google and Firebase keys

`AIza…` keys in `google-services.json`, `GoogleService-Info.plist` and
`firebase_options.dart` are **Firebase client identifiers** — public by design. They are
not a finding by themselves. Security comes from Security Rules and App Check (see
`BACKEND.md`).

It **is** a finding when the same or another `AIza…` key is unrestricted and enabled for
paid APIs (Maps, Places, Directions, Gemini/Generative Language, Translate). Impact:
billing abuse and quota exhaustion.

Validate: which file is it in, which APIs does the code call with it? If it is used for
Maps, recommend Android package + SHA-1 and iOS bundle-ID restrictions. For Gemini or any
LLM key: move the call behind your backend — app restrictions do not stop extraction.

### Backend admin keys

- **Supabase `service_role`** — bypasses all Row Level Security. Critical if present.
  The app must use the anon / publishable key only.
- Firebase Admin SDK JSON (`"type": "service_account"`, `private_key`) — critical.
- AWS `AKIA…` with secret, database URLs with passwords, Algolia **admin** keys, Twilio
  auth tokens, SMTP passwords — high to critical depending on permissions.

```dart
// ❌ never
final supabase = SupabaseClient(url, serviceRoleKey);
// ✅
await Supabase.initialize(url: url, anonKey: anonKey); // + RLS on every table
```

### Hardcoded credentials

Usernames/passwords for test accounts, basic-auth headers, `client_secret` for OAuth,
API gateway keys. Ask: does this credential give access beyond what any logged-in user
already has? If yes, it is a finding. OAuth `client_secret` in a mobile app is always a
problem — use PKCE with a public client.

### Private keys

PEM blocks, `.p12`, `.jks`/`.keystore` files with passwords in `key.properties`, signing
keys. A committed upload keystore + password lets someone sign updates as you (for
non-Play-App-Signing setups). Treat as compromised: rotate and purge history.

### Payment keys

Stripe `sk_live_` / `rk_live_`, Payme / Click / Uzum **merchant secret keys**, PayPal
client secret. Only publishable or public identifiers belong in the app. Payment
confirmation must be verified by your server (webhook / callback signature check), never
by the app telling the server "payment succeeded".

### Telegram bot tokens

`123456789:AA…` — full control of the bot. Common in Uzbek/CIS apps that send order
notifications straight from the app. Fix: revoke via @BotFather and send notifications
from the backend.

### .env files are not secret

`flutter_dotenv` loads `.env` as a Flutter **asset** — it is a plain file inside the
APK (`assets/flutter_assets/.env`). Fine for base URLs and feature flags, never for
secrets. Same for `envied` without obfuscation, and for `--dart-define` values.
