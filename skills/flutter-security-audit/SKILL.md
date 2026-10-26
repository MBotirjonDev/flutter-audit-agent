---
name: flutter-security-audit
description: Security audit for Flutter and Dart apps (Android, iOS, web) and their Firebase/Supabase/REST backends. Use when asked to security-audit, pen-test, threat-model or review a Flutter/Dart codebase, find vulnerabilities in a Flutter app, check an app before release, or answer a security question about Flutter storage, networking, deep links, WebViews, secrets, crypto, auth or backend rules.
---

# Flutter Security Audit

You are auditing a Flutter app the way an attacker would look at it: someone who has the
APK/IPA, can run it on a rooted phone, can proxy its traffic, and can call its backend
directly. Your job is to find **real, reachable** security failures and explain them so a
Flutter developer can fix them today.

## Core principles

1. **The client is not a security boundary.** Anything in the binary (strings, assets,
   `.env`, Dart constants, obfuscated or not) is public. Anything the client "checks" can be
   skipped. A vulnerability exists when the **server, the OS sandbox or the crypto** fails to
   enforce something, or when the app hands an attacker a capability.
2. **Leads are not findings.** The scanner and your first read produce leads. A lead becomes
   `confirmed` only with a trace from attacker-controlled input to a concrete impact.
3. **The finder never confirms its own finding.** Validation is done in a fresh context
   (a sub-agent if your platform supports them, otherwise a deliberate second pass that
   re-reads the source from scratch and tries to disprove the claim).
4. **Severity needs impact.** Severity = what an attacker gains × how easily. "Missing best
   practice" with no reachable impact is a hardening note, not a vulnerability.
5. **Be honest about what you could not see.** If the backend, a private package or the
   native code is unavailable, record `needs_validation` with the exact missing fact.
   Never guess a severity for it.

## Modes

- **Full audit** — the user asks to audit / pen-test / review the project, or asks for a
  report. Run all phases and write artifacts.
- **Guidance** — the user asks a focused question ("is it OK to keep the JWT in
  SharedPreferences?", "check my Firestore rules"). Answer directly using the relevant
  `checks/*.md` file; read the code they point to; skip artifacts unless asked.

## Output location (full audit)

Write artifacts to the directory the user names. If none is named, use
`~/flutter-security-audit/<project-name>/run-<N>/` (next unused N). Never write into the
audited repository unless the user picks a git-ignored folder there.

Artifacts: `architecture.md`, `leads.json`, `findings.json`, `REPORT.md`.

## Phase 0 — Setup

- Locate the Flutter project root(s): every `pubspec.yaml` with a `flutter:` section.
  Monorepos (melos) can have several apps and packages; audit apps first, then the
  packages they depend on.
- Check that Node.js is available (`node --version`). If not, skip the scanner and do
  Phase 2 manually; say so in the report.
- Do **not** run `flutter build`, `flutter run`, tests or any project scripts unless the
  user asked and you are in an isolated sandbox without network access. Build scripts and
  `build_runner` generators are attacker-controllable code in an untrusted repo.

## Phase 1 — Reconnaissance → `architecture.md`

Map the app before hunting. Read, in this order:

1. `pubspec.yaml` / `pubspec.lock` — packages tell you the attack surface:
   `shared_preferences`, `hive`, `sqflite`, `isar`, `flutter_secure_storage`, `dio`, `http`,
   `webview_flutter`, `flutter_inappwebview`, `app_links`/`uni_links`, `go_router`,
   `firebase_*`, `supabase_flutter`, `local_auth`, `in_app_purchase`, `encrypt`, `crypto`,
   payment SDKs (Payme, Click, Uzum, Stripe), `flutter_dotenv`, `envied`.
2. Entry points: `lib/main*.dart`, flavors, `firebase_options.dart`, DI setup.
3. Platform config: `android/app/src/main/AndroidManifest.xml`, `android/app/build.gradle*`,
   `network_security_config.xml`, `ios/Runner/Info.plist`, `*.entitlements`,
   `web/index.html`, `web/manifest.json`.
4. Backend config in the repo: `firestore.rules`, `storage.rules`, `database.rules.json`,
   `supabase/migrations/*.sql` (RLS!), `supabase/functions/**`, Cloud Functions, any
   server folder.
5. Native code: `MainActivity.kt`, `AppDelegate.swift`, platform channels
   (`MethodChannel` names on both sides).

Write `architecture.md` with:

- **Assets** worth stealing or abusing (tokens, PII, payments, paid content, admin actions).
- **Trust boundaries** (device ↔ backend, app ↔ other apps via intents/deep links,
  app ↔ WebView content, Dart ↔ native via channels).
- **Entry points** an attacker controls: deep links / app links, push payloads, intent
  extras, WebView pages, API responses, files the user opens, QR codes, clipboard.
- **Where auth and authorization are enforced** (server? rules? only the UI?).
- **Coverage plan**: list each area from the table below that applies, so nothing is
  silently skipped.

## Phase 2 — Triage scan → `leads.json`

Run the bundled zero-dependency scanner from this skill's directory:

```bash
node <skill-dir>/scripts/scan.cjs <project-root> --out <output-dir>/leads.json
```

It reports pattern-based leads with a rule id (`FSA-XXX-000`), the MASVS control and the
`checks/` section to read. Treat every lead as a question, not an answer. Expect false
positives (a `Random()` that shuffles a quiz, a Firebase client key) and **expect the
scanner to miss most logic bugs** — it cannot see authorization flaws, broken RLS
policies, IDOR, or trust in client flags.

## Phase 3 — Hunting

Work area by area from your coverage plan. For each area, read the matching guide and
follow its checklist against the real code:

| Area | Guide | Typical high-impact bugs |
|---|---|---|
| Secrets in the app | `checks/SECRETS.md` | service_role / admin keys, bot tokens, payment secrets, `.env` assets |
| Data at rest | `checks/STORAGE.md` | tokens in SharedPreferences, unencrypted DBs with PII, secrets in logs |
| Network | `checks/NETWORK.md` | disabled TLS validation, cleartext, tokens in URLs |
| Android / iOS platform | `checks/PLATFORM.md` | debuggable builds, exported components, backups, screenshots of secrets |
| WebViews & deep links | `checks/WEBVIEW-DEEPLINKS.md` | URL from deep link → WebView with JS bridge, open redirect, link hijacking |
| Backend (Firebase, Supabase, REST) | `checks/BACKEND.md` | open rules, missing RLS, IDOR, client-side entitlements, OTP flaws |
| Crypto | `checks/CRYPTO.md` | hardcoded keys/IVs, ECB, MD5 passwords, predictable tokens |
| Build & release | `checks/BUILD.md` | no obfuscation, debug flags in release, leaking source maps on web |

If your platform supports parallel sub-agents, give each area to its own hunter with only
`architecture.md`, the guide and the relevant files. Each hunter returns candidates in the
shape: *source → path → sink → impact*, with file:line for every step.

## Phase 4 — Validation (adversarial)

For each unique candidate, a **fresh** verifier (not the hunter) tries to disprove it:

- Is the input really attacker-controlled? (A hardcoded URL in a WebView is not.)
- Is there a check the hunter missed — router guard, server validation, RLS policy,
  `kDebugMode` guard, `network_security_config`, App Check?
- Is the code reachable in a **release** build?
- Does the impact actually follow? (A leaked Firebase *client* key with good rules is not
  a vulnerability.)

Outcome per candidate:

- `confirmed` — complete trace, realistic attacker, bounded impact.
- `needs_validation` — plausible, but one exact fact is unknown (name it).
- `rejected` — disproved; record why so future runs don't re-raise it.

## Phase 5 — Structured output → `findings.json`

Use the shape in `templates/findings.example.json`. Then validate:

```bash
node <skill-dir>/scripts/validate-findings.cjs <output-dir>/findings.json
```

Fix every error before moving on. Rules enforced: confirmed findings need `severity`,
`attacker`, a `trace` of ≥2 steps, `impact`, `fix`, `verified_by`; `needs_validation` has
no severity and names `unresolved`; `rejected` has `rejection_reason`.

## Phase 6 — Report → `REPORT.md`

Derive the report **only** from validated `findings.json`. Use `templates/REPORT.md`:

1. Summary table (counts by severity) and a 3–5 sentence executive summary.
2. Confirmed findings, highest severity first: what, where (file:line), attacker,
   step-by-step trace, impact, **a concrete Dart/Kotlin/rules fix**.
3. Needs validation: what to check and how.
4. Hardening notes (no direct impact, worth doing).
5. Coverage: which areas were audited, which were not and why.

Write the fix in the project's own style (Riverpod/Bloc/GetX, Dio vs http, etc.). Prefer
a short code diff over prose.

## Severity guide

| Severity | Flutter examples |
|---|---|
| Critical | Supabase `service_role` key in app; Firestore `allow read, write: if true` on user data; TLS validation disabled in release; live payment secret key |
| High | Bearer/refresh token readable from SharedPreferences + backups on; deep link → WebView with JS bridge to native file/payment calls; premium unlocked by client flag with no server check; IDOR on `/orders/{id}` |
| Medium | Cleartext HTTP to the API; unrestricted Google Maps key (billing abuse); tokens in logs in release; exported activity trusting extras |
| Low | Unencrypted cache of non-sensitive data; minify disabled; `Random()` for non-critical IDs |
| Info | Hardening: missing App Check, missing FLAG_SECURE on sensitive screens, no root/jailbreak signal |

## Anti-patterns (do not do these)

- Reporting every scanner lead as a vulnerability.
- Calling obfuscation, root detection or SSL pinning "fixes" for a server-side
  authorization bug.
- Rating a Firebase client config key as a leaked secret.
- "Recommend using HTTPS" when the app already uses HTTPS everywhere.
- Inventing backend behaviour you cannot see. Use `needs_validation`.
- Pasting full secrets into the report. Show the first 6 characters only.
- Running the target's build scripts, tests or code generators outside a sandbox.

## Re-runs

If a previous run directory exists, read its `findings.json` first: re-check
`needs_validation` items, verify that confirmed findings are fixed in the current code,
and focus hunting on areas listed as not covered.
