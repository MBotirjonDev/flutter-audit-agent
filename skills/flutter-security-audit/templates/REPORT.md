# Security audit — {{project}}

| | |
|---|---|
| Commit | `{{commit}}` |
| Date | {{date}} |
| Scope | {{apps / packages / backend folders audited}} |
| Method | flutter-security-audit skill: recon → triage scan → hunting → adversarial validation |

## Summary

| Critical | High | Medium | Low | Needs validation |
|---:|---:|---:|---:|---:|
| {{n}} | {{n}} | {{n}} | {{n}} | {{n}} |

{{3–5 sentences: what the app is, the most serious problem in plain words, what to fix first.}}

## Confirmed findings

### F-1 · {{title}} — **{{Severity}}**

**Where:** `{{file}}:{{line}}` · **MASVS:** {{control}}

**Attacker:** {{who, and what they control}}

**How it works**
1. {{step with file:line}}
2. {{step with file:line}}
3. {{impact}}

**Impact:** {{what is lost or gained, in business terms}}

**Fix**
```dart
// before → after, in the project's own style
```

---

## Needs validation

| ID | Title | What to check |
|---|---|---|
| F-n | {{title}} | {{exact unresolved fact and how to verify it}} |

## Hardening notes

- {{no direct impact, but worth doing}}

## Coverage

| Area | Status | Notes |
|---|---|---|
| Secrets | ✅ audited | |
| Data at rest | ✅ audited | |
| Network | ✅ audited | |
| Android / iOS platform | ✅ audited | |
| WebViews & deep links | ✅ audited | |
| Backend rules / API | ⚠️ partial | {{e.g. rules not in repo}} |
| Crypto | ✅ audited | |
| Build & release | ✅ audited | |

_Generated with [Flutter Audit Agent](https://github.com/MBotirjonDev/flutter-audit-agent). Automated audits miss things; repeat runs and a human review increase coverage._
