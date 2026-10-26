# Contributing

Thanks for helping Flutter apps ship safer. Every contribution counts: a new rule, a
false-positive fix, a better checklist item, a translation.

## Add a scanner rule (≈15 minutes)

1. **Open an issue first** using the *New rule* template, so nobody duplicates work.
2. Add the rule to `skills/flutter-security-audit/scripts/rules.cjs`:
   - next free id in the area: `FSA-<AREA>-<NNN>` (`SEC STO NET AND IOS WEB CRY BE BLD LOG`)
   - `files`, `pattern` (with the `g` flag), `severity`, `masvs`, `guide`, `message`, `fix`
   - keep false positives low: use `exclude` / `matchExclude`
3. Add a **positive case** to `tests/fixtures/vuln_app/` (and if it looks like a real
   secret, generate it in `tests/scan.test.cjs` instead — GitHub push protection will
   otherwise block the push).
4. Make sure `tests/fixtures/clean_app/` stays clean. Add a tricky **negative** case
   there if your rule could misfire.
5. Add or extend the matching section in `skills/flutter-security-audit/checks/*.md`
   (the `guide` anchor must exist — the tests check it).
6. Update the rules table in `README.md`.
7. `npm test` — all green, no new dependencies.

## Improve a checklist

The `checks/*.md` files are what the agent actually reads during an audit. Good changes:

- a real-world Flutter bug pattern with a minimal *bad → good* code example
- "how to validate" hints that help the agent reject false positives
- package-specific notes (`dio`, `go_router`, `flutter_inappwebview`, `supabase_flutter`…)

Keep examples short and never include real keys, real company names or real victims.

## Report a false positive

Use the *False positive* issue template with the smallest code snippet that triggers it.

## Ground rules

- Zero runtime dependencies. Node ≥ 18 standard library only.
- Rules produce **leads**; wording should say "review"/"may", not "you are hacked".
- Be kind in reviews. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Found a vulnerability *in this project*? See [SECURITY.md](SECURITY.md).
