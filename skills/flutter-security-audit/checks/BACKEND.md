# Backend: Firebase, Supabase and REST APIs

Most **critical** findings in Flutter projects are here, not in Dart. An attacker does
not need your app: they take the project ID / anon key / API base URL from the binary and
call the backend directly with `curl`.

## Checklist

- [ ] Firestore / Realtime DB / Storage rules in the repo (`firestore.rules`, `storage.rules`, `database.rules.json`)
- [ ] Supabase: every table in `public` has RLS enabled **and** sensible policies (`supabase/migrations/*.sql`)
- [ ] Supabase Edge Functions / Cloud Functions: auth checked? input validated? CORS?
- [ ] REST endpoints the app calls: does `/users/{id}`, `/orders/{id}` check ownership server-side (IDOR)?
- [ ] who can set `role`, `isAdmin`, `balance`, `isPremium`, `status` fields?
- [ ] OTP / SMS login: rate limits, OTP length and expiry, OTP not returned in the API response
- [ ] in-app purchases and payments verified on the server (receipt validation, webhook signature)
- [ ] App Check / Play Integrity enabled for Firebase and sensitive endpoints

### Firebase security rules

```js
// ❌ anyone can read and write everything
allow read, write: if true;
// ❌ "test mode" left on (expired date still deploys broken or open rules)
allow read, write: if request.time < timestamp.date(2026, 1, 1);
// ❌ any logged-in user can read every user's data
allow read, write: if request.auth != null;
// ✅ ownership
match /users/{uid} {
  allow read, write: if request.auth != null && request.auth.uid == uid;
}
match /orders/{orderId} {
  allow read: if request.auth.uid == resource.data.userId;
  allow create: if request.auth.uid == request.resource.data.userId
                && !('status' in request.resource.data);
}
```

Also check that users cannot write privileged fields on their own document
(`role`, `balance`, `isPremium`) — use `request.resource.data.diff(resource.data)
.affectedKeys().hasOnly([...])`.

If the rules file is **not** in the repo, record `needs_validation`: "Firestore rules not
available; verify in Firebase console that collections X, Y require auth + ownership."

#### Supabase RLS

```sql
-- ❌ table without RLS is fully readable/writable with the anon key
create table public.profiles (...);
-- ✅
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles
  for all using (auth.uid() = id) with check (auth.uid() = id);
```

Watch for `using (true)` policies, `security definer` functions exposed via RPC without
checks, and views that bypass RLS (`security_invoker` not set).

### Trust the server, not the client

Classic Flutter bugs:

- `isPremium = true` after a purchase callback, never verified by the server → patch the
  APK or replay the API response with a proxy to unlock everything.
- Admin panel hidden in the UI (`if (user.role == 'admin')`) but the API does not check
  the role.
- Price/total calculated in the app and sent to the server, which charges that amount.
- "Payment success" sent by the app instead of the payment provider's server callback
  (common with Payme / Click / Uzum integrations — the merchant callback must be signed
  and verified).
- OTP compared in the app (`if (inputCode == response.code)`).

Report the **server-side** gap as the vulnerability. A UI flag is only the symptom.
