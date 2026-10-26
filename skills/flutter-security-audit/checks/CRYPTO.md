# Crypto

Most apps should not implement crypto at all: TLS protects transport, Keystore/Keychain
(via `flutter_secure_storage`) protects keys at rest, and the server hashes passwords.
Custom crypto in Dart is a strong signal to look closely.

## Checklist

- [ ] where do keys come from? (hardcoded, derived from a constant, fetched, generated?)
- [ ] mode and IV: AES-ECB? static IV? IV reused across messages?
- [ ] integrity: AES-CBC/CTR without a MAC → use AES-GCM (`cryptography` package)
- [ ] password handling: is the client hashing passwords and sending the hash as "the password"?
- [ ] randomness for tokens, nonces, OTPs, file names, invite codes
- [ ] JWTs: is the app *verifying* tokens with a secret it holds? (then the secret is public)

### Weak hashes

MD5 and SHA-1 must not be used for passwords, signatures or integrity against an
attacker. Client-side password hashing with any fast hash does not protect anything —
the hash becomes the password. Use TLS and let the server hash with Argon2id / bcrypt /
scrypt.

MD5 for cache keys or file deduplication is fine — reject such leads.

### Randomness

```dart
// ❌ predictable
final code = Random().nextInt(999999);
// ✅
final rng = Random.secure();
final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
```

Only report when the value must be unguessable (auth, invites, password reset, file
names of private uploads). Shuffling, animations and UI jitter are fine.

### Hardcoded keys

```dart
// ❌ key and IV in the binary — "encryption" anyone can undo
final key = Key.fromUtf8('my32lengthsupersecretnooneknows1');
final iv = IV.fromUtf8('1234567890123456');
// ✅ random key kept in Keystore/Keychain, fresh IV per message, authenticated mode
final algorithm = AesGcm.with256bits();
final secretKey = await algorithm.newSecretKey();          // store via flutter_secure_storage
final box = await algorithm.encrypt(plain, secretKey: secretKey); // random nonce inside
```

Severity depends on what the hardcoded key protects: offline paid content or "encrypted"
tokens → high; obfuscating a non-sensitive config → low/hardening.
