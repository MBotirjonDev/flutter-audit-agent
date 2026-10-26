import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const baseUrl = 'https://api.example-shop.uz/v1';
const devUrl = 'http://10.0.2.2:8080';

class AuthService {
  final _storage = const FlutterSecureStorage();

  Future<void> saveSession(String token) async {
    await _storage.write(key: 'access_token', value: token);
    if (kDebugMode) debugPrint('login ok');
  }

  String nonce() => Random.secure().nextInt(1 << 32).toString();

  // Label text, not a secret: should not trigger FSA-SEC-003.
  static const passwordHint = 'Enter your password here please';

  // Shuffling a quiz is not security-relevant.
  List<int> shuffle(List<int> xs) => xs..shuffle(Random(42)); // fsa-ignore: FSA-CRY-002 quiz order only
}
