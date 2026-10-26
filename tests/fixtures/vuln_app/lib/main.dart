// INTENTIONALLY VULNERABLE fixture for flutter-security-audit tests.
// Do not copy this code into a real app.
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:hive/hive.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:webview_flutter/webview_flutter.dart';

const baseUrl = 'http://api.example-shop.uz/v1';
const clientSecret = 'demo-not-real-0123456789abcdef';
// Supabase admin client initialised with the service_role key (fixture).
const supabaseAdminRole = 'service_role';

class AuthService {
  bool isPremium = false;

  Future<void> saveSession(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('access_token', token);
    print('login ok, token=$token');
  }

  void unlock() {
    isPremium = true;
  }

  String hashPassword(String password) => md5.convert(password.codeUnits).toString();

  String otp() => (Random().nextInt(900000) + 100000).toString();
}

class LocalCache {
  Future<Box> open() => Hive.openBox('user_cache');

  final key = Key.fromUtf8('my32lengthsupersecretnooneknows1');
  final iv = IV.fromUtf8('1234567890123456');
}

HttpClient insecureClient() {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;
  return client;
}

void openPromo(WebViewController controller, String deepLinkUrl) {
  controller.addJavaScriptChannel('Native', onMessageReceived: (m) {});
  controller.loadRequest(Uri.parse(deepLinkUrl));
}
