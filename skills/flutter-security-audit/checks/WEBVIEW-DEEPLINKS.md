# WebViews and deep links

These two together cause the most serious Flutter client-side bugs: an attacker sends a
link (Telegram, SMS, QR code, website), the app opens, and attacker content runs inside a
trusted WebView that can talk to native code.

## Checklist

- [ ] list every deep link / app link route (`go_router`, `auto_route`, `app_links`, `uni_links`, `firebase_dynamic_links`) and its parameters
- [ ] Android App Links have `android:autoVerify="true"` and a valid `assetlinks.json`; iOS uses Universal Links with `apple-app-site-association` — custom schemes (`myapp://`) can be claimed by other apps
- [ ] which routes take a URL, file path, amount, user id or token as a parameter?
- [ ] every WebView: where does its URL come from? Is navigation restricted?
- [ ] JavaScript channels / handlers: what can they do (open files, get tokens, start payments, navigate)?
- [ ] OAuth / payment callbacks via deep link: is `state` checked, is the result verified server-side?

### JavaScript bridges

`webview_flutter` → `addJavaScriptChannel`; `flutter_inappwebview` →
`addJavaScriptHandler`; native → `addJavascriptInterface`.

Every page that ends up in the WebView can call the bridge — including pages reached by
redirects or links clicked inside your own page. A bridge is dangerous when it:

- returns the user's auth token to JS,
- triggers payments, purchases or account changes,
- reads/writes files or opens arbitrary URLs/intents.

```dart
// ✅ restrict where the WebView may go, and check the origin before trusting messages
controller
  ..setNavigationDelegate(NavigationDelegate(
    onNavigationRequest: (req) {
      final uri = Uri.parse(req.url);
      return (uri.scheme == 'https' && _allowedHosts.contains(uri.host))
          ? NavigationDecision.navigate
          : NavigationDecision.prevent;
    },
  ))
  ..addJavaScriptChannel('Native', onMessageReceived: (msg) async {
    final current = Uri.tryParse(await controller.currentUrl() ?? '');
    if (current == null || !_allowedHosts.contains(current.host)) return;
    _handle(msg.message); // parse strictly, never eval/execute
  });
```

### Untrusted URLs

Report as **high** when this chain exists in a release build:

1. attacker controls a URL (deep link query param, push notification data, API field
   editable by users, QR code), **and**
2. the app loads it into a WebView without an https + host allow-list, **and**
3. the WebView has a JS bridge, injected auth cookies/headers, or `file://` access
   (`allowFileAccess`, `allowUniversalAccessFromFileURLs`).

Without step 3 it is usually an open redirect / phishing-in-app issue (medium).

### File-URL access

In `flutter_inappwebview`, `allowFileAccessFromFileURLs: true` can let a page loaded
from `file://` read other local files. If attacker-controlled HTML, injected content or
navigation can reach that page, this may become a local-file disclosure path. Treat a
scanner hit as a lead: check the affected platform, content source, release settings and
which files are actually reachable before confirming impact.

```dart
// ❌ A file-origin page may be able to read other local files.
final riskySettings = InAppWebViewSettings(
  allowFileAccessFromFileURLs: true,
);

// ✅ Keep file-origin access disabled.
final saferSettings = InAppWebViewSettings(
  allowFileAccessFromFileURLs: false,
);
```

Prefer omitting the setting when file access is not needed, and restrict WebView
navigation to trusted HTTPS origins. Do not load untrusted HTML from `file://`.

Also check `url_launcher` with attacker-controlled `intent://` or `file://` URLs, and
`Navigator`/`go_router` redirects that take a `next=` parameter.
