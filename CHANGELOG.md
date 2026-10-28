# Changelog

## 1.0.2
- Dashboard → Updates → **Check again** now also refreshes the GitHub release check.

## 1.0.1
- Test release for the GitHub updater (no functional change).

## 1.0.0
- First release.
- Brute-force lockout per IP with extended lockouts, admin email alerts, atomic counters (safe under concurrent requests).
- Login log with filters, search, CSV export and daily pruning.
- IP whitelist / blacklist (single, range, CIDR, IPv6). Proxy headers only trusted from Cloudflare or configured proxies.
- Custom login messages, generic "username or password incorrect" option.
- CAPTCHA: reCAPTCHA v2 / v3, Cloudflare Turnstile on wp-login, WooCommerce and comments.
- Two-factor: authenticator app, email code, backup codes, required per role (with in-login enrollment), SSO safety net, XML-RPC blocking with application-password support.
- Updates from GitHub Releases inside wp-admin.
