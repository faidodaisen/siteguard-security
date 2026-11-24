# Changelog

## 1.1.0
- Warning in wp-admin when the site is behind Cloudflare but IP detection is still REMOTE_ADDR: SiteGuard was recording the Cloudflare edge IP, so lockouts hit an IP shared by many real visitors and Login Logs / IP lists showed the wrong address. One click switches to CF-Connecting-IP. The same check covers a private proxy / load balancer sending X-Forwarded-For.
- The setting never changes on its own: activation and updates only show the suggestion. Sites already set correctly see no change, and proxy headers are still only trusted from Cloudflare or your trusted proxies.
- Dashboard: Your IP now shows the IP SiteGuard uses and how it was detected, plus the connecting address (REMOTE_ADDR) when it differs.

## 1.0.3
- Repository is now public: updates work without a GitHub token (token field kept as optional).

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
