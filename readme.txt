=== SiteGuard Security ===
Contributors: fidodesign
Tags: security, brute force, login, two factor, 2fa, captcha, turnstile
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Login protection: brute-force lockout, login logs, IP blacklist/whitelist, custom login errors, CAPTCHA and two-factor authentication. No account, no upsell, no external service except the CAPTCHA provider you choose.

== Features ==

* Brute-force lockout per IP: max retries, lockout minutes, extended lockout after N lockouts, auto reset. Counters are atomic (safe with many PHP workers). Application-password failures over REST / XML-RPC are counted too.
* Admin email on lockout (optional, threshold).
* Login log (success, failed, lockout, blocked, CAPTCHA fail, 2FA fail, backup code used, email failure) with filter, search, CSV export, daily pruning in batches.
* IP whitelist / blacklist: single IP, range (a - b), CIDR, IPv6. Whitelist wins.
* IP detection: REMOTE_ADDR (default), Cloudflare (header trusted only from Cloudflare ranges), X-Forwarded-For / X-Real-IP (trusted only from your proxies).
* Custom messages: generic "username or password incorrect", attempts left, locked out, blacklisted.
* CAPTCHA: Google reCAPTCHA v2 / v3 or Cloudflare Turnstile on wp-login (login, register, lost password), WooCommerce (login, register, lost password, checkout login) and comments. Programmatic calls by other plugins are never blocked.
* Two-factor: authenticator app (TOTP, QR set-up), email code, 10 one-time backup codes, required per role (super admins included on multisite), in-login enrollment when only the app is allowed, admin reset for lost phones.
* 2FA covers wp-login, WooCommerce, AJAX login forms (with a link to finish), the interim "session expired" login, and SSO / social / magic-link plugins (safety net on wp_login; exempt a trusted one with the `siteguard_2fa_required` filter).
* XML-RPC password logins are refused for 2FA users; application passwords keep working.
* Multisite: per-site settings, tables and cron; network activation and new sites handled.
* Updates from GitHub Releases in wp-admin (private repository token supported).

== Emergency access ==

Add `define( 'SITEGUARD_DISABLE', true );` to wp-config.php, or rename the plugin folder over FTP/SFTP. All login checks stop; settings stay.

== Updates ==

The plugin checks https://github.com/faidodaisen/siteguard-security releases every 6 hours. The repository is private, so add a fine-grained GitHub token with "Contents: Read-only" on that repository under SiteGuard → Updates, or define `SITEGUARD_GITHUB_TOKEN` in wp-config.php.

== Changelog ==

= 1.0.0 =
* First release.
