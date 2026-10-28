# SiteGuard Security

WordPress login protection by Fido Design. Free, no account, no upsell.

- Brute-force lockout per IP, login logs, IP whitelist / blacklist
- CAPTCHA: Google reCAPTCHA v2 / v3, Cloudflare Turnstile (wp-login, WooCommerce, comments)
- Two-factor: authenticator app (TOTP), email code, backup codes, required per role
- Updates itself from this repository's GitHub Releases

Requires WordPress 6.0+ and PHP 7.4+.

## Install on a client site

1. Download `siteguard-security.zip` from the latest [release](../../releases/latest).
2. WP Admin → Plugins → Add New → Upload Plugin.
3. Because this repository is private, give the site a read-only token so it can see updates:
   - GitHub → Settings → Developer settings → Fine-grained tokens → Generate.
   - Repository access: **Only select repositories → siteguard-security**.
   - Permissions: **Contents: Read-only** (nothing else).
   - Paste it in **SiteGuard → Updates**, or add to `wp-config.php`:
     ```php
     define( 'SITEGUARD_GITHUB_TOKEN', 'github_pat_...' );
     ```
4. New releases then show up in **Dashboard → Updates** and **Plugins** like any other plugin (checked every 6 hours, or press **SiteGuard → Updates → Check now**).

## Release a new version

1. Bump the version in **three** places (the release workflow refuses mismatches):
   - `siteguard-security.php` header `Version:`
   - `define( 'SITEGUARD_VERSION', ... )` in the same file
   - `readme.txt` → `Stable tag:`
2. Add a `## x.y.z` section to `CHANGELOG.md` (it becomes the release notes).
3. Commit, then tag and push:
   ```bash
   git tag v1.0.1
   git push origin main --tags
   ```
4. GitHub Actions lints on PHP 7.4–8.4, builds `siteguard-security.zip` and publishes the release. Sites see it within 6 hours.

Only published, non-draft, non-prerelease releases with a version higher than the installed one are offered.

## Emergency off switch

`define( 'SITEGUARD_DISABLE', true );` in `wp-config.php` (or rename the plugin folder) turns every login check off. Settings are kept.
