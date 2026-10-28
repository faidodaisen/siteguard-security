<?php
/**
 * Plugin Name:       SiteGuard Security
 * Plugin URI:        https://github.com/faidodaisen/siteguard-security
 * Description:       Login protection: brute-force lockout, login logs, IP blacklist/whitelist, custom login errors, CAPTCHA (reCAPTCHA v2/v3, Cloudflare Turnstile) and two-factor authentication (authenticator app + email code).
 * Version:           1.0.3
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Fido Design
 * Author URI:        https://fidodesign.net
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       siteguard-security
 * Domain Path:       /languages
 * Update URI:        https://github.com/faidodaisen/siteguard-security
 *
 * Emergency off switch: add  define( 'SITEGUARD_DISABLE', true );  to wp-config.php
 * (or rename this plugin folder) to bypass every login check.
 */

defined( 'ABSPATH' ) || exit;

if ( defined( 'SITEGUARD_VERSION' ) ) {
	return; // Another copy of this plugin is already loaded.
}

define( 'SITEGUARD_VERSION', '1.0.3' );
define( 'SITEGUARD_FILE', __FILE__ );
define( 'SITEGUARD_DIR', plugin_dir_path( __FILE__ ) );
define( 'SITEGUARD_URL', plugin_dir_url( __FILE__ ) );
define( 'SITEGUARD_DB_VERSION', '2' );

require_once SITEGUARD_DIR . 'includes/class-siteguard-options.php';
require_once SITEGUARD_DIR . 'includes/class-siteguard-ip.php';
require_once SITEGUARD_DIR . 'includes/class-siteguard-install.php';
require_once SITEGUARD_DIR . 'includes/class-siteguard-bruteforce.php';
require_once SITEGUARD_DIR . 'includes/class-siteguard-captcha.php';
require_once SITEGUARD_DIR . 'includes/class-siteguard-totp.php';
require_once SITEGUARD_DIR . 'includes/class-siteguard-twofactor.php';
require_once SITEGUARD_DIR . 'includes/class-siteguard-updater.php';

register_activation_hook( __FILE__, array( 'SiteGuard_Install', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'SiteGuard_Install', 'deactivate' ) );

add_action( 'plugins_loaded', 'siteguard_security_boot' );

add_action( 'init', 'siteguard_security_textdomain', 1 );

function siteguard_security_textdomain() {
	load_plugin_textdomain( 'siteguard-security', false, dirname( plugin_basename( SITEGUARD_FILE ) ) . '/languages' );
}

function siteguard_security_boot() {
	SiteGuard_Options::init();
	SiteGuard_Install::init();
	SiteGuard_Updater::init();

	if ( is_admin() ) {
		require_once SITEGUARD_DIR . 'admin/class-siteguard-admin.php';
		SiteGuard_Admin::init();
	}

	if ( defined( 'SITEGUARD_DISABLE' ) && SITEGUARD_DISABLE ) {
		return;
	}
	if ( ! SiteGuard_Install::tables_ok() ) {
		return; // Fail open rather than fatal; the admin dashboard shows the problem.
	}

	SiteGuard_BruteForce::init();
	SiteGuard_Captcha::init();
	SiteGuard_TwoFactor::init();
}
