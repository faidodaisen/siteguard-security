<?php
defined( 'ABSPATH' ) || exit;

/**
 * Two-factor authentication: authenticator app (TOTP), email code, one-time backup codes.
 *
 * Login flow: valid password -> NO auth cookie is issued. A challenge (hashed token, own row in
 * usermeta) is created, its token goes into the httponly cookie `siteguard_2fa`, and the browser
 * is sent to wp-login.php?action=siteguard_2fa. Only a correct code issues wp_set_auth_cookie().
 *
 * Safety net: logins that skip the `authenticate` filter (SSO / social / magic-link plugins that
 * call wp_set_auth_cookie() then fire `wp_login`) are caught on `wp_login`: the fresh session is
 * destroyed and the user is sent to the same code screen. Filter `siteguard_2fa_required` (bool,
 * WP_User, string context) lets a site exempt a trusted integration.
 *
 * Enrollment is per user and therefore network-wide on multisite.
 */
class SiteGuard_TwoFactor {

	const COOKIE        = 'siteguard_2fa';
	const TOKEN_TTL     = 600;
	const MAX_ATTEMPTS  = 5;   // Wrong codes per challenge.
	const MAX_CHALLENGE = 5;   // Open challenges per user (devices/tabs).
	const USER_FAILS    = 10;  // Wrong codes per user per window before a cool-down.
	const USER_WINDOW   = 900;
	const BACKUP_COUNT  = 10;

	const M_METHOD     = '_sg_tfa_method';
	const M_SECRET     = '_sg_totp_secret';
	const M_PENDING    = '_sg_totp_pending';
	const M_LAST_STEP  = '_sg_totp_last_step';
	const M_BACKUP     = '_sg_backup_code';  // One row per code (hash).
	const M_FAILS      = '_sg_2fa_fails';
	const M_CHAL       = '_sg_chal_';        // Prefix; one row per challenge.

	private static $profile_error = '';
	private static $completing    = false;
	private static $app_password  = false;
	private static $last_token    = '';

	public static function init() {
		// Profile UI is available even when the login step is off, so users can prepare.
		add_action( 'show_user_profile', array( __CLASS__, 'profile_section' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'profile_section' ) );
		add_action( 'personal_options_update', array( __CLASS__, 'profile_save' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'profile_save' ) );
		add_action( 'user_profile_update_errors', array( __CLASS__, 'profile_errors' ), 10, 3 );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'profile_assets' ) );
		add_action( 'admin_notices', array( __CLASS__, 'backup_codes_notice' ) );
		add_action( 'admin_notices', array( __CLASS__, 'enroll_nag' ) );

		if ( ! SiteGuard_Options::get( 'tfa_enabled' ) ) {
			return;
		}
		add_filter( 'authenticate', array( __CLASS__, 'intercept' ), 100000, 3 );
		add_action( 'application_password_did_authenticate', array( __CLASS__, 'mark_app_password' ) );
		add_action( 'set_auth_cookie', array( __CLASS__, 'remember_token' ), 10, 6 );
		add_action( 'wp_login', array( __CLASS__, 'safety_net' ), 0, 2 );
		add_action( 'login_form_siteguard_2fa', array( __CLASS__, 'login_step' ) );
		add_filter( 'wp_login_errors', array( __CLASS__, 'expired_notice' ) );
	}

	/* =========================================================
	 * Policy
	 * ======================================================= */

	public static function allowed_methods() {
		$m = array_values( array_intersect( array( 'totp', 'email' ), (array) SiteGuard_Options::get( 'tfa_methods' ) ) );
		return $m ? $m : array( 'email' );
	}

	public static function is_forced( WP_User $user ) {
		$roles = (array) SiteGuard_Options::get( 'tfa_force_roles' );
		if ( array_intersect( $roles, (array) $user->roles ) ) {
			return true;
		}
		return is_multisite() && in_array( 'administrator', $roles, true ) && is_super_admin( $user->ID );
	}

	/** 'totp' | 'email' | 'enroll' (forced, must set up an app during login) | '' (no 2FA). */
	public static function effective_method( WP_User $user ) {
		$allowed = self::allowed_methods();
		$method  = (string) get_user_meta( $user->ID, self::M_METHOD, true );
		if ( 'totp' === $method && ! get_user_meta( $user->ID, self::M_SECRET, true ) ) {
			$method = '';
		}
		if ( in_array( $method, $allowed, true ) ) {
			return $method;
		}
		if ( self::is_forced( $user ) ) {
			return in_array( 'email', $allowed, true ) ? 'email' : 'enroll';
		}
		return '';
	}

	private static function required( WP_User $user, $context ) {
		$method = self::effective_method( $user );
		if ( '' === $method ) {
			return '';
		}
		return apply_filters( 'siteguard_2fa_required', true, $user, $context ) ? $method : '';
	}

	/* =========================================================
	 * Helpers
	 * ======================================================= */

	private static function h( $value ) {
		return hash_hmac( 'sha256', (string) $value, wp_salt( 'auth' ) );
	}

	public static function step_url( $args = array() ) {
		// site_url() (not wp_login_url()) so custom-login-URL plugins rewrite it to their slug.
		return add_query_arg( array_merge( array( 'action' => 'siteguard_2fa' ), $args ), site_url( 'wp-login.php', 'login' ) );
	}

	private static function secure_cookie() {
		return is_ssl() || 'https' === wp_parse_url( site_url(), PHP_URL_SCHEME );
	}

	private static function set_cookie( $value, $expire ) {
		if ( headers_sent() ) {
			return false;
		}
		$paths = array_unique( array( SITECOOKIEPATH, COOKIEPATH, '/' ) );
		foreach ( $paths as $path ) {
			setcookie( self::COOKIE, $value, array( 'expires' => $expire, 'path' => $path ? $path : '/', 'domain' => COOKIE_DOMAIN ? COOKIE_DOMAIN : '', 'secure' => self::secure_cookie(), 'httponly' => true, 'samesite' => 'Lax' ) );
		}
		return true;
	}

	private static function clear_cookie() {
		self::set_cookie( '', time() - YEAR_IN_SECONDS );
	}

	private static function flush_meta_cache( $user_id ) {
		wp_cache_delete( $user_id, 'user_meta' );
	}

	/* =========================================================
	 * Challenges (one usermeta row each → atomic claim by DELETE)
	 * ======================================================= */

	private static function challenge_rows( $user_id ) {
		global $wpdb;
		return $wpdb->get_results( $wpdb->prepare( "SELECT umeta_id, meta_key, meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key LIKE %s ORDER BY umeta_id ASC", $user_id, $wpdb->esc_like( self::M_CHAL ) . '%' ) );
	}

	private static function create_challenge( WP_User $user, $method, $context ) {
		global $wpdb;
		// Drop expired challenges; cap open ones (oldest first).
		$rows = self::challenge_rows( $user->ID );
		$open = array();
		foreach ( $rows as $r ) {
			$d = maybe_unserialize( $r->meta_value );
			if ( ! is_array( $d ) || (int) ( $d['expires'] ?? 0 ) < time() ) {
				$wpdb->delete( $wpdb->usermeta, array( 'umeta_id' => (int) $r->umeta_id ), array( '%d' ) );
			} else {
				$open[] = (int) $r->umeta_id;
			}
		}
		while ( count( $open ) >= self::MAX_CHALLENGE ) {
			$wpdb->delete( $wpdb->usermeta, array( 'umeta_id' => array_shift( $open ) ), array( '%d' ) );
		}
		self::flush_meta_cache( $user->ID );

		$redirect = '';
		foreach ( array( 'redirect_to', 'redirect' ) as $k ) {
			if ( ! empty( $_REQUEST[ $k ] ) && is_string( $_REQUEST[ $k ] ) ) { // phpcs:ignore
				$redirect = wp_unslash( $_REQUEST[ $k ] ); // phpcs:ignore
				break;
			}
		}
		if ( '' === $redirect && ( 'wp_login' === $context || ! isset( $GLOBALS['pagenow'] ) || 'wp-login.php' !== $GLOBALS['pagenow'] ) ) {
			// Front-end forms (WooCommerce My Account, checkout, SSO callbacks): return to that page.
			$redirect = (string) wp_validate_redirect( (string) wp_get_raw_referer(), '' );
			if ( '' === $redirect && isset( $_POST['woocommerce-login-nonce'] ) && function_exists( 'wc_get_page_permalink' ) ) { // phpcs:ignore
				$redirect = (string) wc_get_page_permalink( 'myaccount' );
			}
		}

		$token = wp_generate_password( 40, false, false );
		$hash  = self::h( $token );
		$data  = array(
			'hash'     => $hash,
			'expires'  => time() + self::TOKEN_TTL,
			'attempts' => 0,
			'remember' => ! empty( $_POST['rememberme'] ), // phpcs:ignore
			'redirect' => esc_url_raw( $redirect ),
			'interim'  => isset( $_REQUEST['interim-login'] ), // phpcs:ignore
			'blog'     => get_current_blog_id(),
			'email'    => '',
			'sent'     => 0,
			'ip'       => SiteGuard_IP::current(),
		);
		add_user_meta( $user->ID, self::M_CHAL . substr( $hash, 0, 24 ), $data, true );
		self::set_cookie( $user->ID . '|' . $token, time() + self::TOKEN_TTL );

		$mail_ok = true;
		if ( 'email' === $method ) {
			$mail_ok = self::send_email_code( $user, substr( $hash, 0, 24 ) );
		}
		return array( $token, $mail_ok );
	}

	/** @return array{0:WP_User,1:string,2:array}|false  [user, meta_key, data] */
	private static function current_challenge() {
		if ( empty( $_COOKIE[ self::COOKIE ] ) || ! is_string( $_COOKIE[ self::COOKIE ] ) ) {
			return false;
		}
		$parts = explode( '|', sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ), 2 );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) ) {
			return false;
		}
		$user = get_user_by( 'id', (int) $parts[0] );
		if ( ! $user ) {
			return false;
		}
		$hash = self::h( $parts[1] );
		$key  = self::M_CHAL . substr( $hash, 0, 24 );
		self::flush_meta_cache( $user->ID );
		$data = get_user_meta( $user->ID, $key, true );
		if ( ! is_array( $data ) || empty( $data['hash'] ) || ! hash_equals( $data['hash'], $hash )
			|| (int) $data['expires'] < time() || (int) $data['attempts'] >= self::MAX_ATTEMPTS
			|| (int) ( $data['blog'] ?? 0 ) !== get_current_blog_id() ) {
			return false;
		}
		return array( $user, $key, $data );
	}

	/** Atomically consume a challenge; only one request can ever get true. */
	private static function claim( $user_id, $key ) {
		global $wpdb;
		$n = $wpdb->delete( $wpdb->usermeta, array( 'user_id' => $user_id, 'meta_key' => $key ), array( '%d', '%s' ) ); // phpcs:ignore
		self::flush_meta_cache( $user_id );
		return 1 === (int) $n;
	}

	private static function send_email_code( WP_User $user, $chal_id ) {
		$key  = self::M_CHAL . $chal_id;
		$data = get_user_meta( $user->ID, $key, true );
		if ( ! is_array( $data ) ) {
			return false;
		}
		$code          = (string) random_int( 100000, 999999 );
		$data['email'] = self::h( $code );
		$data['sent']  = time();
		update_user_meta( $user->ID, $key, $data );

		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$ok   = wp_mail(
			$user->user_email,
			/* translators: 1: site name 2: code */
			sprintf( __( '[%1$s] Your login code: %2$s', 'siteguard-security' ), $site, $code ),
			sprintf(
				/* translators: 1: display name 2: site URL 3: code 4: IP */
				__( "Hi %1\$s,\n\nYour login verification code for %2\$s is:\n\n%3\$s\n\nThe code expires in 10 minutes. Request IP: %4\$s\nIf this was not you, change your password now.", 'siteguard-security' ),
				$user->display_name,
				home_url( '/' ),
				$code,
				SiteGuard_IP::current()
			)
		);
		if ( ! $ok ) {
			$data['email'] = '';
			update_user_meta( $user->ID, $key, $data );
			SiteGuard_BruteForce::log( 'email_fail', $user->user_login, 'wp_mail() failed for the 2FA code' );
		}
		return (bool) $ok;
	}

	/* =========================================================
	 * Step 1: password accepted -> divert to the code screen
	 * ======================================================= */

	public static function mark_app_password() {
		self::$app_password = true;
	}

	public static function remember_token( $cookie, $expire, $expiration, $user_id, $scheme = '', $token = '' ) {
		self::$last_token = (string) $token;
	}

	public static function intercept( $user, $username, $password ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}
		// Application passwords are app-specific secrets made for non-interactive clients.
		if ( self::$app_password ) {
			return $user;
		}
		$method = self::required( $user, 'authenticate' );
		if ( '' === $method ) {
			return $user;
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			if ( SiteGuard_Options::get( 'tfa_xmlrpc_block' ) ) {
				SiteGuard_BruteForce::log( 'blocked', $user->user_login, 'XML-RPC password login refused (2FA user)' );
				return new WP_Error( 'sg_2fa_xmlrpc', __( 'Two-factor authentication is enabled for this account; XML-RPC password login is disabled. Use an application password.', 'siteguard-security' ) );
			}
			return $user;
		}

		$is_post = 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ); // phpcs:ignore
		$is_rest = defined( 'REST_REQUEST' ) && REST_REQUEST;

		if ( $is_post && ! $is_rest && ! wp_doing_ajax() && ! headers_sent() ) {
			self::create_challenge( $user, $method, 'authenticate' );
			nocache_headers();
			wp_safe_redirect( self::step_url() );
			exit;
		}

		// AJAX / REST / programmatic callers cannot render a second step: never let them in, but
		// still open a challenge so the user can finish via the link.
		if ( $is_post && ! headers_sent() ) {
			self::create_challenge( $user, $method, 'authenticate' );
		}
		SiteGuard_BruteForce::log( 'challenge', $user->user_login, 'Non-interactive login asked for 2FA' );
		return new WP_Error(
			'sg_2fa_required',
			sprintf(
				/* translators: %s URL */
				__( 'This account uses two-factor authentication. <a href="%s">Continue to enter your verification code</a>.', 'siteguard-security' ),
				esc_url( self::step_url() )
			)
		);
	}

	/**
	 * Logins that bypassed `authenticate` (SSO, social, magic links): kill the new session and
	 * require the code. Our own completion sets $completing.
	 */
	public static function safety_net( $user_login, $user = null ) {
		if ( self::$completing || ! ( $user instanceof WP_User ) ) {
			return;
		}
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : ''; // phpcs:ignore
		if ( in_array( $action, array( 'switch_to_user', 'switch_to_olduser', 'switch_off' ), true ) ) {
			return; // User Switching plugin: an admin acting, not a login.
		}
		$method = self::required( $user, 'wp_login' );
		if ( '' === $method ) {
			return;
		}

		if ( '' !== self::$last_token && class_exists( 'WP_Session_Tokens' ) ) {
			WP_Session_Tokens::get_instance( $user->ID )->destroy( self::$last_token );
		}
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );
		SiteGuard_BruteForce::log( 'challenge', $user->user_login, 'Login without password step: 2FA required' );

		self::create_challenge( $user, $method, 'wp_login' );
		$url = self::step_url();
		if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			wp_send_json_error( array( 'message' => __( 'Two-factor verification required.', 'siteguard-security' ), 'redirect' => $url ), 401 );
		}
		if ( ! headers_sent() ) {
			nocache_headers();
			wp_safe_redirect( $url );
			exit;
		}
		wp_die( sprintf( '<a href="%s">%s</a>', esc_url( $url ), esc_html__( 'Continue to two-factor verification', 'siteguard-security' ) ), '', array( 'response' => 401 ) );
	}

	public static function expired_notice( $errors ) {
		if ( isset( $_GET['sg2fa'] ) && is_wp_error( $errors ) ) { // phpcs:ignore
			$why = sanitize_key( $_GET['sg2fa'] ); // phpcs:ignore
			$msg = 'cooldown' === $why
				? __( 'Too many wrong verification codes for this account. Please wait 15 minutes and log in again.', 'siteguard-security' )
				: __( 'Your verification session expired or had too many wrong codes. Please log in again.', 'siteguard-security' );
			$errors->add( 'sg_2fa_expired', $msg );
		}
		return $errors;
	}

	/* =========================================================
	 * Step 2: wp-login.php?action=siteguard_2fa
	 * ======================================================= */

	private static function user_cooling_down( WP_User $user ) {
		$f = get_user_meta( $user->ID, self::M_FAILS, true );
		return is_array( $f ) && (int) $f['since'] > time() - self::USER_WINDOW && (int) $f['count'] >= self::USER_FAILS;
	}

	private static function user_fail( WP_User $user ) {
		$f = get_user_meta( $user->ID, self::M_FAILS, true );
		if ( ! is_array( $f ) || (int) $f['since'] <= time() - self::USER_WINDOW ) {
			$f = array( 'count' => 0, 'since' => time() );
		}
		++$f['count'];
		update_user_meta( $user->ID, self::M_FAILS, $f );
	}

	private static function bail( $why = 'expired' ) {
		self::clear_cookie();
		nocache_headers();
		wp_safe_redirect( add_query_arg( 'sg2fa', $why, site_url( 'wp-login.php', 'login' ) ) );
		exit;
	}

	public static function login_step() {
		nocache_headers();
		$c = self::current_challenge();
		if ( ! $c ) {
			self::bail();
		}
		list( $user, $key, $data ) = $c;
		if ( self::user_cooling_down( $user ) ) {
			self::claim( $user->ID, $key );
			self::bail( 'cooldown' );
		}

		$method = self::effective_method( $user );
		if ( '' === $method ) {
			$method = 'email'; // Policy changed mid-login; still demand a factor.
		}
		$valid = array( $method );
		if ( 'enroll' !== $method && in_array( 'email', self::allowed_methods(), true ) ) {
			$valid[] = 'email';
		}
		if ( self::backup_count( $user ) ) {
			$valid[] = 'backup';
		}
		$use = isset( $_REQUEST['sg_use'] ) ? sanitize_key( $_REQUEST['sg_use'] ) : $method; // phpcs:ignore
		if ( ! in_array( $use, $valid, true ) ) {
			$use = $method;
		}
		$error   = '';
		$notice  = '';
		$is_post = 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ); // phpcs:ignore
		$chal_id = substr( $key, strlen( self::M_CHAL ) );

		if ( 'email' === $use && empty( $data['sent'] ) && ! $is_post ) {
			// Switched to email from another method: send the first code now.
			if ( self::send_email_code( $user, $chal_id ) ) {
				$notice = __( 'A code has been sent to your email address.', 'siteguard-security' );
			} else {
				$error = __( 'We could not send the email. Use another method or contact the site administrator.', 'siteguard-security' );
			}
		} elseif ( $is_post && isset( $_POST['sg_send_email'] ) ) { // phpcs:ignore
			$use = 'email';
			if ( time() - (int) $data['sent'] < 60 ) {
				$error = __( 'Please wait a minute before requesting another code.', 'siteguard-security' );
			} elseif ( self::send_email_code( $user, $chal_id ) ) {
				$notice = __( 'A new code has been sent to your email address.', 'siteguard-security' );
			} else {
				$error = __( 'We could not send the email. Use another method or contact the site administrator.', 'siteguard-security' );
			}
		} elseif ( $is_post && isset( $_POST['sg_code'] ) && is_string( $_POST['sg_code'] ) ) { // phpcs:ignore
			$code = sanitize_text_field( wp_unslash( $_POST['sg_code'] ) ); // phpcs:ignore
			if ( self::check_code( $user, $use, $code, $data ) && self::claim( $user->ID, $key ) ) {
				self::complete_login( $user, $data );
			}
			$data['attempts'] = (int) $data['attempts'] + 1;
			if ( get_user_meta( $user->ID, $key, true ) ) {
				update_user_meta( $user->ID, $key, $data );
			}
			self::user_fail( $user );
			SiteGuard_BruteForce::record_failure( $user->user_login, '2fa_fail' );
			if ( $data['attempts'] >= self::MAX_ATTEMPTS || SiteGuard_BruteForce::locked_for() ) {
				self::claim( $user->ID, $key );
				self::bail();
			}
			$error = __( 'Invalid or expired code. Please try again.', 'siteguard-security' );
		} elseif ( 'email' === $use && ! empty( $data['sent'] ) && empty( $data['email'] ) ) {
			$error = __( 'We could not send the email. Use another method or contact the site administrator.', 'siteguard-security' );
		}

		self::render_step( $user, $method, $use, $error, $notice, $data );
		exit;
	}

	private static function check_code( WP_User $user, $use, $code, array $data ) {
		global $wpdb;
		$code = trim( (string) $code );

		if ( 'totp' === $use || 'enroll' === $use ) {
			$secret = 'enroll' === $use ? (string) get_user_meta( $user->ID, self::M_PENDING, true ) : (string) get_user_meta( $user->ID, self::M_SECRET, true );
			$last   = 'enroll' === $use ? 0 : (int) get_user_meta( $user->ID, self::M_LAST_STEP, true );
			$step   = SiteGuard_TOTP::verify( $secret, $code, $last );
			if ( false === $step ) {
				return false;
			}
			if ( 'enroll' === $use ) {
				update_user_meta( $user->ID, self::M_SECRET, $secret );
				update_user_meta( $user->ID, self::M_LAST_STEP, $step );
				update_user_meta( $user->ID, self::M_METHOD, 'totp' );
				delete_user_meta( $user->ID, self::M_PENDING );
				if ( ! self::backup_count( $user ) ) {
					self::generate_backup_codes( $user->ID );
				}
				return true;
			}
			// Atomic replay guard: only one request may move last_step forward to $step.
			if ( '' === get_user_meta( $user->ID, self::M_LAST_STEP, true ) ) {
				add_user_meta( $user->ID, self::M_LAST_STEP, '0', true );
			}
			$n = $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->usermeta} SET meta_value = %s WHERE user_id = %d AND meta_key = %s AND CAST(meta_value AS UNSIGNED) < %d", (string) $step, $user->ID, self::M_LAST_STEP, $step ) );
			self::flush_meta_cache( $user->ID );
			return 1 === (int) $n;
		}

		if ( 'email' === $use ) {
			$code = preg_replace( '/\D/', '', $code );
			return ! empty( $data['email'] ) && (int) $data['sent'] >= time() - self::TOKEN_TTL && hash_equals( (string) $data['email'], self::h( $code ) );
		}

		if ( 'backup' === $use ) {
			$code = strtolower( preg_replace( '/[^A-Za-z0-9]/', '', $code ) );
			if ( '' === $code ) {
				return false;
			}
			$n = $wpdb->delete( $wpdb->usermeta, array( 'user_id' => $user->ID, 'meta_key' => self::M_BACKUP, 'meta_value' => self::h( $code ) ), array( '%d', '%s', '%s' ) ); // phpcs:ignore
			self::flush_meta_cache( $user->ID );
			if ( $n ) {
				SiteGuard_BruteForce::log( 'backup_code', $user->user_login, self::backup_count( $user ) . ' backup code(s) left' );
				return true;
			}
		}
		return false;
	}

	private static function complete_login( WP_User $user, array $data ) {
		self::clear_cookie();
		delete_user_meta( $user->ID, self::M_FAILS );
		self::$completing = true;
		wp_set_auth_cookie( $user->ID, ! empty( $data['remember'] ) );
		wp_set_current_user( $user->ID );
		do_action( 'wp_login', $user->user_login, $user );

		if ( ! empty( $data['interim'] ) && function_exists( 'login_header' ) ) {
			$GLOBALS['interim_login'] = 'success'; // phpcs:ignore
			login_header( '', '<p class="message">' . esc_html__( 'You have logged in successfully.', 'siteguard-security' ) . '</p>' );
			echo '</div>';
			do_action( 'login_footer' );
			echo '</body></html>';
			exit;
		}

		$requested = ! empty( $data['redirect'] ) ? $data['redirect'] : admin_url();
		$redirect  = apply_filters( 'login_redirect', $requested, $requested, $user );
		if ( empty( $redirect ) || 'wp-admin/' === $redirect || admin_url() === $redirect ) {
			if ( is_multisite() && ! get_active_blog_for_user( $user->ID ) && ! is_super_admin( $user->ID ) ) {
				$redirect = user_admin_url();
			} elseif ( is_multisite() && ! $user->has_cap( 'read' ) ) {
				$redirect = get_dashboard_url( $user->ID );
			} elseif ( ! $user->has_cap( 'edit_posts' ) ) {
				$redirect = $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url();
			}
		}
		wp_safe_redirect( $redirect ? $redirect : admin_url() );
		exit;
	}

	private static function render_step( WP_User $user, $method, $use, $error, $notice, array $data ) {
		$errors = new WP_Error();
		if ( $error ) {
			$errors->add( 'sg_2fa', $error );
		}
		if ( $notice ) {
			$errors->add( 'sg_2fa_notice', $notice, 'message' );
		}
		$title = __( 'Two-factor authentication', 'siteguard-security' );
		if ( function_exists( 'login_header' ) ) {
			login_header( $title, '', $errors );
		} else {
			echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>' . esc_html( $title ) . '</title></head><body style="font-family:sans-serif;max-width:360px;margin:40px auto">';
			foreach ( $errors->get_error_messages() as $m ) {
				echo '<p>' . wp_kses_post( $m ) . '</p>';
			}
		}

		$labels = array(
			'totp'   => __( 'Enter the 6-digit code from your authenticator app.', 'siteguard-security' ),
			/* translators: masked email */
			'email'  => sprintf( __( 'Enter the 6-digit code we emailed to %s.', 'siteguard-security' ), self::mask_email( $user->user_email ) ),
			'backup' => __( 'Enter one of your backup codes. Each code works once.', 'siteguard-security' ),
			'enroll' => __( 'Your account requires two-factor authentication. Scan this QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy…), then enter the 6-digit code it shows.', 'siteguard-security' ),
		);
		$args   = array( 'sg_use' => $use );
		if ( ! empty( $data['interim'] ) ) {
			$args['interim-login'] = 1;
		}
		$action = self::step_url( $args );
		$plain  = 'style="display:inline;margin:0;padding:0;box-shadow:none;background:none;border:0"';
		?>
		<form name="siteguard_2fa" id="loginform" action="<?php echo esc_url( $action ); ?>" method="post" autocomplete="off">
			<p class="message" style="margin-left:0;margin-right:0"><?php echo esc_html( $labels[ $use ] ); ?></p>
			<?php
			if ( 'enroll' === $use ) :
				$pending = (string) get_user_meta( $user->ID, self::M_PENDING, true );
				if ( '' === $pending ) {
					$pending = SiteGuard_TOTP::generate_secret();
					update_user_meta( $user->ID, self::M_PENDING, $pending );
				}
				$uri = SiteGuard_TOTP::uri( $pending, $user->user_login, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
				?>
				<div id="sg-qr" data-uri="<?php echo esc_attr( $uri ); ?>" style="margin:12px 0;background:#fff;text-align:center"></div>
				<p style="font-size:12px;word-break:break-all"><?php esc_html_e( 'Manual key:', 'siteguard-security' ); ?> <code><?php echo esc_html( trim( chunk_split( $pending, 4, ' ' ) ) ); ?></code></p>
				<script src="<?php echo esc_url( SITEGUARD_URL . 'assets/qrcode.js?ver=' . SITEGUARD_VERSION ); ?>"></script>
				<script>(function(){var el=document.getElementById('sg-qr');if(!el||typeof qrcode==='undefined')return;var q=qrcode(0,'M');q.addData(el.getAttribute('data-uri'));q.make();el.innerHTML=q.createSvgTag(4,0);})();</script>
			<?php endif; ?>
			<p>
				<label for="sg_code"><?php esc_html_e( 'Verification code', 'siteguard-security' ); ?></label>
				<input type="text" name="sg_code" id="sg_code" class="input" value="" size="20"
					<?php echo 'backup' === $use ? '' : 'inputmode="numeric" autocomplete="one-time-code"'; ?> autofocus required />
			</p>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'siteguard-security' ); ?>" />
			</p>
		</form>
		<p id="nav" style="line-height:2">
			<?php if ( 'email' === $use ) : ?>
				<form method="post" action="<?php echo esc_url( $action ); ?>" <?php echo $plain; // phpcs:ignore ?>>
					<button type="submit" name="sg_send_email" value="1" class="button-link"><?php esc_html_e( 'Resend code', 'siteguard-security' ); ?></button>
				</form><br>
			<?php endif; ?>
			<?php if ( in_array( $method, array( 'totp', 'enroll' ), true ) && $method !== $use ) : ?>
				<a href="<?php echo esc_url( self::step_url( array_merge( $args, array( 'sg_use' => $method ) ) ) ); ?>"><?php echo esc_html( 'enroll' === $method ? __( 'Set up authenticator app', 'siteguard-security' ) : __( 'Use authenticator app', 'siteguard-security' ) ); ?></a><br>
			<?php endif; ?>
			<?php if ( 'email' !== $use && 'enroll' !== $method && in_array( 'email', self::allowed_methods(), true ) ) : ?>
				<a href="<?php echo esc_url( self::step_url( array_merge( $args, array( 'sg_use' => 'email' ) ) ) ); ?>"><?php esc_html_e( 'Email me a code instead', 'siteguard-security' ); ?></a><br>
			<?php endif; ?>
			<?php if ( 'backup' !== $use && self::backup_count( $user ) ) : ?>
				<a href="<?php echo esc_url( self::step_url( array_merge( $args, array( 'sg_use' => 'backup' ) ) ) ); ?>"><?php esc_html_e( 'Use a backup code', 'siteguard-security' ); ?></a><br>
			<?php endif; ?>
			<a href="<?php echo esc_url( site_url( 'wp-login.php', 'login' ) ); ?>"><?php esc_html_e( '&larr; Back to login', 'siteguard-security' ); ?></a>
		</p>
		<?php
		if ( function_exists( 'login_footer' ) ) {
			login_footer( 'sg_code' );
		} else {
			echo '</body></html>';
		}
	}

	private static function mask_email( $email ) {
		list( $local, $domain ) = array_pad( explode( '@', (string) $email, 2 ), 2, '' );
		return substr( $local, 0, 2 ) . str_repeat( '*', max( 1, strlen( $local ) - 2 ) ) . '@' . $domain;
	}

	public static function backup_count( WP_User $user ) {
		return count( (array) get_user_meta( $user->ID, self::M_BACKUP, false ) );
	}

	/** @return string[] plain codes (shown once). */
	public static function generate_backup_codes( $user_id ) {
		delete_user_meta( $user_id, self::M_BACKUP );
		$plain = array();
		for ( $i = 0; $i < self::BACKUP_COUNT; $i++ ) {
			$c       = strtolower( wp_generate_password( 10, false, false ) );
			$plain[] = substr( $c, 0, 5 ) . '-' . substr( $c, 5 );
			add_user_meta( $user_id, self::M_BACKUP, self::h( $c ) );
		}
		set_transient( 'sg_backup_show_' . $user_id, $plain, 30 * MINUTE_IN_SECONDS );
		return $plain;
	}

	public static function reset_user( $user_id ) {
		global $wpdb;
		foreach ( array( self::M_METHOD, self::M_SECRET, self::M_PENDING, self::M_LAST_STEP, self::M_BACKUP, self::M_FAILS ) as $k ) {
			delete_user_meta( $user_id, $k );
		}
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key LIKE %s", $user_id, $wpdb->esc_like( self::M_CHAL ) . '%' ) );
		self::flush_meta_cache( $user_id );
	}

	/* =========================================================
	 * Profile screen
	 * ======================================================= */

	public static function profile_assets( $hook ) {
		if ( in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			wp_enqueue_script( 'siteguard-qrcode', SITEGUARD_URL . 'assets/qrcode.js', array(), SITEGUARD_VERSION, true );
		}
	}

	private static function can_reset_others() {
		return is_multisite() ? current_user_can( 'manage_network_users' ) : current_user_can( 'edit_users' );
	}

	public static function profile_section( $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}
		$own     = get_current_user_id() === $user->ID;
		$allowed = self::allowed_methods();
		$method  = (string) get_user_meta( $user->ID, self::M_METHOD, true );
		$has_tot = (bool) get_user_meta( $user->ID, self::M_SECRET, true );
		$forced  = self::is_forced( $user );
		$eff     = self::effective_method( $user );
		$names   = array(
			'totp'   => __( 'Authenticator app', 'siteguard-security' ),
			'email'  => __( 'Email code', 'siteguard-security' ),
			'enroll' => __( 'Required — app set-up at next login', 'siteguard-security' ),
		);
		if ( ! $own && ! self::can_reset_others() ) {
			return;
		}
		wp_nonce_field( 'sg_tfa_profile_' . $user->ID, '_sg_tfa_nonce' );
		?>
		<h2 id="siteguard-2fa"><?php esc_html_e( 'Two-Factor Authentication (SiteGuard)', 'siteguard-security' ); ?></h2>
		<?php if ( ! SiteGuard_Options::get( 'tfa_enabled' ) ) : ?>
			<p class="description"><?php esc_html_e( 'Two-factor login is currently switched off by the site administrator. Settings saved here apply once it is enabled.', 'siteguard-security' ); ?></p>
		<?php endif; ?>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'Status', 'siteguard-security' ); ?></th>
				<td>
					<?php
					if ( $eff ) {
						/* translators: method name */
						echo '<strong style="color:#008a20">' . esc_html( sprintf( __( 'On — %s', 'siteguard-security' ), $names[ $eff ] ) ) . '</strong>';
					} else {
						echo '<strong style="color:#b32d2e">' . esc_html__( 'Off', 'siteguard-security' ) . '</strong>';
					}
					if ( $forced ) {
						echo ' <span class="description">' . esc_html__( '(required for this role)', 'siteguard-security' ) . '</span>';
					}
					/* translators: number */
					echo '<br><span class="description">' . esc_html( sprintf( __( 'Backup codes left: %d', 'siteguard-security' ), self::backup_count( $user ) ) ) . '</span>';
					?>
				</td>
			</tr>
			<?php if ( $own ) : ?>
			<tr>
				<th><label for="sg_tfa_method"><?php esc_html_e( 'Method', 'siteguard-security' ); ?></label></th>
				<td>
					<select name="sg_tfa_method" id="sg_tfa_method">
						<option value=""><?php echo esc_html( $forced ? __( 'Default (set by administrator)', 'siteguard-security' ) : __( 'Off', 'siteguard-security' ) ); ?></option>
						<?php foreach ( $allowed as $m ) : ?>
							<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $method, $m ); ?>><?php echo esc_html( $names[ $m ] ); ?></option>
						<?php endforeach; ?>
					</select>
				</td>
			</tr>
				<?php
				if ( in_array( 'totp', $allowed, true ) ) :
					$pending = (string) get_user_meta( $user->ID, self::M_PENDING, true );
					if ( '' === $pending ) {
						$pending = SiteGuard_TOTP::generate_secret();
						update_user_meta( $user->ID, self::M_PENDING, $pending );
					}
					$uri = SiteGuard_TOTP::uri( $pending, $user->user_login, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
					?>
			<tr id="sg-totp-setup" style="<?php echo ( 'totp' === $method && $has_tot ) ? 'display:none' : ''; ?>">
				<th><?php echo $has_tot ? esc_html__( 'Replace authenticator', 'siteguard-security' ) : esc_html__( 'Set up authenticator', 'siteguard-security' ); ?></th>
				<td>
					<p><?php esc_html_e( 'Scan with Google Authenticator, Microsoft Authenticator, Authy, 1Password, etc., then type the 6-digit code it shows and save.', 'siteguard-security' ); ?></p>
					<div id="sg-qr" data-uri="<?php echo esc_attr( $uri ); ?>" style="margin:10px 0;background:#fff;display:inline-block;padding:8px"></div>
					<p><?php esc_html_e( 'Manual key:', 'siteguard-security' ); ?> <code><?php echo esc_html( trim( chunk_split( $pending, 4, ' ' ) ) ); ?></code></p>
					<p><input type="text" name="sg_totp_code" id="sg_totp_code" class="regular-text" inputmode="numeric" autocomplete="off" placeholder="123456" style="width:10em" />
					<span class="description"><?php esc_html_e( 'Required when switching to Authenticator app.', 'siteguard-security' ); ?></span></p>
				</td>
			</tr>
					<?php if ( 'totp' === $method && $has_tot ) : ?>
			<tr><th></th><td><button type="button" class="button" onclick="document.getElementById('sg-totp-setup').style.display='';this.style.display='none'"><?php esc_html_e( 'Move to a new phone', 'siteguard-security' ); ?></button></td></tr>
					<?php endif; ?>
			<script>
			document.addEventListener('DOMContentLoaded', function(){
				var el = document.getElementById('sg-qr');
				if (!el || typeof qrcode === 'undefined') return;
				var qr = qrcode(0, 'M'); qr.addData(el.getAttribute('data-uri')); qr.make();
				el.innerHTML = qr.createSvgTag(5, 0);
			});
			</script>
				<?php endif; ?>
			<tr>
				<th><?php esc_html_e( 'Backup codes', 'siteguard-security' ); ?></th>
				<td><label><input type="checkbox" name="sg_regen_backup" value="1" /> <?php esc_html_e( 'Generate new backup codes (old codes stop working). They are shown once after saving.', 'siteguard-security' ); ?></label></td>
			</tr>
			<?php else : ?>
			<tr>
				<th><?php esc_html_e( 'Reset', 'siteguard-security' ); ?></th>
				<td><label><input type="checkbox" name="sg_tfa_reset" value="1" /> <?php esc_html_e( 'Turn off this user\'s 2FA and delete their authenticator key and backup codes (use if they lost their phone).', 'siteguard-security' ); ?></label>
				<?php if ( is_multisite() ) : ?><p class="description"><?php esc_html_e( '2FA set-up is per user, so this applies on every site in the network.', 'siteguard-security' ); ?></p><?php endif; ?></td>
			</tr>
			<?php endif; ?>
		</table>
		<?php
	}

	public static function profile_save( $user_id ) {
		$user_id = (int) $user_id;
		if ( ! isset( $_POST['_sg_tfa_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_sg_tfa_nonce'] ) ), 'sg_tfa_profile_' . $user_id ) ) {
			return;
		}
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		if ( get_current_user_id() !== $user_id ) {
			if ( ! empty( $_POST['sg_tfa_reset'] ) && self::can_reset_others() ) {
				self::reset_user( $user_id );
				$u = get_userdata( $user_id );
				SiteGuard_BruteForce::log( '2fa_reset', $u ? $u->user_login : '', 'Reset by ' . wp_get_current_user()->user_login );
			}
			return;
		}

		$new     = isset( $_POST['sg_tfa_method'] ) ? sanitize_key( $_POST['sg_tfa_method'] ) : '';
		$allowed = self::allowed_methods();
		if ( '' !== $new && ! in_array( $new, $allowed, true ) ) {
			$new = '';
		}
		$code    = isset( $_POST['sg_totp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['sg_totp_code'] ) ) : '';
		$pending = (string) get_user_meta( $user_id, self::M_PENDING, true );

		if ( '' !== trim( $code ) && $pending ) {
			$step = SiteGuard_TOTP::verify( $pending, $code );
			if ( false === $step ) {
				self::$profile_error = __( 'The authenticator code is wrong; 2FA settings were not changed. Check your phone\'s clock and try again.', 'siteguard-security' );
				return;
			}
			update_user_meta( $user_id, self::M_SECRET, $pending );
			update_user_meta( $user_id, self::M_LAST_STEP, (string) $step );
			delete_user_meta( $user_id, self::M_PENDING );
			if ( '' === $new || 'email' !== $new ) {
				$new = 'totp';
			}
		} elseif ( 'totp' === $new && ! get_user_meta( $user_id, self::M_SECRET, true ) ) {
			self::$profile_error = __( 'Enter the 6-digit code from your authenticator app to switch on app-based 2FA.', 'siteguard-security' );
			return;
		}

		update_user_meta( $user_id, self::M_METHOD, $new );
		if ( '' === $new ) {
			delete_user_meta( $user_id, self::M_SECRET );
		}

		$user = get_userdata( $user_id );
		if ( ! empty( $_POST['sg_regen_backup'] ) || ( $new && $user && ! self::backup_count( $user ) ) ) {
			self::generate_backup_codes( $user_id );
		}
	}

	public static function profile_errors( $errors, $update, $user ) {
		if ( self::$profile_error && is_wp_error( $errors ) ) {
			$errors->add( 'sg_tfa', self::$profile_error );
		}
	}

	public static function backup_codes_notice() {
		$uid   = get_current_user_id();
		$codes = $uid ? get_transient( 'sg_backup_show_' . $uid ) : false;
		if ( ! $codes || ! is_array( $codes ) ) {
			return;
		}
		delete_transient( 'sg_backup_show_' . $uid );
		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'SiteGuard backup codes — save these now, they will not be shown again:', 'siteguard-security' ) . '</strong></p>';
		echo '<p style="font-family:monospace;font-size:15px;columns:2;max-width:320px">' . implode( '<br>', array_map( 'esc_html', $codes ) ) . '</p></div>';
	}

	/** Remind forced users who still rely on the email fallback to set up an app. */
	public static function enroll_nag() {
		if ( ! SiteGuard_Options::get( 'tfa_enabled' ) || ! is_user_logged_in() ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && 'profile' === $screen->id ) {
			return;
		}
		$user = wp_get_current_user();
		if ( self::is_forced( $user ) && '' === (string) get_user_meta( $user->ID, self::M_METHOD, true ) && in_array( 'totp', self::allowed_methods(), true ) ) {
			echo '<div class="notice notice-info"><p>' . wp_kses_post( sprintf(
				/* translators: %s URL */
				__( 'Two-factor login is required for your account. You are currently using email codes — <a href="%s">set up an authenticator app</a> for faster, more reliable logins.', 'siteguard-security' ),
				esc_url( admin_url( 'profile.php#siteguard-2fa' ) )
			) ) . '</p></div>';
		}
	}
}
