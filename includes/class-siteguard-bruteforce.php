<?php
defined( 'ABSPATH' ) || exit;

/**
 * Brute-force protection, login logging, blacklist enforcement, custom login errors.
 *
 * Per IP: fails++ (atomic) -> when fails >= max_retries: lockouts++, fails = 0,
 * locked_until = now + lockout_minutes (extended_hours once lockouts >= max_lockouts).
 * Counters reset after reset_hours without a failure.
 */
class SiteGuard_BruteForce {

	/** Error codes that mean "wrong credentials" and count toward a lockout. */
	const CREDENTIAL_CODES = array( 'invalid_username', 'incorrect_password', 'invalid_email', 'sg_invalid', 'authentication_failed', 'invalid_application_credentials', 'application_passwords_disabled_for_user' );

	const DEFAULT_ATTEMPTS = '%d attempt(s) left before a temporary lockout.';
	const DEFAULT_LOCKED   = 'Too many failed login attempts. Please try again in %s.';
	const DEFAULT_BLOCKED  = 'Your IP address has been blocked from logging in.';

	private static $failed_this_request = false;

	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'gate' ), 99999, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_failed' ), 10, 2 );
		add_action( 'wp_login', array( __CLASS__, 'on_success' ), 10, 2 );
		add_filter( 'login_errors', array( __CLASS__, 'login_errors' ), 99 );
		add_action( 'login_init', array( __CLASS__, 'blocked_screen' ), 1 );
		// REST / XML-RPC application passwords: count failures, refuse locked IPs.
		add_action( 'application_password_failed_authentication', array( __CLASS__, 'on_app_password_failed' ) );
		add_filter( 'application_password_is_api_request', array( __CLASS__, 'app_password_gate' ), 99 );
	}

	/* ---------- state ---------- */

	public static function get_row( $ip ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . SiteGuard_Install::table_ips() . ' WHERE ip = %s', $ip ) ); // phpcs:ignore
	}

	/** Seconds remaining on a lockout, 0 when not locked. */
	public static function locked_for( $ip = null ) {
		if ( ! SiteGuard_Options::get( 'bf_enabled' ) ) {
			return 0;
		}
		$ip = $ip ? $ip : SiteGuard_IP::current();
		if ( SiteGuard_IP::is_whitelisted( $ip ) ) {
			return 0;
		}
		$row = self::get_row( $ip );
		if ( ! $row ) {
			return 0;
		}
		$left = (int) $row->locked_until - time();
		return $left > 0 ? $left : 0;
	}

	public static function attempts_left( $ip = null ) {
		$ip  = $ip ? $ip : SiteGuard_IP::current();
		$row = self::get_row( $ip );
		$max = max( 1, (int) SiteGuard_Options::get( 'max_retries' ) );
		return $row ? max( 0, $max - (int) $row->fails ) : $max;
	}

	public static function log( $event, $username = '', $detail = '', $ip = null ) {
		global $wpdb;
		$url = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		if ( '' === $url && ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			$url = 'wp-cli';
		}
		$wpdb->insert(
			SiteGuard_Install::table_log(),
			array(
				'ip'       => $ip ? $ip : SiteGuard_IP::current(),
				'username' => self::cut( $username, 190 ),
				'event'    => self::cut( $event, 20 ),
				'detail'   => self::cut( $detail, 255 ),
				'url'      => self::cut( $url, 255 ),
				'created'  => time(),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d' )
		);
	}

	public static function cut( $s, $len ) {
		$s = (string) $s;
		return function_exists( 'mb_substr' ) ? mb_substr( $s, 0, $len ) : substr( $s, 0, $len );
	}

	/** Record one failed attempt for the current IP (atomic). Returns lockout seconds applied (0 if none). */
	public static function record_failure( $username = '', $reason = 'failed' ) {
		global $wpdb;
		$ip = SiteGuard_IP::current();
		self::$failed_this_request = true;
		self::log( $reason, $username );

		if ( ! SiteGuard_Options::get( 'bf_enabled' ) || SiteGuard_IP::is_whitelisted( $ip ) ) {
			return 0;
		}

		$o     = SiteGuard_Options::all();
		$t     = SiteGuard_Install::table_ips();
		$now   = time();
		$max   = max( 1, (int) $o['max_retries'] );
		$maxl  = max( 1, (int) $o['max_lockouts'] );
		$short = max( 1, (int) $o['lockout_minutes'] ) * MINUTE_IN_SECONDS;
		$long  = max( 1, (int) $o['extended_hours'] ) * HOUR_IN_SECONDS;
		$reset = $now - max( 1, (int) $o['reset_hours'] ) * HOUR_IN_SECONDS;
		$user  = self::cut( $username, 190 );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$t} (ip, username, fails, lockouts, last_fail, locked_until) VALUES (%s, %s, 0, 0, %d, 0)", $ip, $user, $now ) );
		$wpdb->query( $wpdb->prepare( "UPDATE {$t} SET fails = 0, lockouts = 0 WHERE ip = %s AND last_fail < %d AND locked_until < %d", $ip, $reset, $now ) );
		$wpdb->query( $wpdb->prepare( "UPDATE {$t} SET fails = fails + 1, last_fail = %d, username = %s WHERE ip = %s", $now, $user, $ip ) );
		// Only one concurrent request can win this (fails is reset in the same statement).
		$won = $wpdb->query( $wpdb->prepare( "UPDATE {$t} SET locked_until = %d + IF(lockouts + 1 >= %d, %d, %d), fails = 0, lockouts = lockouts + 1 WHERE ip = %s AND fails >= %d", $now, $maxl, $long, $short, $ip, $max ) );
		// phpcs:enable

		if ( ! $won ) {
			return 0;
		}
		$row     = self::get_row( $ip );
		$locks   = $row ? (int) $row->lockouts : 1;
		$applied = $row ? max( 0, (int) $row->locked_until - $now ) : $short;
		self::log( 'lockout', $username, sprintf( 'Lockout #%d for %s', $locks, human_time_diff( $now, $now + $applied ) ) );
		if ( $o['notify_admin'] && $locks >= max( 1, (int) $o['notify_after'] ) ) {
			self::notify_admin( $ip, $username, $locks, $applied );
		}
		return $applied;
	}

	public static function unlock( $ip ) {
		global $wpdb;
		return $wpdb->delete( SiteGuard_Install::table_ips(), array( 'ip' => $ip ), array( '%s' ) );
	}

	private static function notify_admin( $ip, $username, $locks, $seconds ) {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		wp_mail(
			get_option( 'admin_email' ),
			/* translators: 1: site name 2: IP */
			sprintf( __( '[%1$s] Login lockout: %2$s', 'siteguard-security' ), $site, $ip ),
			sprintf(
				/* translators: 1: IP 2: site URL 3: duration 4: username 5: count 6: admin URL */
				__( "IP %1\$s has been locked out of %2\$s for %3\$s after repeated failed logins.\nLast username tried: %4\$s\nTotal lockouts: %5\$d\n\nManage: %6\$s", 'siteguard-security' ),
				$ip,
				home_url( '/' ),
				human_time_diff( 0, $seconds ),
				$username,
				$locks,
				admin_url( 'admin.php?page=siteguard' )
			)
		);
	}

	/* ---------- messages ---------- */

	public static function msg( $key ) {
		$val = (string) SiteGuard_Options::get( $key );
		switch ( $key ) {
			case 'msg_attempts_left':
				return self::DEFAULT_ATTEMPTS === $val ? __( '%d attempt(s) left before a temporary lockout.', 'siteguard-security' ) : $val;
			case 'msg_locked':
				return self::DEFAULT_LOCKED === $val ? __( 'Too many failed login attempts. Please try again in %s.', 'siteguard-security' ) : $val;
			case 'msg_blacklisted':
				return self::DEFAULT_BLOCKED === $val || '' === $val ? __( 'Your IP address has been blocked from logging in.', 'siteguard-security' ) : $val;
		}
		return $val;
	}

	public static function locked_message( $seconds ) {
		return esc_html( str_replace( '%s', human_time_diff( time(), time() + $seconds ), self::msg( 'msg_locked' ) ) );
	}

	/* ---------- hooks ---------- */

	/** Final word on every authentication attempt (wp-login, XML-RPC, WooCommerce, etc.). */
	public static function gate( $user, $username, $password ) {
		$ip = SiteGuard_IP::current();

		if ( SiteGuard_IP::is_blacklisted( $ip ) ) {
			return new WP_Error( 'sg_blacklisted', esc_html( self::msg( 'msg_blacklisted' ) ) );
		}
		$left = self::locked_for( $ip );
		if ( $left ) {
			return new WP_Error( 'sg_locked', self::locked_message( $left ) );
		}

		if ( is_wp_error( $user ) ) {
			$cred = array_intersect( $user->get_error_codes(), array( 'invalid_username', 'incorrect_password', 'invalid_email' ) );
			if ( $cred ) {
				$msg = trim( (string) SiteGuard_Options::get( 'msg_failed' ) );
				if ( '' === $msg && SiteGuard_Options::get( 'msg_generic' ) ) {
					$msg = __( 'The username or password you entered is incorrect.', 'siteguard-security' );
				}
				if ( '' !== $msg ) {
					return new WP_Error( 'sg_invalid', '<strong>' . esc_html__( 'Error:', 'siteguard-security' ) . '</strong> ' . esc_html( $msg ) );
				}
			}
		}
		return $user;
	}

	public static function on_failed( $username, $error = null ) {
		$code = is_wp_error( $error ) ? (string) $error->get_error_code() : 'authentication_failed';
		if ( in_array( $code, array( 'sg_blacklisted', 'sg_locked' ), true ) ) {
			self::log( 'blocked', $username, $code );
			return;
		}
		if ( 'sg_captcha' === $code ) {
			self::log( 'captcha_fail', $username );
			return;
		}
		if ( 0 === strpos( $code, 'sg_2fa' ) || in_array( $code, array( 'empty_username', 'empty_password' ), true ) ) {
			return; // Password was right (2FA refusal, logged elsewhere) or nothing was tried.
		}
		if ( in_array( $code, self::CREDENTIAL_CODES, true ) ) {
			self::record_failure( $username );
			return;
		}
		// Another plugin refused the login for its own reason: log it, do not count it.
		self::log( 'failed', $username, 'Refused by another plugin: ' . $code );
	}

	public static function on_success( $user_login, $user = null ) {
		global $wpdb;
		$wpdb->update( SiteGuard_Install::table_ips(), array( 'fails' => 0 ), array( 'ip' => SiteGuard_IP::current() ), array( '%d' ), array( '%s' ) );
		self::log( 'success', $user_login );
	}

	public static function on_app_password_failed( $error ) {
		$code = is_wp_error( $error ) ? $error->get_error_code() : '';
		if ( in_array( $code, array( 'invalid_username', 'invalid_email', 'incorrect_password' ), true ) ) {
			$user = isset( $_SERVER['PHP_AUTH_USER'] ) ? sanitize_user( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) ) : '';
			self::record_failure( $user, 'failed' );
		}
	}

	/** Locked / blacklisted IPs cannot use application passwords either. */
	public static function app_password_gate( $is_api ) {
		if ( $is_api && ( SiteGuard_IP::is_blacklisted() || self::locked_for() ) ) {
			return false;
		}
		return $is_api;
	}

	public static function login_errors( $errors ) {
		if ( ! self::$failed_this_request || ! SiteGuard_Options::get( 'bf_enabled' ) || SiteGuard_IP::is_whitelisted() ) {
			return $errors;
		}
		$left = self::locked_for();
		if ( $left ) {
			return '<strong>' . esc_html__( 'Error:', 'siteguard-security' ) . '</strong> ' . self::locked_message( $left );
		}
		$tpl = trim( self::msg( 'msg_attempts_left' ) );
		if ( '' !== $tpl ) {
			$errors .= '<br>' . esc_html( str_replace( '%d', (string) self::attempts_left(), $tpl ) );
		}
		return $errors;
	}

	/** Replace wp-login.php with a block page for blacklisted / locked IPs. */
	public static function blocked_screen() {
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : 'login'; // phpcs:ignore
		if ( in_array( $action, array( 'logout', 'postpass', 'confirmaction', 'rp', 'resetpass' ), true ) ) {
			return;
		}
		$msg = '';
		if ( SiteGuard_IP::is_blacklisted() ) {
			$msg = esc_html( self::msg( 'msg_blacklisted' ) );
		} else {
			$left = self::locked_for();
			if ( $left ) {
				$msg = self::locked_message( $left );
			}
		}
		if ( '' === $msg ) {
			return;
		}
		if ( 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) && isset( $_POST['log'] ) ) { // phpcs:ignore
			self::log( 'blocked', sanitize_user( wp_unslash( $_POST['log'] ) ), SiteGuard_IP::is_blacklisted() ? 'blacklisted' : 'locked' ); // phpcs:ignore
		}
		nocache_headers();
		wp_die(
			'<h1>' . esc_html__( 'Access blocked', 'siteguard-security' ) . '</h1><p>' . $msg . '</p><p><small>IP: ' . esc_html( SiteGuard_IP::current() ) . '</small></p>',
			esc_html__( 'Access blocked', 'siteguard-security' ),
			array( 'response' => 403 )
		);
	}
}
