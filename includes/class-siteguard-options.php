<?php
defined( 'ABSPATH' ) || exit;

/**
 * Single per-site option array `siteguard_options` with defaults.
 */
class SiteGuard_Options {

	const KEY = 'siteguard_options';

	/** @var array<int,array> cache keyed by blog id (multisite switch_to_blog safe). */
	private static $cache = array();

	public static function init() {
		add_action( 'switch_blog', array( __CLASS__, 'flush' ) );
	}

	public static function flush() {
		self::$cache = array();
		if ( class_exists( 'SiteGuard_IP' ) ) {
			SiteGuard_IP::flush();
		}
	}

	public static function defaults() {
		return array(
			// Brute force.
			'bf_enabled'             => 1,
			'max_retries'            => 3,
			'lockout_minutes'        => 15,
			'max_lockouts'           => 5,
			'extended_hours'         => 24,
			'reset_hours'            => 6,
			'notify_admin'           => 0,
			'notify_after'           => 3,
			'ip_method'              => 'REMOTE_ADDR',
			'trusted_proxies'        => '',
			'log_days'               => 30,
			// Messages ('' = WordPress default).
			'msg_generic'            => 0,
			'msg_failed'             => '',
			'msg_attempts_left'      => '%d attempt(s) left before a temporary lockout.',
			'msg_locked'             => 'Too many failed login attempts. Please try again in %s.',
			'msg_blacklisted'        => 'Your IP address has been blocked from logging in.',
			// IP lists.
			'blacklist'              => '',
			'whitelist'              => '',
			// CAPTCHA.
			'captcha_provider'       => 'none',
			'captcha_site_key'       => '',
			'captcha_secret_key'     => '',
			'captcha_v3_score'       => 0.5,
			'captcha_login'          => 1,
			'captcha_register'       => 1,
			'captcha_lostpass'       => 1,
			'captcha_comments'       => 0,
			'captcha_woocommerce'    => 1,
			'captcha_skip_logged_in' => 1,
			// Two-factor.
			'tfa_enabled'            => 1,
			'tfa_methods'            => array( 'totp', 'email' ),
			'tfa_force_roles'        => array(),
			'tfa_xmlrpc_block'       => 1,
		);
	}

	public static function all() {
		$blog = function_exists( 'get_current_blog_id' ) ? get_current_blog_id() : 0;
		if ( ! isset( self::$cache[ $blog ] ) ) {
			$saved                = get_option( self::KEY, array() );
			self::$cache[ $blog ] = wp_parse_args( is_array( $saved ) ? $saved : array(), self::defaults() );
		}
		return self::$cache[ $blog ];
	}

	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	public static function update( array $values ) {
		$saved = get_option( self::KEY, array() );
		$saved = is_array( $saved ) ? $saved : array();
		update_option( self::KEY, array_merge( self::defaults(), $saved, $values ), true );
		self::flush();
	}
}
