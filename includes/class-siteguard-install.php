<?php
defined( 'ABSPATH' ) || exit;

/**
 * Per-site tables:
 *  {prefix}siteguard_ips  – live brute-force state per IP.
 *  {prefix}siteguard_log  – history of login events.
 * Multisite: every site gets its own tables + cron (created lazily on first load, or at
 * network activation / new-site creation).
 */
class SiteGuard_Install {

	const CRON_HOOK = 'siteguard_daily';

	private static $ok = null;

	public static function init() {
		self::maybe_upgrade();
		add_action( self::CRON_HOOK, array( __CLASS__, 'prune_logs' ) );
		add_action( 'wp_initialize_site', array( __CLASS__, 'new_site' ), 200 );
		// Self-heal the schedule (network activation, cron table wiped, migrations).
		if ( self::tables_ok() && ! wp_next_scheduled( self::CRON_HOOK ) && ! wp_installing() ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	public static function table_ips() {
		global $wpdb;
		return $wpdb->prefix . 'siteguard_ips';
	}

	public static function table_log() {
		global $wpdb;
		return $wpdb->prefix . 'siteguard_log';
	}

	public static function activate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			$sites = get_sites( array( 'fields' => 'ids', 'number' => 500 ) );
			foreach ( $sites as $id ) {
				switch_to_blog( $id );
				self::activate_site();
				restore_current_blog();
			}
			return;
		}
		self::activate_site();
	}

	private static function activate_site() {
		self::create_tables();
		if ( false === get_option( SiteGuard_Options::KEY ) ) {
			add_option( SiteGuard_Options::KEY, SiteGuard_Options::defaults(), '', true );
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	public static function new_site( $site ) {
		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( is_object( $site ) && isset( $site->blog_id ) && is_plugin_active_for_network( plugin_basename( SITEGUARD_FILE ) ) ) {
			switch_to_blog( (int) $site->blog_id );
			self::activate_site();
			restore_current_blog();
		}
	}

	public static function deactivate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			foreach ( get_sites( array( 'fields' => 'ids', 'number' => 500 ) ) as $id ) {
				switch_to_blog( $id );
				wp_clear_scheduled_hook( self::CRON_HOOK );
				restore_current_blog();
			}
			return;
		}
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function maybe_upgrade() {
		if ( get_option( 'siteguard_db_version' ) !== SITEGUARD_DB_VERSION ) {
			// Throttle retries when the DB user cannot create tables.
			if ( get_transient( 'siteguard_db_retry' ) ) {
				return;
			}
			if ( ! self::create_tables() ) {
				set_transient( 'siteguard_db_retry', 1, 5 * MINUTE_IN_SECONDS );
			}
		}
	}

	/** True when the schema is in place for the current site. */
	public static function tables_ok() {
		if ( null === self::$ok || is_multisite() ) {
			self::$ok = get_option( 'siteguard_db_version' ) === SITEGUARD_DB_VERSION;
		}
		return self::$ok;
	}

	public static function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$ips     = self::table_ips();
		$log     = self::table_log();

		$suppress = $wpdb->suppress_errors( true );
		dbDelta( "CREATE TABLE {$ips} (
  ip varchar(45) NOT NULL,
  username varchar(190) NOT NULL DEFAULT '',
  fails int(10) unsigned NOT NULL DEFAULT 0,
  lockouts int(10) unsigned NOT NULL DEFAULT 0,
  last_fail int(10) unsigned NOT NULL DEFAULT 0,
  locked_until int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (ip),
  KEY locked_until (locked_until)
) {$charset};" );

		dbDelta( "CREATE TABLE {$log} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  ip varchar(45) NOT NULL,
  username varchar(190) NOT NULL DEFAULT '',
  event varchar(20) NOT NULL,
  detail varchar(255) NOT NULL DEFAULT '',
  url varchar(255) NOT NULL DEFAULT '',
  created int(10) unsigned NOT NULL,
  PRIMARY KEY  (id),
  KEY created (created),
  KEY ip (ip)
) {$charset};" );
		$wpdb->suppress_errors( $suppress );

		$ok = self::table_exists( $ips ) && self::table_exists( $log );
		if ( $ok ) {
			update_option( 'siteguard_db_version', SITEGUARD_DB_VERSION, true );
			delete_transient( 'siteguard_db_retry' );
		}
		self::$ok = $ok;
		return $ok;
	}

	public static function table_exists( $table ) {
		global $wpdb;
		return $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
	}

	/** Daily: prune old logs and stale IP rows in bounded batches. */
	public static function prune_logs() {
		global $wpdb;
		if ( ! self::tables_ok() ) {
			return;
		}
		$days   = max( 1, (int) SiteGuard_Options::get( 'log_days' ) );
		$cutoff = time() - $days * DAY_IN_SECONDS;
		for ( $i = 0; $i < 50; $i++ ) {
			$n = $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table_log() . ' WHERE created < %d LIMIT 5000', $cutoff ) ); // phpcs:ignore
			if ( ! $n || $n < 5000 ) {
				break;
			}
		}
		$reset = max( 1, (int) SiteGuard_Options::get( 'reset_hours' ) ) * HOUR_IN_SECONDS;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table_ips() . ' WHERE locked_until < %d AND last_fail < %d LIMIT 50000', time(), time() - max( $reset, DAY_IN_SECONDS ) ) ); // phpcs:ignore
	}
}
