<?php
// Remove all SiteGuard data when the plugin is deleted from wp-admin.
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

function siteguard_security_uninstall_site() {
	global $wpdb;
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}siteguard_ips" ); // phpcs:ignore
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}siteguard_log" ); // phpcs:ignore
	delete_option( 'siteguard_options' );
	delete_option( 'siteguard_db_version' );
	delete_transient( 'siteguard_db_retry' );
	wp_clear_scheduled_hook( 'siteguard_daily' );
}

if ( is_multisite() ) {
	$siteguard_offset = 0;
	do {
		$siteguard_ids = get_sites( array( 'fields' => 'ids', 'number' => 100, 'offset' => $siteguard_offset ) );
		foreach ( $siteguard_ids as $siteguard_id ) {
			switch_to_blog( $siteguard_id );
			siteguard_security_uninstall_site();
			restore_current_blog();
		}
		$siteguard_offset += 100;
	} while ( count( $siteguard_ids ) === 100 );
} else {
	siteguard_security_uninstall_site();
}

// Per-user 2FA data (shared by all sites) and network-level options.
global $wpdb;
foreach ( array( '_sg_tfa_method', '_sg_totp_secret', '_sg_totp_pending', '_sg_totp_last_step', '_sg_backup_code', '_sg_2fa_fails' ) as $siteguard_key ) {
	delete_metadata( 'user', 0, $siteguard_key, '', true );
}
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( '_sg_chal_' ) . '%' ) );
delete_site_option( 'siteguard_github_token' );
delete_site_transient( 'siteguard_update_check' );
