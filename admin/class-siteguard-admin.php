<?php
defined( 'ABSPATH' ) || exit;

/**
 * Admin screens: Dashboard, Brute Force, IP Lists, Messages, CAPTCHA, Two-Factor, Logs.
 */
class SiteGuard_Admin {

	const SLUG = 'siteguard';
	const CAP  = 'manage_options';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_siteguard_save', array( __CLASS__, 'save' ) );
		add_action( 'admin_post_siteguard_action', array( __CLASS__, 'action' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( SITEGUARD_FILE ), array( __CLASS__, 'links' ) );
		add_action( 'admin_notices', array( __CLASS__, 'conflict_notice' ) );
	}

	/** Other plugins that also run a login 2FA / lockout step. */
	public static function conflicts() {
		$found = array();
		$map   = array(
			'Two_Factor_Core'         => 'Two Factor',
			'wordfence'               => 'Wordfence (if its 2FA / login security is on)',
			'LOGINIZER_VERSION'       => 'Loginizer',
			'Limit_Login_Attempts'    => 'Limit Login Attempts Reloaded',
			'WP_2FA\\WP2FA'           => 'WP 2FA',
			'ITSEC_Core'              => 'Solid Security / iThemes Security',
			'AIO_WP_Security'         => 'All In One WP Security',
			'MiniOrange_2_Factor'     => 'miniOrange 2FA',
		);
		foreach ( $map as $symbol => $name ) {
			if ( class_exists( $symbol ) || defined( $symbol ) ) {
				$found[] = $name;
			}
		}
		return $found;
	}

	public static function conflict_notice() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || ( 'plugins' !== $screen->id && false === strpos( (string) $screen->id, self::SLUG ) ) ) {
			return;
		}
		$c = self::conflicts();
		if ( $c ) {
			echo '<div class="notice notice-warning"><p><strong>SiteGuard:</strong> ' . esc_html(
				/* translators: plugin names */
				sprintf( __( 'Another login-security plugin is active (%s). Running two lockout/2FA systems at once causes double prompts or lockouts. Turn off the overlapping feature in one of them.', 'siteguard-security' ), implode( ', ', $c ) )
			) . '</p></div>';
		}
	}

	public static function tabs() {
		return array(
			'dashboard' => __( 'Dashboard', 'siteguard-security' ),
			'bruteforce' => __( 'Brute Force', 'siteguard-security' ),
			'iplists'   => __( 'IP Lists', 'siteguard-security' ),
			'messages'  => __( 'Messages', 'siteguard-security' ),
			'captcha'   => __( 'CAPTCHA', 'siteguard-security' ),
			'twofactor' => __( 'Two-Factor', 'siteguard-security' ),
			'logs'      => __( 'Login Logs', 'siteguard-security' ),
			'updates'   => __( 'Updates', 'siteguard-security' ),
		);
	}

	public static function menu() {
		add_menu_page( 'SiteGuard Security', 'SiteGuard', self::CAP, self::SLUG, array( __CLASS__, 'page' ), 'dashicons-shield', 80 );
	}

	public static function links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ) . '">' . esc_html__( 'Settings', 'siteguard-security' ) . '</a>' );
		return $links;
	}

	private static function url( $tab, $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::SLUG, 'tab' => $tab ), $args ), admin_url( 'admin.php' ) );
	}

	/* ---------------- page ---------------- */

	public static function page() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$tabs = self::tabs();
		$tab  = isset( $_GET['tab'] ) && isset( $tabs[ $_GET['tab'] ] ) ? sanitize_key( $_GET['tab'] ) : 'dashboard'; // phpcs:ignore
		?>
		<div class="wrap siteguard">
			<h1><span class="dashicons dashicons-shield" style="font-size:28px;width:28px;height:28px;margin-right:6px"></span>SiteGuard Security</h1>
			<?php self::notices(); ?>
			<nav class="nav-tab-wrapper">
				<?php foreach ( $tabs as $k => $label ) : ?>
					<a href="<?php echo esc_url( self::url( $k ) ); ?>" class="nav-tab <?php echo $tab === $k ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</nav>
			<style>
				.siteguard .sg-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin:20px 0}
				.siteguard .sg-card{background:#fff;border:1px solid #dcdcde;border-radius:4px;padding:16px}
				.siteguard .sg-card b{display:block;font-size:26px;line-height:1.2;margin-bottom:4px}
				.siteguard .sg-pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;background:#f0f0f1}
				.siteguard .sg-ok{background:#d1f0d8;color:#00591a}.siteguard .sg-bad{background:#fbe0e0;color:#8a1f1f}.siteguard .sg-warn{background:#fcf0d0;color:#6b4c00}
				.siteguard textarea.code{width:100%;max-width:520px}
			</style>
			<?php
			if ( 'updates' !== $tab && ! SiteGuard_Install::tables_ok() ) {
				echo '<div class="notice notice-error"><p>' . esc_html__( 'SiteGuard could not create its database tables, so login protection is currently OFF. The database user needs CREATE TABLE permission.', 'siteguard-security' ) . ' <a class="button" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=siteguard_action&do=repair' ), 'siteguard_action' ) ) . '">' . esc_html__( 'Try again', 'siteguard-security' ) . '</a></p></div>';
				if ( 'dashboard' === $tab || 'logs' === $tab ) {
					echo '</div>';
					return;
				}
			}
			if ( defined( 'SITEGUARD_DISABLE' ) && SITEGUARD_DISABLE ) {
				echo '<div class="notice notice-warning"><p>' . esc_html__( 'SITEGUARD_DISABLE is set in wp-config.php: all login protection is OFF.', 'siteguard-security' ) . '</p></div>';
			}
			$method = 'tab_' . $tab;
			self::$method();
			?>
		</div>
		<?php
	}

	private static function notices() {
		$map = array(
			'saved'    => array( 'success', __( 'Settings saved.', 'siteguard-security' ) ),
			'unlocked' => array( 'success', __( 'IP unlocked.', 'siteguard-security' ) ),
			'unlockall' => array( 'success', __( 'All lockouts cleared.', 'siteguard-security' ) ),
			'cleared'  => array( 'success', __( 'Logs cleared.', 'siteguard-security' ) ),
			'blacklisted' => array( 'success', __( 'IP added to blacklist.', 'siteguard-security' ) ),
			'checked'  => array( 'success', __( 'Checked GitHub for updates.', 'siteguard-security' ) ),
			'token'    => array( 'success', __( 'Update token saved.', 'siteguard-security' ) ),
			'selfblock' => array( 'error', __( 'Your own IP is in the blacklist. It was saved, but add your IP to the whitelist or you will be locked out on next login.', 'siteguard-security' ) ),
		);
		$k = isset( $_GET['sg_msg'] ) ? sanitize_key( $_GET['sg_msg'] ) : ''; // phpcs:ignore
		if ( isset( $map[ $k ] ) ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $map[ $k ][0] ), esc_html( $map[ $k ][1] ) );
		}
	}

	private static function form_open( $tab ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="siteguard_save"><input type="hidden" name="tab" value="' . esc_attr( $tab ) . '">';
		wp_nonce_field( 'siteguard_save_' . $tab );
		echo '<table class="form-table" role="presentation">';
	}

	private static function form_close() {
		echo '</table>';
		submit_button();
		echo '</form>';
	}

	private static function row( $label, $html, $desc = '' ) {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . $html; // phpcs:ignore
		if ( $desc ) {
			echo '<p class="description">' . wp_kses_post( $desc ) . '</p>';
		}
		echo '</td></tr>';
	}

	private static function checkbox( $key, $label ) {
		return '<label><input type="checkbox" name="sg[' . esc_attr( $key ) . ']" value="1" ' . checked( SiteGuard_Options::get( $key ), 1, false ) . '> ' . esc_html( $label ) . '</label>';
	}

	private static function number( $key, $min = 1, $max = 100000, $suffix = '', $step = '1' ) {
		return '<input type="number" class="small-text" name="sg[' . esc_attr( $key ) . ']" value="' . esc_attr( SiteGuard_Options::get( $key ) ) . '" min="' . esc_attr( $min ) . '" max="' . esc_attr( $max ) . '" step="' . esc_attr( $step ) . '"> ' . esc_html( $suffix );
	}

	private static function text( $key, $class = 'regular-text', $type = 'text' ) {
		return '<input type="' . esc_attr( $type ) . '" class="' . esc_attr( $class ) . '" name="sg[' . esc_attr( $key ) . ']" value="' . esc_attr( SiteGuard_Options::get( $key ) ) . '" autocomplete="off">';
	}

	/* ---------------- tabs ---------------- */

	private static function tab_dashboard() {
		global $wpdb;
		$log  = SiteGuard_Install::table_log();
		$ips  = SiteGuard_Install::table_ips();
		$day  = time() - DAY_IN_SECONDS;
		$fail = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$log} WHERE event IN ('failed','2fa_fail') AND created > %d", $day ) ); // phpcs:ignore
		$ok   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$log} WHERE event = 'success' AND created > %d", $day ) ); // phpcs:ignore
		$lock = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$log} WHERE event = 'lockout' AND created > %d", $day ) ); // phpcs:ignore
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$ips} WHERE locked_until > %d ORDER BY locked_until DESC LIMIT 200", time() ) ); // phpcs:ignore
		$nlck = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$ips} WHERE locked_until > %d", time() ) ); // phpcs:ignore
		$o    = SiteGuard_Options::all();
		$me   = SiteGuard_IP::current();
		$pill = function ( $on, $txt_on = 'On', $txt_off = 'Off' ) {
			return '<span class="sg-pill ' . ( $on ? 'sg-ok' : 'sg-warn' ) . '">' . esc_html( $on ? $txt_on : $txt_off ) . '</span>';
		};
		?>
		<div class="sg-cards">
			<div class="sg-card"><b><?php echo (int) $fail; ?></b><?php esc_html_e( 'Failed logins (24h)', 'siteguard-security' ); ?></div>
			<div class="sg-card"><b><?php echo (int) $ok; ?></b><?php esc_html_e( 'Successful logins (24h)', 'siteguard-security' ); ?></div>
			<div class="sg-card"><b><?php echo (int) $lock; ?></b><?php esc_html_e( 'Lockouts (24h)', 'siteguard-security' ); ?></div>
			<div class="sg-card"><b><?php echo (int) $nlck; ?></b><?php esc_html_e( 'IPs locked right now', 'siteguard-security' ); ?></div>
		</div>
		<table class="widefat striped" style="max-width:720px">
			<tbody>
				<tr><td><?php esc_html_e( 'Your IP', 'siteguard-security' ); ?></td><td><code><?php echo esc_html( $me ); ?></code> <?php echo SiteGuard_IP::is_whitelisted( $me ) ? '<span class="sg-pill sg-ok">whitelisted</span>' : ''; ?> <span class="description">(<?php echo esc_html( $o['ip_method'] ); ?>)</span></td></tr>
				<tr><td><?php esc_html_e( 'Brute-force protection', 'siteguard-security' ); ?></td><td><?php echo $pill( $o['bf_enabled'] ); // phpcs:ignore ?> <?php echo esc_html( sprintf( '%d tries → %d min lockout; %d lockouts → %d h', $o['max_retries'], $o['lockout_minutes'], $o['max_lockouts'], $o['extended_hours'] ) ); ?></td></tr>
				<tr><td>CAPTCHA</td><td><?php echo $pill( SiteGuard_Captcha::active(), SiteGuard_Captcha::PROVIDERS[ $o['captcha_provider'] ] ?? 'On', 'Off' ); // phpcs:ignore ?></td></tr>
				<tr><td><?php esc_html_e( 'Two-factor', 'siteguard-security' ); ?></td><td><?php echo $pill( $o['tfa_enabled'] ); // phpcs:ignore ?> <?php echo $o['tfa_force_roles'] ? esc_html( 'Required for: ' . implode( ', ', $o['tfa_force_roles'] ) ) : ''; ?></td></tr>
				<tr><td><?php esc_html_e( 'Daily cleanup', 'siteguard-security' ); ?></td><td>
					<?php
					$next = wp_next_scheduled( SiteGuard_Install::CRON_HOOK );
					echo $next ? $pill( true, esc_html( sprintf( __( 'Next run %s', 'siteguard-security' ), wp_date( 'Y-m-d H:i', $next ) ) ) ) : $pill( false, '', __( 'Not scheduled', 'siteguard-security' ) ); // phpcs:ignore
					if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
						echo ' <span class="description">' . esc_html__( 'WP-Cron is disabled: make sure the server runs wp-cron.php on a schedule.', 'siteguard-security' ) . '</span>';
					}
					?>
					<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=siteguard_action&do=prune' ), 'siteguard_action' ) ); ?>"><?php esc_html_e( 'Run now', 'siteguard-security' ); ?></a>
				</td></tr>
				<tr><td><?php esc_html_e( 'Emergency off switch', 'siteguard-security' ); ?></td><td><code>define( 'SITEGUARD_DISABLE', true );</code> <?php esc_html_e( 'in wp-config.php', 'siteguard-security' ); ?></td></tr>
			</tbody>
		</table>

		<h2><?php esc_html_e( 'Currently locked IPs', 'siteguard-security' ); ?></h2>
		<?php if ( ! $rows ) : ?>
			<p><?php esc_html_e( 'No IP is locked out.', 'siteguard-security' ); ?></p>
		<?php else : ?>
			<p><a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=siteguard_action&do=unlockall' ), 'siteguard_action' ) ); ?>"><?php esc_html_e( 'Unlock all', 'siteguard-security' ); ?></a></p>
			<table class="widefat striped">
				<thead><tr><th>IP</th><th><?php esc_html_e( 'Last username', 'siteguard-security' ); ?></th><th><?php esc_html_e( 'Lockouts', 'siteguard-security' ); ?></th><th><?php esc_html_e( 'Unlocks in', 'siteguard-security' ); ?></th><th></th></tr></thead>
				<tbody>
				<?php foreach ( $rows as $r ) : ?>
					<tr>
						<td><code><?php echo esc_html( $r->ip ); ?></code></td>
						<td><?php echo esc_html( $r->username ); ?></td>
						<td><?php echo (int) $r->lockouts; ?></td>
						<td><?php echo esc_html( human_time_diff( time(), (int) $r->locked_until ) ); ?></td>
						<td>
							<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=siteguard_action&do=unlock&ip=' . rawurlencode( $r->ip ) ), 'siteguard_action' ) ); ?>"><?php esc_html_e( 'Unlock', 'siteguard-security' ); ?></a> |
							<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=siteguard_action&do=blacklist&ip=' . rawurlencode( $r->ip ) ), 'siteguard_action' ) ); ?>"><?php esc_html_e( 'Blacklist', 'siteguard-security' ); ?></a>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif;
	}

	private static function tab_bruteforce() {
		self::form_open( 'bruteforce' );
		self::row( __( 'Protection', 'siteguard-security' ), self::checkbox( 'bf_enabled', __( 'Enable brute-force lockout', 'siteguard-security' ) ) );
		self::row( __( 'Max retries', 'siteguard-security' ), self::number( 'max_retries', 1, 100, __( 'failed attempts before a lockout', 'siteguard-security' ) ) );
		self::row( __( 'Lockout time', 'siteguard-security' ), self::number( 'lockout_minutes', 1, 10080, __( 'minutes', 'siteguard-security' ) ) );
		self::row( __( 'Max lockouts', 'siteguard-security' ), self::number( 'max_lockouts', 1, 100, __( 'lockouts before the extended lockout', 'siteguard-security' ) ) );
		self::row( __( 'Extended lockout', 'siteguard-security' ), self::number( 'extended_hours', 1, 8760, __( 'hours', 'siteguard-security' ) ) );
		self::row( __( 'Reset retries after', 'siteguard-security' ), self::number( 'reset_hours', 1, 8760, __( 'hours without a failed attempt', 'siteguard-security' ) ) );
		self::row( __( 'Email notification', 'siteguard-security' ), self::checkbox( 'notify_admin', __( 'Email the site admin when an IP gets locked out', 'siteguard-security' ) ) . '<br><br>' . self::number( 'notify_after', 1, 100, __( 'only from this lockout count onward', 'siteguard-security' ) ) );
		$sel = '<select name="sg[ip_method]">';
		foreach ( SiteGuard_IP::METHODS as $k => $l ) {
			$v    = isset( $_SERVER[ $k ] ) ? ' — ' . sanitize_text_field( wp_unslash( $_SERVER[ $k ] ) ) : ' — (empty)';
			$sel .= '<option value="' . esc_attr( $k ) . '" ' . selected( SiteGuard_Options::get( 'ip_method' ), $k, false ) . '>' . esc_html( $l . $v ) . '</option>';
		}
		$sel .= '</select>';
		self::row( __( 'Detect IP from', 'siteguard-security' ), $sel, __( 'Only change this when the site is behind Cloudflare or a proxy. Headers are only believed when the request really comes from Cloudflare (CF-Connecting-IP) or from a trusted proxy below, so they cannot be faked by visitors.', 'siteguard-security' ) );
		self::row( __( 'Trusted proxies', 'siteguard-security' ), '<textarea name="sg[trusted_proxies]" rows="4" class="code" placeholder="10.0.0.0/8">' . esc_textarea( SiteGuard_Options::get( 'trusted_proxies' ) ) . '</textarea>', __( 'IPs / CIDR of your own load balancer or reverse proxy (one per line). Empty = private and loopback networks. Your server sees you as: ', 'siteguard-security' ) . '<code>' . esc_html( isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '-' ) . '</code>' );
		self::row( __( 'Keep logs for', 'siteguard-security' ), self::number( 'log_days', 1, 3650, __( 'days', 'siteguard-security' ) ) );
		self::form_close();
	}

	private static function tab_iplists() {
		self::form_open( 'iplists' );
		$help = __( 'One per line. Formats: <code>203.0.113.5</code>, range <code>203.0.113.1 - 203.0.113.50</code>, CIDR <code>203.0.113.0/24</code>, IPv6 <code>2001:db8::/32</code>. Text after <code>#</code> is a comment.', 'siteguard-security' );
		self::row( __( 'Whitelist', 'siteguard-security' ), '<textarea name="sg[whitelist]" rows="8" class="code">' . esc_textarea( SiteGuard_Options::get( 'whitelist' ) ) . '</textarea>', __( 'Never locked out, never asked for CAPTCHA. Your IP: ', 'siteguard-security' ) . '<code>' . esc_html( SiteGuard_IP::current() ) . '</code><br>' . $help );
		self::row( __( 'Blacklist', 'siteguard-security' ), '<textarea name="sg[blacklist]" rows="8" class="code">' . esc_textarea( SiteGuard_Options::get( 'blacklist' ) ) . '</textarea>', __( 'Cannot open the login page at all. Whitelist wins over blacklist.', 'siteguard-security' ) . '<br>' . $help );
		self::form_close();
	}

	private static function tab_messages() {
		self::form_open( 'messages' );
		self::row( __( 'Hide account hints', 'siteguard-security' ), self::checkbox( 'msg_generic', __( 'Show one generic error instead of "unknown username" / "wrong password for user X" (stops username discovery)', 'siteguard-security' ) ) );
		self::row( __( 'Failed login', 'siteguard-security' ), self::text( 'msg_failed', 'large-text' ), __( 'Custom text for a wrong username/password. Empty = WordPress default (or the generic one above).', 'siteguard-security' ) );
		self::row( __( 'Attempts left', 'siteguard-security' ), self::text( 'msg_attempts_left', 'large-text' ), __( '<code>%d</code> = attempts left. Empty = do not show.', 'siteguard-security' ) );
		self::row( __( 'Locked out', 'siteguard-security' ), self::text( 'msg_locked', 'large-text' ), __( '<code>%s</code> = time remaining, e.g. "15 mins".', 'siteguard-security' ) );
		self::row( __( 'Blacklisted', 'siteguard-security' ), self::text( 'msg_blacklisted', 'large-text' ) );
		self::form_close();
	}

	private static function tab_captcha() {
		self::form_open( 'captcha' );
		$sel = '<select name="sg[captcha_provider]">';
		foreach ( SiteGuard_Captcha::PROVIDERS as $k => $l ) {
			$sel .= '<option value="' . esc_attr( $k ) . '" ' . selected( SiteGuard_Options::get( 'captcha_provider' ), $k, false ) . '>' . esc_html( $l ) . '</option>';
		}
		$sel .= '</select>';
		self::row( __( 'Provider', 'siteguard-security' ), $sel, __( 'Keys: <a href="https://www.google.com/recaptcha/admin" target="_blank" rel="noopener">Google reCAPTCHA admin</a> (pick the matching v2 checkbox / v3 type) or <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" rel="noopener">Cloudflare Turnstile</a>. CAPTCHA stays off until both keys are filled.', 'siteguard-security' ) );
		self::row( __( 'Site key', 'siteguard-security' ), self::text( 'captcha_site_key' ) );
		self::row( __( 'Secret key', 'siteguard-security' ), self::text( 'captcha_secret_key', 'regular-text', 'password' ) );
		self::row( __( 'v3 minimum score', 'siteguard-security' ), self::number( 'captcha_v3_score', 0, 1, __( '0.0 (bot) – 1.0 (human); 0.5 recommended', 'siteguard-security' ), '0.1' ) );
		self::row(
			__( 'Show on', 'siteguard-security' ),
			self::checkbox( 'captcha_login', __( 'Login form', 'siteguard-security' ) ) . '<br>' .
			self::checkbox( 'captcha_register', __( 'Registration form', 'siteguard-security' ) ) . '<br>' .
			self::checkbox( 'captcha_lostpass', __( 'Lost password form', 'siteguard-security' ) ) . '<br>' .
			self::checkbox( 'captcha_comments', __( 'Comment form', 'siteguard-security' ) ) . '<br>' .
			self::checkbox( 'captcha_woocommerce', __( 'WooCommerce login, register, lost password and checkout login', 'siteguard-security' ) ) . '<br>' .
			self::checkbox( 'captcha_skip_logged_in', __( 'Skip comment CAPTCHA for logged-in users', 'siteguard-security' ) )
		);
		self::form_close();
		echo '<p class="description">' . esc_html__( 'Locked out by a bad key? Add your IP to the whitelist (skips CAPTCHA) or use the SITEGUARD_DISABLE switch.', 'siteguard-security' ) . '</p>';
	}

	private static function tab_twofactor() {
		self::form_open( 'twofactor' );
		self::row( __( 'Two-factor login', 'siteguard-security' ), self::checkbox( 'tfa_enabled', __( 'Enable two-factor authentication', 'siteguard-security' ) ), __( 'Each user sets up their method under <a href="profile.php#siteguard-2fa">Users → Profile</a>.', 'siteguard-security' ) );
		$m  = (array) SiteGuard_Options::get( 'tfa_methods' );
		$cb = '<label><input type="checkbox" name="sg[tfa_methods][]" value="totp" ' . checked( in_array( 'totp', $m, true ), true, false ) . '> ' . esc_html__( 'Authenticator app (Google Authenticator, Authy, Microsoft Authenticator…)', 'siteguard-security' ) . '</label><br>'
			. '<label><input type="checkbox" name="sg[tfa_methods][]" value="email" ' . checked( in_array( 'email', $m, true ), true, false ) . '> ' . esc_html__( 'Email code', 'siteguard-security' ) . '</label>';
		self::row( __( 'Allowed methods', 'siteguard-security' ), $cb, __( 'Email code needs working site email (SMTP). Test it before forcing it on admins.', 'siteguard-security' ) );
		$roles = (array) SiteGuard_Options::get( 'tfa_force_roles' );
		$rc    = '';
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			$rc .= '<label style="display:inline-block;min-width:170px"><input type="checkbox" name="sg[tfa_force_roles][]" value="' . esc_attr( $slug ) . '" ' . checked( in_array( $slug, $roles, true ), true, false ) . '> ' . esc_html( translate_user_role( $name ) ) . '</label> ';
		}
		self::row( __( 'Require for roles', 'siteguard-security' ), $rc, __( 'Users in these roles cannot log in without a second factor. Without their own set-up they get an email code, or (when email is not allowed) must set up an authenticator app during login. On multisite, ticking Administrator also covers super admins.', 'siteguard-security' ) );
		self::row( __( 'XML-RPC', 'siteguard-security' ), self::checkbox( 'tfa_xmlrpc_block', __( 'Block XML-RPC password logins for users with 2FA (recommended — XML-RPC cannot ask for a code)', 'siteguard-security' ) ), __( 'Application Passwords (Users → Profile) still work for apps and integrations.', 'siteguard-security' ) );
		self::form_close();

		global $wpdb;
		$users = $wpdb->get_results( $wpdb->prepare( "SELECT u.ID, u.user_login, m.meta_value AS method FROM {$wpdb->users} u JOIN {$wpdb->usermeta} m ON m.user_id = u.ID AND m.meta_key = %s JOIN {$wpdb->usermeta} c ON c.user_id = u.ID AND c.meta_key = %s WHERE m.meta_value <> '' ORDER BY u.user_login LIMIT 500", SiteGuard_TwoFactor::M_METHOD, $wpdb->get_blog_prefix() . 'capabilities' ) );
		echo '<h2>' . esc_html__( 'Users with 2FA set up', 'siteguard-security' ) . '</h2>';
		if ( ! $users ) {
			echo '<p>' . esc_html__( 'None yet.', 'siteguard-security' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped" style="max-width:600px"><thead><tr><th>' . esc_html__( 'User', 'siteguard-security' ) . '</th><th>' . esc_html__( 'Method', 'siteguard-security' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $users as $u ) {
			echo '<tr><td>' . esc_html( $u->user_login ) . '</td><td>' . esc_html( 'totp' === $u->method ? 'Authenticator app' : 'Email code' ) . '</td><td><a href="' . esc_url( get_edit_user_link( $u->ID ) . '#siteguard-2fa' ) . '">' . esc_html__( 'Manage / reset', 'siteguard-security' ) . '</a></td></tr>';
		}
		echo '</tbody></table>';
	}

	private static function tab_logs() {
		global $wpdb;
		$t      = SiteGuard_Install::table_log();
		$per    = 50;
		$paged  = max( 1, isset( $_GET['paged'] ) ? (int) $_GET['paged'] : 1 ); // phpcs:ignore
		$ev     = isset( $_GET['event'] ) ? sanitize_key( $_GET['event'] ) : ''; // phpcs:ignore
		$s      = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : ''; // phpcs:ignore
		$where  = array( '1=1' );
		$params = array();
		if ( $ev ) {
			$where[]  = 'event = %s';
			$params[] = $ev;
		}
		if ( '' !== $s ) {
			$where[]  = '(ip LIKE %s OR username LIKE %s)';
			$like     = '%' . $wpdb->esc_like( $s ) . '%';
			$params[] = $like;
			$params[] = $like;
		}
		$w     = implode( ' AND ', $where );
		$total = (int) $wpdb->get_var( $params ? $wpdb->prepare( "SELECT COUNT(*) FROM {$t} WHERE {$w}", $params ) : "SELECT COUNT(*) FROM {$t} WHERE {$w}" ); // phpcs:ignore
		$q     = "SELECT * FROM {$t} WHERE {$w} ORDER BY id DESC LIMIT %d OFFSET %d";
		$rows  = $wpdb->get_results( $wpdb->prepare( $q, array_merge( $params, array( $per, ( $paged - 1 ) * $per ) ) ) ); // phpcs:ignore

		$events = array( '' => 'All events', 'success' => 'Success', 'failed' => 'Failed', 'lockout' => 'Lockout', 'blocked' => 'Blocked', 'captcha_fail' => 'CAPTCHA failed', '2fa_fail' => '2FA failed', 'backup_code' => 'Backup code used', '2fa_reset' => '2FA reset', 'challenge' => '2FA challenge', 'email_fail' => 'Email failed', 'captcha_error' => 'CAPTCHA error' );
		$cls    = array( 'success' => 'sg-ok', 'failed' => 'sg-warn', '2fa_fail' => 'sg-warn', 'captcha_fail' => 'sg-warn', 'lockout' => 'sg-bad', 'blocked' => 'sg-bad', 'email_fail' => 'sg-bad', 'captcha_error' => 'sg-bad' );
		?>
		<form method="get" style="margin:16px 0">
			<input type="hidden" name="page" value="<?php echo esc_attr( self::SLUG ); ?>"><input type="hidden" name="tab" value="logs">
			<select name="event"><?php foreach ( $events as $k => $l ) { echo '<option value="' . esc_attr( $k ) . '" ' . selected( $ev, $k, false ) . '>' . esc_html( $l ) . '</option>'; } ?></select>
			<input type="search" name="s" value="<?php echo esc_attr( $s ); ?>" placeholder="IP / username">
			<button class="button"><?php esc_html_e( 'Filter', 'siteguard-security' ); ?></button>
			<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=siteguard_action&do=export' ), 'siteguard_action' ) ); ?>"><?php esc_html_e( 'Export CSV', 'siteguard-security' ); ?></a>
			<a class="button" style="color:#b32d2e" onclick="return confirm('Clear all logs?')" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=siteguard_action&do=clearlogs' ), 'siteguard_action' ) ); ?>"><?php esc_html_e( 'Clear logs', 'siteguard-security' ); ?></a>
		</form>
		<table class="widefat striped">
			<thead><tr><th><?php esc_html_e( 'Time', 'siteguard-security' ); ?></th><th>IP</th><th><?php esc_html_e( 'Username', 'siteguard-security' ); ?></th><th><?php esc_html_e( 'Event', 'siteguard-security' ); ?></th><th><?php esc_html_e( 'Detail', 'siteguard-security' ); ?></th><th>URL</th></tr></thead>
			<tbody>
			<?php if ( ! $rows ) : ?>
				<tr><td colspan="6"><?php esc_html_e( 'No log entries.', 'siteguard-security' ); ?></td></tr>
			<?php endif; ?>
			<?php foreach ( $rows as $r ) : ?>
				<tr>
					<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', (int) $r->created ) ); ?></td>
					<td><code><?php echo esc_html( $r->ip ); ?></code></td>
					<td><?php echo esc_html( $r->username ); ?></td>
					<td><span class="sg-pill <?php echo esc_attr( $cls[ $r->event ] ?? '' ); ?>"><?php echo esc_html( $events[ $r->event ] ?? $r->event ); ?></span></td>
					<td><?php echo esc_html( $r->detail ); ?></td>
					<td><small><?php echo esc_html( $r->url ); ?></small></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		$pages = (int) ceil( $total / $per );
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">' . paginate_links( array( 'base' => add_query_arg( 'paged', '%#%' ), 'format' => '', 'current' => $paged, 'total' => $pages ) ) . '</div></div>'; // phpcs:ignore
		}
	}

	private static function tab_updates() {
		$status = SiteGuard_Updater::status();
		$rel    = SiteGuard_Updater::latest_release();
		?>
		<table class="widefat striped" style="max-width:720px;margin-top:20px"><tbody>
			<tr><td><?php esc_html_e( 'Installed version', 'siteguard-security' ); ?></td><td><code><?php echo esc_html( SITEGUARD_VERSION ); ?></code></td></tr>
			<tr><td><?php esc_html_e( 'Latest release on GitHub', 'siteguard-security' ); ?></td><td>
				<?php
				if ( $rel ) {
					echo '<code>' . esc_html( $rel['version'] ) . '</code> ';
					echo SiteGuard_Updater::is_newer( $rel['version'] )
						? '<a class="button button-primary" href="' . esc_url( admin_url( 'plugins.php' ) ) . '">' . esc_html__( 'Update available — go to Plugins', 'siteguard-security' ) . '</a>'
						: '<span class="sg-pill sg-ok">' . esc_html__( 'Up to date', 'siteguard-security' ) . '</span>';
				} elseif ( ! empty( $status['error'] ) ) {
					echo '<span class="sg-pill sg-bad">' . esc_html( $status['error'] ) . '</span>';
				} else {
					esc_html_e( 'No published release yet.', 'siteguard-security' );
				}
				?>
			</td></tr>
			<tr><td><?php esc_html_e( 'Last checked', 'siteguard-security' ); ?></td><td><?php echo ! empty( $status['checked'] ) ? esc_html( wp_date( 'Y-m-d H:i', (int) $status['checked'] ) ) : '—'; ?>
				<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=siteguard_action&do=checkupdate' ), 'siteguard_action' ) ); ?>"><?php esc_html_e( 'Check now', 'siteguard-security' ); ?></a></td></tr>
		</tbody></table>
		<?php
		if ( SiteGuard_Updater::token_from_constant() ) {
			echo '<p>' . esc_html__( 'GitHub token is set by the SITEGUARD_GITHUB_TOKEN constant in wp-config.php.', 'siteguard-security' ) . '</p>';
			return;
		}
		if ( is_multisite() && ! current_user_can( 'manage_network_options' ) ) {
			return;
		}
		self::form_open( 'updates' );
		$has = '' !== SiteGuard_Updater::token();
		self::row(
			__( 'GitHub token', 'siteguard-security' ),
			'<input type="password" class="regular-text" name="sg[github_token]" value="" autocomplete="new-password" placeholder="' . esc_attr( $has ? __( '(saved — leave empty to keep)', 'siteguard-security' ) : 'github_pat_…' ) . '">'
			. ( $has ? '<br><label><input type="checkbox" name="sg[github_token_clear]" value="1"> ' . esc_html__( 'Remove saved token', 'siteguard-security' ) . '</label>' : '' ),
			__( 'The repository is private, so WordPress needs a read-only token to see releases. Create a fine-grained token on GitHub with access to this one repository and the permission <strong>Contents: Read-only</strong>. Or put <code>define( \'SITEGUARD_GITHUB_TOKEN\', \'…\' );</code> in wp-config.php.', 'siteguard-security' )
		);
		self::form_close();
	}

	/* ---------------- handlers ---------------- */

	public static function save() {
		$tab = isset( $_POST['tab'] ) ? sanitize_key( $_POST['tab'] ) : '';
		if ( ! current_user_can( self::CAP ) || ! check_admin_referer( 'siteguard_save_' . $tab ) ) {
			wp_die( 'Forbidden', 403 );
		}
		$in  = isset( $_POST['sg'] ) && is_array( $_POST['sg'] ) ? wp_unslash( $_POST['sg'] ) : array(); // phpcs:ignore
		$out = array();
		$int = function ( $k, $min, $max ) use ( $in, &$out ) {
			$out[ $k ] = min( $max, max( $min, (int) ( $in[ $k ] ?? $min ) ) );
		};
		$bool = function ( $k ) use ( $in, &$out ) {
			$out[ $k ] = empty( $in[ $k ] ) ? 0 : 1;
		};
		$msg = 'saved';

		switch ( $tab ) {
			case 'bruteforce':
				$bool( 'bf_enabled' );
				$bool( 'notify_admin' );
				$int( 'max_retries', 1, 100 );
				$int( 'lockout_minutes', 1, 10080 );
				$int( 'max_lockouts', 1, 100 );
				$int( 'extended_hours', 1, 8760 );
				$int( 'reset_hours', 1, 8760 );
				$int( 'notify_after', 1, 100 );
				$int( 'log_days', 1, 3650 );
				$out['ip_method']       = isset( SiteGuard_IP::METHODS[ $in['ip_method'] ?? '' ] ) ? $in['ip_method'] : 'REMOTE_ADDR';
				$out['trusted_proxies'] = implode( "\n", SiteGuard_IP::parse_list( $in['trusted_proxies'] ?? '' ) );
				break;
			case 'iplists':
				$out['whitelist'] = implode( "\n", SiteGuard_IP::parse_list( $in['whitelist'] ?? '' ) );
				$out['blacklist'] = implode( "\n", SiteGuard_IP::parse_list( $in['blacklist'] ?? '' ) );
				break;
			case 'messages':
				$bool( 'msg_generic' );
				foreach ( array( 'msg_failed', 'msg_attempts_left', 'msg_locked', 'msg_blacklisted' ) as $k ) {
					$out[ $k ] = sanitize_text_field( $in[ $k ] ?? '' );
				}
				break;
			case 'captcha':
				$out['captcha_provider']   = isset( SiteGuard_Captcha::PROVIDERS[ $in['captcha_provider'] ?? '' ] ) ? $in['captcha_provider'] : 'none';
				$out['captcha_site_key']   = sanitize_text_field( $in['captcha_site_key'] ?? '' );
				$out['captcha_secret_key'] = sanitize_text_field( $in['captcha_secret_key'] ?? '' );
				$out['captcha_v3_score']   = min( 1, max( 0, round( (float) ( $in['captcha_v3_score'] ?? 0.5 ), 1 ) ) );
				foreach ( array( 'captcha_login', 'captcha_register', 'captcha_lostpass', 'captcha_comments', 'captcha_woocommerce', 'captcha_skip_logged_in' ) as $k ) {
					$bool( $k );
				}
				break;
			case 'twofactor':
				$bool( 'tfa_enabled' );
				$bool( 'tfa_xmlrpc_block' );
				$out['tfa_methods']     = array_values( array_intersect( array( 'totp', 'email' ), (array) ( $in['tfa_methods'] ?? array() ) ) );
				if ( ! $out['tfa_methods'] ) {
					$out['tfa_methods'] = array( 'totp', 'email' );
				}
				$out['tfa_force_roles'] = array_values( array_intersect( array_keys( wp_roles()->get_names() ), (array) ( $in['tfa_force_roles'] ?? array() ) ) );
				break;
			case 'updates':
				if ( is_multisite() && ! current_user_can( 'manage_network_options' ) ) {
					wp_die( 'Forbidden', 403 );
				}
				if ( ! empty( $in['github_token_clear'] ) ) {
					delete_site_option( 'siteguard_github_token' );
				} elseif ( '' !== trim( (string) ( $in['github_token'] ?? '' ) ) ) {
					update_site_option( 'siteguard_github_token', preg_replace( '/[^A-Za-z0-9_]/', '', (string) $in['github_token'] ) );
				}
				SiteGuard_Updater::clear_cache();
				delete_site_transient( 'update_plugins' );
				wp_safe_redirect( self::url( 'updates', array( 'sg_msg' => 'token' ) ) );
				exit;
			default:
				wp_die( 'Unknown tab', 400 );
		}
		SiteGuard_Options::update( $out );
		if ( 'iplists' === $tab && SiteGuard_IP::is_blacklisted() ) {
			$msg = 'selfblock';
		}
		wp_safe_redirect( self::url( $tab, array( 'sg_msg' => $msg ) ) );
		exit;
	}

	public static function action() {
		if ( ! current_user_can( self::CAP ) || ! check_admin_referer( 'siteguard_action' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		global $wpdb;
		$do = isset( $_GET['do'] ) ? sanitize_key( $_GET['do'] ) : '';
		$ip = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
		switch ( $do ) {
			case 'unlock':
				if ( SiteGuard_IP::valid( $ip ) ) {
					SiteGuard_BruteForce::unlock( $ip );
				}
				$redirect = self::url( 'dashboard', array( 'sg_msg' => 'unlocked' ) );
				break;
			case 'unlockall':
				$wpdb->query( 'DELETE FROM ' . SiteGuard_Install::table_ips() ); // phpcs:ignore
				$redirect = self::url( 'dashboard', array( 'sg_msg' => 'unlockall' ) );
				break;
			case 'blacklist':
				if ( SiteGuard_IP::valid( $ip ) && $ip !== SiteGuard_IP::current() ) {
					$list = trim( SiteGuard_Options::get( 'blacklist' ) . "\n" . $ip );
					SiteGuard_Options::update( array( 'blacklist' => implode( "\n", SiteGuard_IP::parse_list( $list ) ) ) );
				}
				$redirect = self::url( 'dashboard', array( 'sg_msg' => 'blacklisted' ) );
				break;
			case 'prune':
				SiteGuard_Install::prune_logs();
				$redirect = self::url( 'dashboard', array( 'sg_msg' => 'saved' ) );
				break;
			case 'repair':
				delete_transient( 'siteguard_db_retry' );
				SiteGuard_Install::create_tables();
				$redirect = self::url( 'dashboard' );
				break;
			case 'checkupdate':
				SiteGuard_Updater::clear_cache();
				SiteGuard_Updater::latest_release( true );
				delete_site_transient( 'update_plugins' );
				$redirect = self::url( 'updates', array( 'sg_msg' => 'checked' ) );
				break;
				$wpdb->query( 'TRUNCATE TABLE ' . SiteGuard_Install::table_log() ); // phpcs:ignore
				$redirect = self::url( 'logs', array( 'sg_msg' => 'cleared' ) );
				break;
			case 'export':
				nocache_headers();
				header( 'Content-Type: text/csv; charset=utf-8' );
				header( 'Content-Disposition: attachment; filename=siteguard-log-' . gmdate( 'Ymd-His' ) . '.csv' );
				$fh = fopen( 'php://output', 'w' );
				fputcsv( $fh, array( 'time', 'ip', 'username', 'event', 'detail', 'url' ), ',', '"', '' );
				$last = PHP_INT_MAX;
				do {
					$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM ' . SiteGuard_Install::table_log() . ' WHERE id < %d ORDER BY id DESC LIMIT 1000', $last ) ); // phpcs:ignore
					foreach ( $rows as $r ) {
						// Prefix formula-looking cells so spreadsheets do not execute them.
						$cells = array_map(
							function ( $v ) {
								return preg_match( '/^[=+\-@]/', (string) $v ) ? "'" . $v : $v;
							},
							array( wp_date( 'Y-m-d H:i:s', (int) $r->created ), $r->ip, $r->username, $r->event, $r->detail, $r->url )
						);
						fputcsv( $fh, $cells, ',', '"', '' );
						$last = (int) $r->id;
					}
				} while ( count( $rows ) === 1000 );
				fclose( $fh ); // phpcs:ignore
				exit;
			default:
				$redirect = self::url( 'dashboard' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}
}
