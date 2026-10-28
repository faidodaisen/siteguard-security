<?php
defined( 'ABSPATH' ) || exit;

/**
 * Self-hosted updates from GitHub Releases (private repo supported).
 *
 * - `Update URI: https://github.com/<repo>` in the plugin header makes WP 5.8+ ask
 *   `update_plugins_github.com`; `site_transient_update_plugins` covers cached reads.
 * - Only non-draft, non-prerelease releases whose tag parses as a version strictly newer
 *   than SITEGUARD_VERSION are offered (no phantom updates on re-tag).
 * - Built `.zip` release asset preferred; zipball fallback is renamed to the slug.
 * - Token (private repo): wp-config constant SITEGUARD_GITHUB_TOKEN, or the field on
 *   SiteGuard → Updates. Sent only to api.github.com/repos/<this repo>/.
 */
class SiteGuard_Updater {

	const REPO      = 'faidodaisen/siteguard-security';
	const CACHE_KEY = 'siteguard_update_check';
	const CACHE_TTL = 21600; // 6h.
	const ERROR_TTL = 1800;  // 30 min.

	public static function init() {
		add_filter( 'update_plugins_github.com', array( __CLASS__, 'check_for_update' ), 10, 3 );
		add_filter( 'site_transient_update_plugins', array( __CLASS__, 'inject_update' ) );
		add_filter( 'plugins_api', array( __CLASS__, 'plugin_info' ), 20, 3 );
		add_filter( 'upgrader_source_selection', array( __CLASS__, 'fix_source_dir' ), 10, 4 );
		add_filter( 'upgrader_pre_download', array( __CLASS__, 'download' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'clear_cache' ), 10, 0 );
	}

	/* ---------------- config ---------------- */

	public static function repo() {
		$repo = (string) apply_filters( 'siteguard_update_repo', self::REPO );
		return preg_match( '#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $repo ) ? $repo : self::REPO;
	}

	public static function token() {
		if ( defined( 'SITEGUARD_GITHUB_TOKEN' ) && is_string( SITEGUARD_GITHUB_TOKEN ) && '' !== SITEGUARD_GITHUB_TOKEN ) {
			return trim( SITEGUARD_GITHUB_TOKEN );
		}
		return trim( (string) get_site_option( 'siteguard_github_token', '' ) );
	}

	public static function token_from_constant() {
		return defined( 'SITEGUARD_GITHUB_TOKEN' ) && is_string( SITEGUARD_GITHUB_TOKEN ) && '' !== SITEGUARD_GITHUB_TOKEN;
	}

	public static function basename() {
		return plugin_basename( SITEGUARD_FILE );
	}

	public static function slug() {
		return dirname( self::basename() );
	}

	private static function headers( $download = false ) {
		$h     = array(
			'User-Agent' => 'SiteGuard-Security/' . SITEGUARD_VERSION,
			'Accept'     => $download ? 'application/octet-stream' : 'application/vnd.github+json',
		);
		$token = self::token();
		if ( '' !== $token ) {
			$h['Authorization'] = 'Bearer ' . $token;
		}
		return $h;
	}

	/* ---------------- lookup ---------------- */

	/** @return array|null newest eligible release. */
	public static function latest_release( $force = false ) {
		if ( ! $force ) {
			$cached = get_site_transient( self::CACHE_KEY );
			if ( is_array( $cached ) ) {
				return empty( $cached['release'] ) ? null : $cached['release'];
			}
		}

		$res = wp_remote_get(
			'https://api.github.com/repos/' . self::repo() . '/releases?per_page=10',
			array( 'timeout' => 15, 'headers' => self::headers() )
		);
		if ( is_wp_error( $res ) ) {
			self::cache_failure( $res->get_error_message() );
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $res );
		if ( 200 !== $code ) {
			if ( 404 === $code ) {
				$msg = '' === self::token()
					? __( 'Repository not found. It is private: add a GitHub token under SiteGuard → Updates.', 'siteguard-security' )
					: __( 'Repository not found, or the token cannot read it. The token needs "Contents: Read-only" on this repository.', 'siteguard-security' );
			} elseif ( 401 === $code || 403 === $code ) {
				$msg = __( 'GitHub refused the request: the token is invalid/expired, or the hourly rate limit was hit.', 'siteguard-security' );
			} else {
				/* translators: %d HTTP status */
				$msg = sprintf( __( 'GitHub returned HTTP %d.', 'siteguard-security' ), $code );
			}
			self::cache_failure( $msg );
			return null;
		}
		$releases = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $releases ) ) {
			self::cache_failure( __( 'GitHub returned an unreadable response.', 'siteguard-security' ) );
			return null;
		}

		$best = null;
		foreach ( $releases as $r ) {
			if ( ! is_array( $r ) || ! empty( $r['draft'] ) || ! empty( $r['prerelease'] ) ) {
				continue;
			}
			$version = self::normalize_version( isset( $r['tag_name'] ) ? (string) $r['tag_name'] : '' );
			if ( '' === $version || ( $best && version_compare( $version, $best['version'], '<=' ) ) ) {
				continue;
			}
			$package = '';
			$asset   = false;
			$sha256  = '';
			foreach ( ( isset( $r['assets'] ) && is_array( $r['assets'] ) ) ? $r['assets'] : array() as $a ) {
				$name = is_array( $a ) && isset( $a['name'] ) ? strtolower( (string) $a['name'] ) : '';
				if ( '.zip' !== substr( $name, -4 ) ) {
					continue;
				}
				// Private repo: browser URL needs a session, the API asset URL works with a token.
				$package = '' !== self::token() ? (string) ( $a['url'] ?? '' ) : (string) ( $a['browser_download_url'] ?? '' );
				$asset   = '' !== $package;
				if ( isset( $a['digest'] ) && preg_match( '/^sha256:([0-9a-f]{64})$/', strtolower( (string) $a['digest'] ), $m ) ) {
					$sha256 = $m[1];
				}
				break;
			}
			if ( '' === $package ) {
				$package = (string) ( $r['zipball_url'] ?? '' );
			}
			if ( '' === $package ) {
				continue;
			}
			$best = array(
				'version'   => $version,
				'package'   => $package,
				'url'       => (string) ( $r['html_url'] ?? '' ),
				'notes'     => (string) ( $r['body'] ?? '' ),
				'published' => (string) ( $r['published_at'] ?? '' ),
				'asset'     => $asset,
				'sha256'    => $sha256,
			);
		}
		set_site_transient( self::CACHE_KEY, array( 'release' => $best, 'error' => '', 'checked' => time() ), self::CACHE_TTL );
		return $best;
	}

	private static function cache_failure( $msg ) {
		set_site_transient( self::CACHE_KEY, array( 'release' => null, 'error' => $msg, 'checked' => time() ), self::ERROR_TTL );
	}

	public static function status() {
		$c = get_site_transient( self::CACHE_KEY );
		return is_array( $c ) ? $c : array();
	}

	public static function clear_cache() {
		delete_site_transient( self::CACHE_KEY );
	}

	public static function normalize_version( $tag ) {
		return preg_match( '/(\d+(?:\.\d+)+)/', $tag, $m ) ? $m[1] : '';
	}

	public static function is_newer( $remote ) {
		return version_compare( $remote, SITEGUARD_VERSION, '>' );
	}

	/* ---------------- WP plumbing ---------------- */

	private static function payload( array $r ) {
		return array(
			'id'            => 'github.com/' . self::repo(),
			'slug'          => self::slug(),
			'plugin'        => self::basename(),
			'new_version'   => $r['version'],
			'url'           => $r['url'],
			'package'       => $r['package'],
			'icons'         => array(),
			'banners'       => array(),
			'banners_rtl'   => array(),
			'tested'        => get_bloginfo( 'version' ),
			'requires_php'  => '7.4',
			'compatibility' => new stdClass(),
		);
	}

	public static function check_for_update( $update, $plugin_data, $plugin_file ) {
		if ( self::basename() !== $plugin_file ) {
			return $update;
		}
		$r = self::latest_release();
		return ( $r && self::is_newer( $r['version'] ) ) ? self::payload( $r ) : $update;
	}

	public static function inject_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}
		$base = self::basename();
		$r    = self::latest_release();
		if ( ! $r || ! self::is_newer( $r['version'] ) ) {
			if ( isset( $transient->response ) && is_array( $transient->response ) ) {
				unset( $transient->response[ $base ] );
			}
			return $transient;
		}
		if ( ! isset( $transient->response ) || ! is_array( $transient->response ) ) {
			$transient->response = array();
		}
		$transient->response[ $base ] = (object) self::payload( $r );
		if ( isset( $transient->no_update ) && is_array( $transient->no_update ) ) {
			unset( $transient->no_update[ $base ] );
		}
		return $transient;
	}

	public static function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! is_object( $args ) || ! isset( $args->slug ) || self::slug() !== $args->slug ) {
			return $result;
		}
		$r = self::latest_release();
		if ( ! $r ) {
			return $result;
		}
		return (object) array(
			'name'          => 'SiteGuard Security',
			'slug'          => self::slug(),
			'version'       => $r['version'],
			'author'        => 'Fido Design',
			'homepage'      => 'https://github.com/' . self::repo(),
			'requires'      => '6.0',
			'requires_php'  => '7.4',
			'tested'        => get_bloginfo( 'version' ),
			'last_updated'  => $r['published'],
			'download_link' => $r['package'],
			'sections'      => array(
				'description' => '<p>' . esc_html__( 'Login protection: brute-force lockout, login logs, IP lists, CAPTCHA and two-factor authentication.', 'siteguard-security' ) . '</p>',
				'changelog'   => self::render_notes( $r['notes'], $r['url'] ),
			),
		);
	}

	/** Minimal Markdown: escape first, then headings / lists / `code` / **bold**. */
	private static function render_notes( $body, $url ) {
		$out  = '';
		$list = false;
		foreach ( preg_split( '/\R/', trim( (string) $body ) ) as $line ) {
			$t = trim( $line );
			if ( preg_match( '/^[-*]\s+(.*)$/', $t, $m ) ) {
				if ( ! $list ) {
					$out .= '<ul>';
					$list = true;
				}
				$out .= '<li>' . self::inline( $m[1] ) . '</li>';
				continue;
			}
			if ( $list ) {
				$out .= '</ul>';
				$list = false;
			}
			if ( '' === $t ) {
				continue;
			}
			if ( preg_match( '/^#{1,6}\s+(.*)$/', $t, $m ) ) {
				$out .= '<h4>' . self::inline( $m[1] ) . '</h4>';
				continue;
			}
			$out .= '<p>' . self::inline( $t ) . '</p>';
		}
		if ( $list ) {
			$out .= '</ul>';
		}
		return $out . '<p><a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html__( 'View this release on GitHub', 'siteguard-security' ) . '</a></p>';
	}

	private static function inline( $t ) {
		$t = esc_html( $t );
		$t = preg_replace( '/`([^`]+)`/', '<code>$1</code>', $t );
		return preg_replace( '/\*\*([^*]+)\*\*/', '<strong>$1</strong>', $t );
	}

	/**
	 * Download our own package. The GitHub API answers asset/zipball URLs with a redirect to a
	 * pre-signed storage URL; the token must go to api.github.com only (sending it on to the
	 * storage host makes the download fail), so the redirect is followed by hand.
	 * Then the file is checked against GitHub's published SHA-256 when available.
	 */
	public static function download( $reply, $package, $upgrader = null, $hook_extra = array() ) {
		if ( false !== $reply || ! is_string( $package ) || '' === $package ) {
			return $reply;
		}
		$api  = 'https://api.github.com/repos/' . self::repo() . '/';
		$site = 'https://github.com/' . self::repo() . '/';
		if ( 0 !== strpos( $package, $api ) && 0 !== strpos( $package, $site ) ) {
			return $reply; // Not ours.
		}
		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		$url  = $package;
		$file = '';
		if ( 0 === strpos( $package, $api ) ) {
			$res = wp_remote_get(
				$package,
				array(
					'timeout'     => 60,
					'redirection' => 0,
					'headers'     => self::headers( false !== strpos( $package, '/releases/assets/' ) ),
				)
			);
			if ( is_wp_error( $res ) ) {
				return $res;
			}
			$code = (int) wp_remote_retrieve_response_code( $res );
			if ( in_array( $code, array( 301, 302, 303, 307, 308 ), true ) ) {
				$url = (string) wp_remote_retrieve_header( $res, 'location' );
				if ( '' === $url || 0 !== strpos( $url, 'https://' ) ) {
					return new WP_Error( 'siteguard_download', __( 'GitHub returned an invalid download location.', 'siteguard-security' ) );
				}
			} elseif ( 200 === $code ) {
				$file = wp_tempnam( 'siteguard-security.zip' );
				if ( ! $file || false === file_put_contents( $file, wp_remote_retrieve_body( $res ) ) ) { // phpcs:ignore
					return new WP_Error( 'siteguard_download', __( 'Could not save the downloaded update.', 'siteguard-security' ) );
				}
			} else {
				/* translators: %d HTTP status */
				return new WP_Error( 'siteguard_download', sprintf( __( 'GitHub refused the download (HTTP %d). Check the token under SiteGuard → Updates.', 'siteguard-security' ), $code ) );
			}
		}
		if ( '' === $file ) {
			$file = download_url( $url, 300 );
			if ( is_wp_error( $file ) ) {
				return $file;
			}
		}

		$r = self::latest_release();
		if ( $r && $r['package'] === $package && ! empty( $r['sha256'] ) && ! hash_equals( $r['sha256'], (string) hash_file( 'sha256', $file ) ) ) {
			@unlink( $file ); // phpcs:ignore
			return new WP_Error( 'siteguard_checksum', __( 'The SiteGuard update download failed its checksum check. Nothing was changed; please try again.', 'siteguard-security' ) );
		}
		return $file;
	}

	/** GitHub zipball unpacks to owner-repo-sha/; rename it to the plugin slug. */
	public static function fix_source_dir( $source, $remote_source, $upgrader = null, $args = array() ) {
		if ( is_wp_error( $source ) || ! is_array( $args ) || ( $args['plugin'] ?? '' ) !== self::basename() ) {
			return $source;
		}
		$slug = self::slug();
		if ( basename( untrailingslashit( $source ) ) === $slug ) {
			return $source;
		}
		global $wp_filesystem;
		if ( ! $wp_filesystem ) {
			return $source;
		}
		$target = trailingslashit( dirname( untrailingslashit( $source ) ) ) . $slug;
		if ( $wp_filesystem->exists( $target ) ) {
			$wp_filesystem->delete( $target, true );
		}
		if ( ! $wp_filesystem->move( untrailingslashit( $source ), $target ) ) {
			return new WP_Error( 'siteguard_rename', __( 'Could not rename the downloaded package folder. The update was not installed.', 'siteguard-security' ) );
		}
		return trailingslashit( $target );
	}
}
