<?php
defined( 'ABSPATH' ) || exit;

/**
 * Client IP detection and IP list matching (single IP, range "a - b", CIDR; IPv4 + IPv6).
 *
 * Proxy headers are only believed when the connecting peer (REMOTE_ADDR) is a trusted proxy:
 *  - CF-Connecting-IP: peer must be in Cloudflare's published ranges (or the trusted list).
 *  - X-Forwarded-For / X-Real-IP: peer must be in the "trusted proxies" list (private/loopback
 *    networks when the list is empty). X-Forwarded-For is read right-to-left, skipping trusted
 *    hops, because left-most entries are whatever the client chose to send.
 */
class SiteGuard_IP {

	const METHODS = array(
		'REMOTE_ADDR'           => 'REMOTE_ADDR (default, safest)',
		'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP (site behind Cloudflare)',
		'HTTP_X_FORWARDED_FOR'  => 'X-Forwarded-For (behind proxy / load balancer)',
		'HTTP_X_REAL_IP'        => 'X-Real-IP (nginx reverse proxy)',
	);

	/** https://www.cloudflare.com/ips/ */
	const CLOUDFLARE = "173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n141.101.64.0/18\n108.162.192.0/18\n190.93.240.0/20\n188.114.96.0/20\n197.234.240.0/22\n198.41.128.0/17\n162.158.0.0/15\n104.16.0.0/13\n104.24.0.0/14\n172.64.0.0/13\n131.0.72.0/22\n2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n2405:b500::/32\n2405:8100::/32\n2a06:98c0::/29\n2c0f:f248::/32";

	const PRIVATE_NETS = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n127.0.0.0/8\n100.64.0.0/10\n::1/128\nfc00::/7\nfe80::/10";

	private static $ip = null;

	public static function flush() {
		self::$ip = null;
	}

	/** Canonical text form (IPv6 compressed, IPv4-mapped IPv6 → IPv4). '' when invalid. */
	public static function normalize( $ip ) {
		$ip = trim( (string) $ip );
		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$bin = inet_pton( $ip );
		if ( false === $bin ) {
			return '';
		}
		if ( 16 === strlen( $bin ) && 0 === strpos( $bin, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$bin = substr( $bin, 12 );
		}
		$out = inet_ntop( $bin );
		return false === $out ? '' : $out;
	}

	public static function valid( $ip ) {
		return '' !== self::normalize( $ip );
	}

	public static function current() {
		if ( null !== self::$ip ) {
			return self::$ip;
		}
		$peer   = isset( $_SERVER['REMOTE_ADDR'] ) ? self::normalize( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
		$method = (string) SiteGuard_Options::get( 'ip_method' );
		$ip     = $peer;

		if ( 'REMOTE_ADDR' !== $method && isset( self::METHODS[ $method ] ) && '' !== $peer && ! empty( $_SERVER[ $method ] ) ) {
			$raw = sanitize_text_field( wp_unslash( $_SERVER[ $method ] ) );
			if ( 'HTTP_CF_CONNECTING_IP' === $method ) {
				if ( self::in_list( $peer, self::CLOUDFLARE ) || self::is_trusted_proxy( $peer ) ) {
					$cand = self::normalize( $raw );
					$ip   = '' !== $cand ? $cand : $peer;
				}
			} elseif ( self::is_trusted_proxy( $peer ) ) {
				foreach ( array_reverse( explode( ',', $raw ) ) as $hop ) {
					$hop = self::normalize( $hop );
					if ( '' === $hop ) {
						break; // Malformed entry: stop trusting the chain.
					}
					$ip = $hop;
					if ( ! self::is_trusted_proxy( $hop ) ) {
						break; // First untrusted hop from the right is the client.
					}
				}
			}
		}
		self::$ip = '' !== $ip ? $ip : '0.0.0.0';
		return self::$ip;
	}

	public static function is_trusted_proxy( $ip ) {
		$list = trim( (string) SiteGuard_Options::get( 'trusted_proxies' ) );
		return self::in_list( $ip, '' !== $list ? $list : self::PRIVATE_NETS );
	}

	/** Parse textarea list into valid lines; invalid lines dropped. */
	public static function parse_list( $text ) {
		$out = array();
		foreach ( preg_split( '/[\r\n]+/', (string) $text ) as $line ) {
			$line = trim( preg_replace( '/#.*$/', '', $line ) );
			if ( '' !== $line && self::parse_entry( $line ) ) {
				$out[] = $line;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/** Returns [start_bin, end_bin] or false. */
	public static function parse_entry( $entry ) {
		$entry = trim( $entry );
		if ( false !== strpos( $entry, '/' ) ) {
			list( $base, $bits ) = array_map( 'trim', explode( '/', $entry, 2 ) );
			$base = self::normalize( $base );
			if ( '' === $base || '' === $bits || ! ctype_digit( $bits ) ) {
				return false;
			}
			$bin  = inet_pton( $base );
			$bits = (int) $bits;
			$len  = strlen( $bin );
			if ( $bits > $len * 8 ) {
				return false;
			}
			$start = '';
			$end   = '';
			for ( $i = 0; $i < $len; $i++ ) {
				$keep   = max( 0, min( 8, $bits - $i * 8 ) );
				$mask   = $keep ? ( 0xFF << ( 8 - $keep ) ) & 0xFF : 0;
				$byte   = ord( $bin[ $i ] );
				$start .= chr( $byte & $mask );
				$end   .= chr( ( $byte & $mask ) | ( ~$mask & 0xFF ) );
			}
			return array( $start, $end );
		}
		if ( false !== strpos( $entry, ' - ' ) || ( false !== strpos( $entry, '-' ) && false === strpos( $entry, ':' ) ) ) {
			list( $a, $b ) = array_map( array( __CLASS__, 'normalize' ), explode( '-', $entry, 2 ) );
			if ( '' === $a || '' === $b ) {
				return false;
			}
			$a = inet_pton( $a );
			$b = inet_pton( $b );
			if ( strlen( $a ) !== strlen( $b ) ) {
				return false;
			}
			return strcmp( $a, $b ) <= 0 ? array( $a, $b ) : array( $b, $a );
		}
		$ip = self::normalize( $entry );
		if ( '' === $ip ) {
			return false;
		}
		$bin = inet_pton( $ip );
		return array( $bin, $bin );
	}

	public static function in_list( $ip, $text ) {
		$ip = self::normalize( $ip );
		if ( '' === $ip || '' === trim( (string) $text ) ) {
			return false;
		}
		$bin = inet_pton( $ip );
		foreach ( preg_split( '/[\r\n]+/', (string) $text ) as $line ) {
			$line = trim( preg_replace( '/#.*$/', '', $line ) );
			if ( '' === $line ) {
				continue;
			}
			$range = self::parse_entry( $line );
			if ( $range && strlen( $range[0] ) === strlen( $bin )
				&& strcmp( $bin, $range[0] ) >= 0 && strcmp( $bin, $range[1] ) <= 0 ) {
				return true;
			}
		}
		return false;
	}

	public static function is_whitelisted( $ip = null ) {
		return self::in_list( $ip ? $ip : self::current(), SiteGuard_Options::get( 'whitelist' ) );
	}

	public static function is_blacklisted( $ip = null ) {
		$ip = $ip ? $ip : self::current();
		return ! self::is_whitelisted( $ip ) && self::in_list( $ip, SiteGuard_Options::get( 'blacklist' ) );
	}
}
