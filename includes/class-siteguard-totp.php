<?php
defined( 'ABSPATH' ) || exit;

/**
 * RFC 6238 TOTP (SHA1, 6 digits, 30s) + RFC 4648 base32.
 */
class SiteGuard_TOTP {

	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public static function generate_secret( $bytes = 20 ) {
		return self::base32_encode( random_bytes( $bytes ) );
	}

	public static function base32_encode( $data ) {
		$bits = '';
		foreach ( str_split( $data ) as $c ) {
			$bits .= str_pad( decbin( ord( $c ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::ALPHABET[ bindec( str_pad( $chunk, 5, '0' ) ) ];
		}
		return $out;
	}

	public static function base32_decode( $str ) {
		$str  = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', $str ) );
		$bits = '';
		foreach ( str_split( $str ) as $c ) {
			$bits .= str_pad( decbin( strpos( self::ALPHABET, $c ) ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( strlen( $byte ) === 8 ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	public static function code( $secret, $step ) {
		$key  = self::base32_decode( $secret );
		$msg  = pack( 'N2', 0, $step ); // 64-bit big-endian counter (fits for centuries).
		$hash = hash_hmac( 'sha1', $msg, $key, true );
		$off  = ord( $hash[19] ) & 0x0F;
		$bin  = ( ( ord( $hash[ $off ] ) & 0x7F ) << 24 ) | ( ord( $hash[ $off + 1 ] ) << 16 ) | ( ord( $hash[ $off + 2 ] ) << 8 ) | ord( $hash[ $off + 3 ] );
		return str_pad( (string) ( $bin % 1000000 ), 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Returns the matched time step or false. Accepts ±$window steps for clock drift.
	 * Steps <= $last_step are rejected to stop code replay.
	 */
	public static function verify( $secret, $code, $last_step = 0, $window = 1 ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== 6 || '' === $secret ) {
			return false;
		}
		$now = (int) floor( time() / 30 );
		for ( $i = -$window; $i <= $window; $i++ ) {
			$step = $now + $i;
			if ( $step > (int) $last_step && hash_equals( self::code( $secret, $step ), $code ) ) {
				return $step;
			}
		}
		return false;
	}

	public static function uri( $secret, $account, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $account )
			. '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=6&period=30';
	}
}
