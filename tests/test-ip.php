<?php
/**
 * Standalone test for SiteGuard_IP (no WordPress needed).
 * Run: php tests/test-ip.php   (exit code 0 = all passed)
 */

define( 'ABSPATH', __DIR__ . '/' );

function sanitize_text_field( $s ) {
	return trim( preg_replace( '/[\r\n\t ]+/', ' ', strip_tags( (string) $s ) ) );
}
function wp_unslash( $s ) {
	return is_string( $s ) ? stripslashes( $s ) : $s;
}

class SiteGuard_Options {
	public static $o = array();
	public static function get( $k ) {
		$d = array( 'ip_method' => 'REMOTE_ADDR', 'trusted_proxies' => '', 'whitelist' => '', 'blacklist' => '' );
		return array_key_exists( $k, self::$o ) ? self::$o[ $k ] : ( $d[ $k ] ?? null );
	}
}

require dirname( __DIR__ ) . '/includes/class-siteguard-ip.php';

$pass = 0;
$fail = 0;

/** @param array $server $_SERVER keys, @param array $opts option overrides. */
function scenario( $name, array $server, array $opts, $want_ip, $want_misconf, $want_cf ) {
	global $pass, $fail;
	$_SERVER               = $server;
	SiteGuard_Options::$o  = $opts;
	SiteGuard_IP::flush();
	$ip   = SiteGuard_IP::current();
	$mc   = SiteGuard_IP::misconfiguration();
	$cf   = SiteGuard_IP::behind_cloudflare_misconfigured();
	$got  = $mc ? $mc['method'] : false;
	$ok   = $ip === $want_ip && $got === $want_misconf && $cf === $want_cf;
	$ok ? $pass++ : $fail++;
	printf(
		"%s  %-58s current=%-15s misconf=%-22s cf_warn=%s\n",
		$ok ? 'PASS' : 'FAIL',
		$name,
		$ip,
		var_export( $got, true ),
		var_export( $cf, true )
	);
	if ( ! $ok ) {
		printf( "      expected current=%s misconf=%s cf_warn=%s\n", $want_ip, var_export( $want_misconf, true ), var_export( $want_cf, true ) );
	}
}

$cf  = array( 'ip_method' => 'HTTP_CF_CONNECTING_IP' );
$xff = array( 'ip_method' => 'HTTP_X_FORWARDED_FOR' );

echo "-- ip_method = HTTP_CF_CONNECTING_IP (correct setting) --\n";
scenario( 'CF IPv4 peer + CF header -> real IP', array( 'REMOTE_ADDR' => '172.71.10.20', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7' ), $cf, '203.0.113.7', false, false );
scenario( 'Non-CF peer + forged CF header -> REMOTE_ADDR', array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_CF_CONNECTING_IP' => '1.2.3.4' ), $cf, '198.51.100.9', false, false );
scenario( 'No header -> REMOTE_ADDR', array( 'REMOTE_ADDR' => '198.51.100.9' ), $cf, '198.51.100.9', false, false );
scenario( 'CF IPv6 peer + CF header (IPv4 client) -> real IP', array( 'REMOTE_ADDR' => '2a06:98c1:3120::7', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7' ), $cf, '203.0.113.7', false, false );
scenario( 'CF IPv6 peer + CF header (IPv6 client) -> real IP', array( 'REMOTE_ADDR' => '2400:cb00:2049:1::a29f:1', 'HTTP_CF_CONNECTING_IP' => '2001:db8::5' ), $cf, '2001:db8::5', false, false );
scenario( 'Non-CF IPv6 peer + forged CF header -> REMOTE_ADDR', array( 'REMOTE_ADDR' => '2001:db8:ffff::1', 'HTTP_CF_CONNECTING_IP' => '1.2.3.4' ), $cf, '2001:db8:ffff::1', false, false );
scenario( 'CF peer + garbage CF header -> REMOTE_ADDR', array( 'REMOTE_ADDR' => '172.71.10.20', 'HTTP_CF_CONNECTING_IP' => 'not-an-ip' ), $cf, '172.71.10.20', false, false );

echo "-- ip_method = REMOTE_ADDR (default) --\n";
scenario( 'CF IPv4 peer + CF header -> warn (tda.my case)', array( 'REMOTE_ADDR' => '172.71.10.20', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7' ), array(), '172.71.10.20', 'HTTP_CF_CONNECTING_IP', true );
scenario( 'CF IPv6 peer + CF header -> warn', array( 'REMOTE_ADDR' => '2a06:98c1:3120::7', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7' ), array(), '2a06:98c1:3120::7', 'HTTP_CF_CONNECTING_IP', true );
scenario( 'Non-CF peer + forged CF header -> no warn', array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_CF_CONNECTING_IP' => '1.2.3.4' ), array(), '198.51.100.9', false, false );
scenario( 'No header -> no warn', array( 'REMOTE_ADDR' => '198.51.100.9' ), array(), '198.51.100.9', false, false );
scenario( 'CF peer, no CF header -> no warn', array( 'REMOTE_ADDR' => '172.71.10.20' ), array(), '172.71.10.20', false, false );
scenario( 'CF peer + garbage CF header -> no warn', array( 'REMOTE_ADDR' => '172.71.10.20', 'HTTP_CF_CONNECTING_IP' => 'x' ), array(), '172.71.10.20', false, false );
scenario( 'Private proxy peer + XFF -> warn, suggest XFF', array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7' ), array(), '10.0.0.5', 'HTTP_X_FORWARDED_FOR', false );
scenario( 'Private peer, no XFF -> no warn', array( 'REMOTE_ADDR' => '10.0.0.5' ), array(), '10.0.0.5', false, false );
scenario( 'Public peer + forged XFF -> no warn', array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4' ), array(), '198.51.100.9', false, false );
scenario( 'Private peer + XFF of private hops only -> no warn', array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '10.0.0.9' ), array(), '10.0.0.5', false, false );
scenario( 'Private peer not in custom trusted list + XFF -> no warn', array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7' ), array( 'trusted_proxies' => '192.168.1.1' ), '10.0.0.5', false, false );
scenario( 'No REMOTE_ADDR -> 0.0.0.0, no warn', array(), array(), '0.0.0.0', false, false );

echo "-- other methods unchanged --\n";
scenario( 'XFF method, private peer -> right-most untrusted hop', array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1, 203.0.113.7, 10.0.0.9' ), $xff, '203.0.113.7', false, false );
scenario( 'XFF method, public peer + forged XFF -> REMOTE_ADDR', array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4' ), $xff, '198.51.100.9', false, false );
scenario( 'CF method but site not behind CF -> no warn', array( 'REMOTE_ADDR' => '198.51.100.9' ), $cf, '198.51.100.9', false, false );

printf( "\n%d passed, %d failed\n", $pass, $fail );
exit( $fail ? 1 : 0 );
