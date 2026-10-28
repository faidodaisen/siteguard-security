<?php
defined( 'ABSPATH' ) || exit;

/**
 * CAPTCHA: Google reCAPTCHA v2 (checkbox), reCAPTCHA v3 (invisible score) or Cloudflare Turnstile.
 *
 * Rendering and validation are always paired per form, so programmatic callers of the same
 * core hooks (other plugins registering users, importing comments, etc.) are never blocked:
 *  - wp-login.php login / register / lost password
 *  - WooCommerce My Account login / register / lost password, checkout login
 *  - comment form (wp-comments-post.php only)
 * Inactive until both keys are filled in.
 */
class SiteGuard_Captcha {

	const PROVIDERS = array(
		'none'         => 'Disabled',
		'recaptcha_v2' => 'Google reCAPTCHA v2 (checkbox)',
		'recaptcha_v3' => 'Google reCAPTCHA v3 (invisible)',
		'turnstile'    => 'Cloudflare Turnstile',
	);

	const HANDLE = 'siteguard-captcha';

	private static $verified = null;

	public static function init() {
		if ( ! self::active() ) {
			return;
		}
		$o = SiteGuard_Options::all();

		add_filter( 'script_loader_tag', array( __CLASS__, 'async_tag' ), 10, 2 );
		add_action( 'login_enqueue_scripts', array( __CLASS__, 'login_css' ) );

		if ( $o['captcha_login'] ) {
			add_action( 'login_form', array( __CLASS__, 'render' ) );
			add_filter( 'authenticate', array( __CLASS__, 'check_login' ), 30, 3 );
		}
		if ( $o['captcha_register'] ) {
			add_action( 'register_form', array( __CLASS__, 'render' ) );
			add_filter( 'registration_errors', array( __CLASS__, 'check_core_register' ), 10, 1 );
		}
		if ( $o['captcha_lostpass'] ) {
			add_action( 'lostpassword_form', array( __CLASS__, 'render' ) );
		}
		if ( $o['captcha_lostpass'] || ( $o['captcha_woocommerce'] && class_exists( 'WooCommerce' ) ) ) {
			add_action( 'lostpassword_post', array( __CLASS__, 'check_lostpassword' ), 10, 1 );
		}
		if ( $o['captcha_comments'] ) {
			add_action( 'comment_form_after_fields', array( __CLASS__, 'render_comment' ) );
			add_action( 'comment_form_logged_in_after', array( __CLASS__, 'render_comment' ) );
			add_filter( 'preprocess_comment', array( __CLASS__, 'check_comment' ), 1 );
		}
		if ( $o['captcha_woocommerce'] ) {
			add_action( 'woocommerce_login_form', array( __CLASS__, 'render' ) );
			add_action( 'woocommerce_register_form', array( __CLASS__, 'render' ) );
			add_action( 'woocommerce_lostpassword_form', array( __CLASS__, 'render' ) );
			add_filter( 'woocommerce_process_registration_errors', array( __CLASS__, 'check_wc_register' ), 10, 1 );
		}
	}

	public static function active() {
		$o = SiteGuard_Options::all();
		return isset( self::PROVIDERS[ $o['captcha_provider'] ] ) && 'none' !== $o['captcha_provider']
			&& '' !== trim( (string) $o['captcha_site_key'] ) && '' !== trim( (string) $o['captcha_secret_key'] );
	}

	private static function is_login_page() {
		return isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'];
	}

	private static function is_post() {
		return 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ); // phpcs:ignore
	}

	private static function script_url() {
		$p = SiteGuard_Options::get( 'captcha_provider' );
		if ( 'turnstile' === $p ) {
			return 'https://challenges.cloudflare.com/turnstile/v0/api.js';
		}
		if ( 'recaptcha_v3' === $p ) {
			return 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( SiteGuard_Options::get( 'captcha_site_key' ) );
		}
		return 'https://www.google.com/recaptcha/api.js';
	}

	private static function enqueue() {
		// Footer + async via script_loader_tag: works the same on WP 6.0 – current.
		wp_enqueue_script( self::HANDLE, self::script_url(), array(), null, true ); // phpcs:ignore
	}

	public static function async_tag( $tag, $handle ) {
		if ( self::HANDLE === $handle && false === strpos( $tag, ' async' ) ) {
			$tag = str_replace( ' src=', ' async defer src=', $tag );
		}
		return $tag;
	}

	public static function login_css() {
		if ( 'recaptcha_v2' === SiteGuard_Options::get( 'captcha_provider' ) ) {
			wp_add_inline_style( 'login', '#login{width:352px}' );
		}
		wp_add_inline_style( 'login', '.sg-captcha{margin:0 0 16px}' );
	}

	public static function render() {
		static $count = 0;
		++$count;
		self::enqueue();
		$p   = SiteGuard_Options::get( 'captcha_provider' );
		$key = (string) SiteGuard_Options::get( 'captcha_site_key' );
		echo '<div class="sg-captcha"><input type="hidden" name="siteguard_captcha" value="1">';
		if ( 'turnstile' === $p ) {
			echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( $key ) . '"></div>';
		} elseif ( 'recaptcha_v2' === $p ) {
			echo '<div class="g-recaptcha" data-sitekey="' . esc_attr( $key ) . '"></div>';
		} else {
			$id = 'sg-rc3-' . $count;
			echo '<input type="hidden" name="g-recaptcha-response" id="' . esc_attr( $id ) . '" value="">';
			?>
			<script>
			(function(){
				var input = document.getElementById(<?php echo wp_json_encode( $id ); ?>), form = input && input.form, busy = false, tries = 0;
				if (!form) return;
				function fail(){
					busy = false;
					var p = document.getElementById(<?php echo wp_json_encode( $id . '-err' ); ?>);
					if (!p) { p = document.createElement('p'); p.id = <?php echo wp_json_encode( $id . '-err' ); ?>; p.style.color = '#b32d2e'; input.parentNode.appendChild(p); }
					p.textContent = <?php echo wp_json_encode( __( 'The security check could not load. Please reload the page and try again.', 'siteguard-security' ) ); ?>;
				}
				function resubmit(sub){
					if (form.requestSubmit) { sub && sub.form === form ? form.requestSubmit(sub) : form.requestSubmit(); }
					else { HTMLFormElement.prototype.submit.call(form); }
				}
				form.addEventListener('submit', function(e){
					if (input.value) return;
					e.preventDefault();
					if (busy) return;
					busy = true;
					var sub = e.submitter || null;
					(function wait(){
						if (window.grecaptcha && grecaptcha.execute) {
							grecaptcha.ready(function(){
								grecaptcha.execute(<?php echo wp_json_encode( $key ); ?>, {action: 'login'}).then(function(t){
									input.value = t; busy = false; resubmit(sub);
									setTimeout(function(){ input.value = ''; }, 110000); // tokens expire after 2 min.
								}, fail);
							});
						} else if (++tries < 40) { setTimeout(wait, 250); } else { fail(); }
					})();
				});
			})();
			</script>
			<?php
		}
		echo '</div>';
	}

	public static function render_comment() {
		if ( SiteGuard_Options::get( 'captcha_skip_logged_in' ) && is_user_logged_in() ) {
			return;
		}
		self::render();
	}

	/** Verify the token in the current POST. Cached per request. */
	public static function verify() {
		if ( null !== self::$verified ) {
			return self::$verified;
		}
		if ( SiteGuard_IP::is_whitelisted() ) {
			return self::$verified = true;
		}
		$p     = SiteGuard_Options::get( 'captcha_provider' );
		$field = 'turnstile' === $p ? 'cf-turnstile-response' : 'g-recaptcha-response';
		$token = isset( $_POST[ $field ] ) ? sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) : ''; // phpcs:ignore
		if ( '' === $token ) {
			return self::$verified = false;
		}
		$endpoint = 'turnstile' === $p
			? 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
			: 'https://www.google.com/recaptcha/api/siteverify';

		$res = wp_remote_post(
			$endpoint,
			array(
				'timeout' => 10,
				'body'    => array(
					'secret'   => SiteGuard_Options::get( 'captcha_secret_key' ),
					'response' => $token,
					'remoteip' => SiteGuard_IP::current(),
				),
			)
		);
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			// Provider unreachable: fail closed, leave a trace. Whitelist / SITEGUARD_DISABLE recover access.
			SiteGuard_BruteForce::log( 'captcha_error', '', is_wp_error( $res ) ? $res->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code( $res ) );
			return self::$verified = false;
		}
		$body = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		$ok   = is_array( $body ) && ! empty( $body['success'] );
		if ( $ok && 'recaptcha_v3' === $p ) {
			$ok = isset( $body['score'] ) && (float) $body['score'] >= (float) SiteGuard_Options::get( 'captcha_v3_score' );
		}
		if ( ! $ok && is_array( $body ) && ! empty( $body['error-codes'] ) ) {
			$codes = implode( ',', array_map( 'sanitize_key', (array) $body['error-codes'] ) );
			if ( preg_match( '/invalid-input-secret|missing-input-secret|invalid-keys|sitekey-secret-mismatch/', $codes ) ) {
				SiteGuard_BruteForce::log( 'captcha_error', '', 'Provider says the secret key is wrong: ' . $codes );
			}
		}
		return self::$verified = $ok;
	}

	private static function message() {
		return '<strong>' . esc_html__( 'Error:', 'siteguard-security' ) . '</strong> ' . esc_html__( 'Please complete the CAPTCHA verification.', 'siteguard-security' );
	}

	/** Login: wp-login.php POSTs always; WooCommerce / other forms only when they carry our widget. */
	public static function check_login( $user, $username, $password ) {
		if ( ! self::is_post() || '' === (string) $username || '' === (string) $password ) {
			return $user;
		}
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return $user;
		}
		$core = self::is_login_page() && isset( $_POST['log'] ); // phpcs:ignore
		$wc   = SiteGuard_Options::get( 'captcha_woocommerce' ) && isset( $_POST['woocommerce-login-nonce'] ); // phpcs:ignore
		$ours = isset( $_POST['siteguard_captcha'] ); // phpcs:ignore
		if ( ! $core && ! $wc && ! $ours ) {
			return $user;
		}
		return self::verify() ? $user : new WP_Error( 'sg_captcha', self::message() );
	}

	public static function check_core_register( $errors ) {
		if ( self::is_login_page() && self::is_post() && is_wp_error( $errors ) && ! self::verify() ) {
			$errors->add( 'sg_captcha', self::message() );
		}
		return $errors;
	}

	public static function check_lostpassword( $errors ) {
		if ( ! self::is_post() || ! is_wp_error( $errors ) ) {
			return;
		}
		$core = SiteGuard_Options::get( 'captcha_lostpass' ) && self::is_login_page();
		$wc   = SiteGuard_Options::get( 'captcha_woocommerce' ) && isset( $_POST['woocommerce-lost-password-nonce'] ); // phpcs:ignore
		if ( ( $core || $wc ) && ! self::verify() ) {
			$errors->add( 'sg_captcha', self::message() );
		}
	}

	public static function check_wc_register( $errors ) {
		if ( self::is_post() && isset( $_POST['woocommerce-register-nonce'] ) && is_wp_error( $errors ) && ! self::verify() ) { // phpcs:ignore
			$errors->add( 'sg_captcha', self::message() );
		}
		return $errors;
	}

	public static function check_comment( $data ) {
		// Only real form submissions (wp-comments-post.php); never REST, imports or other plugins.
		if ( ! did_action( 'pre_comment_on_post' ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return $data;
		}
		if ( ! empty( $data['comment_type'] ) && 'comment' !== $data['comment_type'] ) {
			return $data;
		}
		if ( SiteGuard_Options::get( 'captcha_skip_logged_in' ) && is_user_logged_in() ) {
			return $data;
		}
		if ( ! self::verify() ) {
			wp_die( wp_kses_post( self::message() ), esc_html__( 'CAPTCHA failed', 'siteguard-security' ), array( 'response' => 403, 'back_link' => true ) );
		}
		return $data;
	}
}
