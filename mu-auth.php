<?php
/**
 * Plugin Name:     MU Auth
 * Plugin URI:      https://www.marshall.edu
 * Description:     Marshall University SSO authentication for WordPress
 * Author:          Christopher McComas
 * Author URI:      https://www.marshall.edu
 * Version:         1.0.1
 *
 * @package         MU_Auth
 */

// Define constants.
const MUCASAUTH_CAS_HOST                = 'https://auth.marshall.edu';
const MUCASAUTH_CAS_PATH                = '/cas';
const MUCASAUTH_LOGOUT_REDIRECT_URL     = 'https://www.marshall.edu';
const MUCASAUTH_CAS_ATTRIBUTE_GROUPS    = 'groups';
const MUCASAUTH_CAS_ATTRIBUTE_FIRSTNAME = 'firstname';
const MUCASAUTH_CAS_ATTRIBUTE_LASTNAME  = 'lastname';
const MUCASAUTH_CAS_ATTRIBUTE_EMAIL     = 'email';

if ( ! class_exists( 'ACF' ) ) {
	return new WP_Error( 'broke', __( 'Advanced Custom Fields is required for this plugin.', 'mu-moments' ) );
}

require plugin_dir_path( __FILE__ ) . '/acf-fields.php';
require plugin_dir_path( __FILE__ ) . '/mu-auth-admin.php';

/**
 * Flush rewrites whenever the plugin is activated.
 */
function mu_auth_activate() {
	flush_rewrite_rules();
}
register_activation_hook( __FILE__, 'mu_auth_activate' );

/**
 * Flush rewrites whenever the plugin is deactivated.
 */
function mu_auth_deactivate() {
	flush_rewrite_rules();
}
register_deactivation_hook( __FILE__, 'mu_auth_deactivate' );

/**
 * Redirect the user to the homepage after logging out.
 *
 * @return void
 */
function mu_auth_logout_redirect() {
	wp_safe_redirect( 'https://www.marshall.edu' );
	exit;
}
add_action( 'wp_logout', 'mu_auth_logout_redirect' );

/**
 * Check if the current URL is the WordPress login page.
 *
 * @return boolean
 */
function mu_auth_is_wordpress_admin_login() {
	$current_url = trim( $_SERVER['REQUEST_URI'], '/' ); // phpcs:ignore
	return ( strpos( $current_url, 'wp-login.php' ) !== false && strpos( $current_url, 'action=logout' ) === false && strpos( $current_url, 'action=postpass' ) === false );
}

/**
 * Login the user via CAS.
 *
 * @return void
 */
function mu_auth_login_user() {
	// Authenticate the user via CAS.
	$auth_data = mu_auth_authenticate();

	// Get username/MUNet to use below.
	$user = mu_auth_get_user_by_username( $auth_data['user'] );

	// By default site access is not allowed.
	$site_access_allowed = false;

	$supers = array(
		'cmccomas',
		'davis220',
		'bajus',
		'madden24',
		'traube3',
		'schmidt29',
		'lauhon2',
		'burwellb',
		'smith566',
	);

	// Allow users in $supers array to access site.
	if ( in_array( $auth_data['user'], $supers, true ) ) {
		$site_access_allowed = true;
	}

	// Allow WordPress super admins to access all sites.
	if ( $user && is_super_admin( $user->ID ) ) {
		$site_access_allowed = true;
	}

	$selected_user = array();

	// Check if user is in the auth_users ACF field/option.
	$site_users = get_field( 'auth_users', 'option' );

	if ( $site_users && is_array( $site_users ) ) {
		foreach ( $site_users as $site_user ) {
			if ( $auth_data['user'] == trim( $site_user['munet'] ) ) { // phpcs:ignore
				$site_access_allowed = true;
				$selected_user = $site_user; // phpcs:ignore
			}
		}
	}

	// Redirect invalid user to homepage.
	if ( ! $site_access_allowed ) {
		wp_safe_redirect( MUCASAUTH_LOGOUT_REDIRECT_URL . '/?error_code=1' );
		exit;
	}

	// If no WordPress user is found, create a new WordPress user.
	if ( ! $user ) {
		if ( 'v_VitalDesign' === $auth_data['user'] ) {
			$user = mu_auth_create_user(
				$auth_data['user'],
				'Vital',
				'Design',
				'inbound@vtldesign.com',
				'administrator',
				array(),
			);
		} else {
			$user = mu_auth_create_user(
				$auth_data['user'],
				$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_FIRSTNAME ],
				$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_LASTNAME ],
				$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_EMAIL ],
				$selected_user['permissions_level'] ? strtolower( $selected_user['permissions_level'] ) : 'administrator',
				$selected_user,
			);
		}

		// Check for valid created WordPress user.
		if ( ! $user ) {
			wp_safe_redirect( MUCASAUTH_LOGOUT_REDIRECT_URL . '/?error_code=2' );
			exit;
		}
	}

	// Add WordPress user to blog/site if needed.
	if ( $user && ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) && ! is_super_admin( $user->ID ) ) {
		add_user_to_blog( get_current_blog_id(), $user->ID, $selected_user['permissions_level'] ? strtolower( $selected_user['permissions_level'] ) : 'administrator' );
	}

	// Login WordPress user if needed.
	if ( ! is_user_logged_in() ) {
		// Log WordPress user in.
		wp_clear_auth_cookie();
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID );

		// Redirect to dashboard for blog/site.
		$redirect_to = get_dashboard_url();
		wp_safe_redirect( $redirect_to );
		exit;
	}
}

/**
 * Create a new WordPress user.
 *
 * @param string $username The username of the user.
 * @param string $first_name The user's first name.
 * @param string $last_name The user's last name.
 * @param string $email The user's email address.
 * @param string $role The role of the user.
 *
 * @return WP_User|boolean
 */
function mu_auth_create_user( $username, $first_name, $last_name, $email, $role ) {
	$user_data = array(
		'user_pass'     => md5( microtime() ),
		'user_login'    => $username,
		'user_nicename' => $username,
		'user_email'    => $email,
		'display_name'  => $first_name . ' ' . $last_name,
		'first_name'    => $first_name,
		'last_name'     => $last_name,
		'role'          => $role,
	);

	$user = wp_insert_user( $user_data );

	if ( is_wp_error( $user ) ) {
		return false;
	}

	return new \WP_User( $user );
}

/**
 * Get the user by username.
 *
 * @param string $username The username of the user.
 *
 * @return WP_User
 */
function mu_auth_get_user_by_username( $username ) {
	return get_user_by( 'login', $username );
}

/**
 * Authenticate the user via CAS.
 *
 * @return array
 */
function mu_auth_authenticate() {
	if ( ! mu_auth_is_ticket_present() ) {
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		wp_redirect( $login_url ); // phpcs:ignore
		exit;
	}

	$ticket = mu_auth_get_ticket();

	if ( ! $ticket ) {
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		wp_redirect( $login_url ); // phpcs:ignore
		exit;
	}

	$cas_response = (object) mu_auth_validate_cas_ticket( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH, $ticket );

	if ( ! isset( $cas_response->authenticationSuccess ) ) { // phpcs:ignore
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		wp_redirect( $login_url ); // phpcs:ignore
		exit;
	}

	return array(
		'user'       => $cas_response->authenticationSuccess->user, // phpcs:ignore
		'attributes' => json_decode( json_encode( $cas_response->authenticationSuccess->attributes ), true ), // phpcs:ignore
	);
}

/**
 * Validate the CAS ticket.
 *
 * @param string $cas_host The CAS host.
 * @param string $cas_path The CAS path.
 * @param string $ticket The CAS ticket.
 * @return array
 */
function mu_auth_validate_cas_ticket( $cas_host, $cas_path, $ticket ) {
	$validation_url = mu_auth_get_validation_url( $cas_host, $cas_path, $ticket );
	$data           = wp_remote_get( $validation_url );

	$xml = simplexml_load_string( $data['body'] );
	$xml = $xml->children( 'http://www.yale.edu/tp/cas' );

	$json = wp_json_encode( $xml );

	return json_decode( $json, false );
}

/**
 * Get the validation URL.
 *
 * @param string $cas_host The CAS host.
 * @param string $cas_path The CAS path.
 * @param string $ticket The CAS ticket.
 * @return string
 */
function mu_auth_get_validation_url( $cas_host, $cas_path, $ticket ) {
	$service_url = mu_auth_get_service_url_without_ticket();
	return trim( $cas_host, '/' ) . $cas_path . '/p3/serviceValidate?service=' . $service_url . '&ticket=' . $ticket;
}

/**
 * Get the ticket from the query string.
 *
 * @return string|boolean
 */
function mu_auth_get_ticket() {
	parse_str( $_SERVER['QUERY_STRING'], $query_string_parts ); // phpcs:ignore

	if ( ! isset( $query_string_parts['ticket'] ) ) {
		return false;
	}

	return $query_string_parts['ticket'];
}

/**
 * Check if the ticket is present in the query string.
 *
 * @return boolean
 */
function mu_auth_is_ticket_present() {
	$service_url = mu_auth_get_service_url();
	return strpos( urldecode( $service_url ), 'ticket=' );
}

/**
 * Get the service URL.
 *
 * @return string
 */
function mu_auth_get_service_url() {
	$scheme = 'http';

	if ( isset( $_SERVER['HTTP_USER_AGENT_HTTPS'] ) && 'ON' === $_SERVER['HTTP_USER_AGENT_HTTPS'] ) {
		$scheme = 'https';
	}

	$current_url = $scheme . '://' . trim($_SERVER['HTTP_HOST'], '/') . '/' . ltrim($_SERVER['REQUEST_URI'], '/'); // phpcs:ignore

	return rawurlencode( urldecode( $current_url ) );
}

/**
 * Get the login URL.
 *
 * @param string $cas_host The CAS host.
 * @param string $cas_path The CAS path.
 * @return string
 */
function mu_auth_get_login_url( $cas_host, $cas_path ) {
	$service_url = mu_auth_get_service_url_without_ticket();
	return trim( $cas_host, '/' ) . $cas_path . '/login?service=' . $service_url;
}

/**
 * Get the service URL without the ticket.
 *
 * @return string
 */
function mu_auth_get_service_url_without_ticket() {
	$service_url = mu_auth_get_service_url();
	$service_url = urldecode( $service_url );

	$service_url_parts = wp_parse_url( $service_url );
	parse_str( $service_url_parts['query'], $query_string_parts );

	$query_string = '?';
	foreach ( $query_string_parts as $key => $value ) {
		if ( 'ticket' !== $key ) {
			$query_string .= $key . '=' . $value . '&';
		}
	}

	$query_string = rtrim( $query_string, '&' );

	return rawurlencode( $service_url_parts['scheme'] . '://' . $service_url_parts['host'] . $service_url_parts['path'] . $query_string );
}

/**
 * Check if user is logged in, if not log the user in.
 *
 * @return void
 */
function mu_auth_check_login() {
	if ( is_admin() && is_user_logged_in() && ( is_user_member_of_blog( get_current_user_id(), get_current_blog_id() ) || is_super_admin() ) ) {
		return;
	}

	// Check for WordPress login page or authenticated user without a blog role.
	if ( mu_auth_is_wordpress_admin_login() || is_admin() && is_user_logged_in() && ! is_user_member_of_blog( get_current_user_id(), get_current_blog_id() ) ) { // phpcs:ignore
		// Remove existing authentication hook.
		remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );

		// Log User In.
		mu_auth_login_user();
	}
}

if ( isset( $_ENV['PANTHEON_ENVIRONMENT'] ) ) {
	add_action( 'init', 'mu_auth_check_login' );
}
