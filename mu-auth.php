<?php
/**
 * Plugin Name:     MU Auth
 * Plugin URI:      https://www.marshall.edu
 * Description:     Marshall University SSO authentication for WordPress
 * Author:          Christopher McComas
 * Author URI:      https://www.marshall.edu
 * Version:         1.0.2
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
	return new WP_Error( 'broke', __( 'Advanced Custom Fields is required for this plugin.', 'mu-auth' ) );
}

require plugin_dir_path( __FILE__ ) . '/acf-fields.php';
require plugin_dir_path( __FILE__ ) . '/mu-auth-admin.php';
require plugin_dir_path( __FILE__ ) . '/forms-users.php';
require plugin_dir_path( __FILE__ ) . '/profiles-users.php';

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
	return (
		( strpos( $current_url, 'wp-login.php' ) !== false || strpos( $current_url, 'evergreen' ) !== false )
		&& strpos( $current_url, 'action=logout' ) === false
		&& strpos( $current_url, 'action=postpass' ) === false
	);
}

/**
 * Convert permissions level to appropriate WordPress role.
 *
 * @param string $permissions_level The permissions level from ACF.
 * @return string The WordPress role name.
 */
function mu_auth_get_role_from_permissions_level( $permissions_level ) {
	$role_mapping = array(
		'Administrator' => 'administrator',
		'Editor'        => 'editor',
		'Forms'         => 'gravity_forms_viewer',
		'Profiles'      => 'profiles_manager',
	);

	return isset( $role_mapping[ $permissions_level ] ) ? $role_mapping[ $permissions_level ] : 'administrator';
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
		'username',
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
		$role = $selected_user['permissions_level'] ? mu_auth_get_role_from_permissions_level( $selected_user['permissions_level'] ) : 'administrator';
		$user = mu_auth_create_user(
			$auth_data['user'],
			$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_FIRSTNAME ],
			$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_LASTNAME ],
			$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_EMAIL ],
			$role
		);

		// Check for valid created WordPress user.
		if ( ! $user ) {
			wp_safe_redirect( MUCASAUTH_LOGOUT_REDIRECT_URL . '/?error_code=2' );
			exit;
		}
	}

	// Add WordPress user to blog/site if needed.
	if ( $user && ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) && ! is_super_admin( $user->ID ) ) {
		$role = $selected_user['permissions_level'] ? mu_auth_get_role_from_permissions_level( $selected_user['permissions_level'] ) : 'administrator';
		add_user_to_blog( get_current_blog_id(), $user->ID, $role );
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
 * @return WP_User|false
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
	mu_auth_debug_log( 'authenticate called' );

	if ( ! mu_auth_is_ticket_present() ) {
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		mu_auth_debug_log( 'authenticate: No ticket, redirecting to CAS', array( 'login_url' => $login_url ) );
		wp_redirect( $login_url ); // phpcs:ignore
		exit;
	}

	$ticket = mu_auth_get_ticket();
	mu_auth_debug_log( 'authenticate: Got ticket', array( 'ticket' => $ticket ) );

	if ( ! $ticket ) {
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		mu_auth_debug_log( 'authenticate: Invalid ticket, redirecting to CAS' );
		wp_redirect( $login_url ); // phpcs:ignore
		exit;
	}

	$cas_response = (object) mu_auth_validate_cas_ticket( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH, $ticket );
	mu_auth_debug_log( 'authenticate: CAS response', array( 'has_success' => isset( $cas_response->authenticationSuccess ) ) ); // phpcs:ignore

	if ( ! isset( $cas_response->authenticationSuccess ) ) { // phpcs:ignore
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		mu_auth_debug_log( 'authenticate: CAS validation failed, redirecting to CAS' );
		wp_redirect( $login_url ); // phpcs:ignore
		exit;
	}

	mu_auth_debug_log( 'authenticate: Success', array( 'user' => $cas_response->authenticationSuccess->user ?? 'unknown' ) ); // phpcs:ignore

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
 * @return object SimpleXML response object on success, or empty object on failure.
 */
function mu_auth_validate_cas_ticket( $cas_host, $cas_path, $ticket ) {
	$validation_url = mu_auth_get_validation_url( $cas_host, $cas_path, $ticket );

	mu_auth_debug_log( 'validate_cas_ticket: Calling CAS', array( // phpcs:ignore
		'validation_url' => $validation_url, // phpcs:ignore
		'decoded_validation_url' => urldecode( $validation_url ),
	)); // phpcs:ignore

	$response = wp_remote_get( $validation_url );

	if ( is_wp_error( $response ) ) {
		mu_auth_debug_log( 'validate_cas_ticket: WP Error', array( 'error' => $response->get_error_message() ) );
		return (object) array();
	}

	$response_code = wp_remote_retrieve_response_code( $response );
	mu_auth_debug_log( 'validate_cas_ticket: Response code', array( 'code' => $response_code ) );

	if ( 200 !== $response_code ) {
		return (object) array();
	}

	$body = wp_remote_retrieve_body( $response );
	mu_auth_debug_log( 'validate_cas_ticket: Response body', array( 'body' => substr( $body, 0, 500 ) ) );

	if ( ! $body ) {
		return (object) array();
	}

	$xml = @simplexml_load_string( $body ); // phpcs:ignore
	if ( ! $xml ) {
		mu_auth_debug_log( 'validate_cas_ticket: Failed to parse XML' );
		return (object) array();
	}

	$xml = $xml->children( 'http://www.yale.edu/tp/cas' );

	$result = json_decode( wp_json_encode( $xml ), false );
	mu_auth_debug_log( 'validate_cas_ticket: Parsed result', array( 'result' => print_r( $result, true ) ) ); // phpcs:ignore

	return $result;
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
	parse_str( $_SERVER['QUERY_STRING'] ?? '', $query_string_parts ); // phpcs:ignore

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
	return strpos( urldecode( $service_url ), 'ticket=' ) !== false;
}

/**
 * Determine if the current request is HTTPS, proxy-aware.
 *
 * @return bool
 */
function mu_auth_is_https_request() {
	// For Forge/Bedrock, always assume HTTPS when MU_AUTH_ENABLE is set.
	if ( getenv( 'MU_AUTH_ENABLE' ) || ( function_exists( 'env' ) && env( 'MU_AUTH_ENABLE' ) ) ) {
		return true;
	}

	// Pantheon-specific check.
	if ( isset( $_SERVER['HTTP_USER_AGENT_HTTPS'] ) && 'ON' === $_SERVER['HTTP_USER_AGENT_HTTPS'] ) {
		return true;
	}

	// Standard HTTPS checks.
	if ( ! empty( $_SERVER['HTTPS'] ) && 'off' !== strtolower( $_SERVER['HTTPS'] ) ) { // phpcs:ignore
		return true;
	}

	// Check for reverse proxy headers.
	if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 'https' === strtolower( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) { // phpcs:ignore
		return true;
	}

	if ( isset( $_SERVER['HTTP_X_FORWARDED_SSL'] ) && 'on' === strtolower( $_SERVER['HTTP_X_FORWARDED_SSL'] ) ) {  // phpcs:ignore
		return true;
	}

	// WordPress helper.
	if ( function_exists( 'is_ssl' ) && is_ssl() ) {
		return true;
	}

	return false;
}

/**
 * Get the service URL.
 *
 * @return string
 */
function mu_auth_get_service_url() {
	$scheme = mu_auth_is_https_request() ? 'https' : 'http';

	// Prefer forwarded host if present (behind proxy/load balancer).
	$host = '';
	if ( ! empty( $_SERVER['HTTP_X_FORWARDED_HOST'] ) ) {
		$host = trim( (string) $_SERVER['HTTP_X_FORWARDED_HOST'] ); // phpcs:ignore
	} elseif ( ! empty( $_SERVER['HTTP_HOST'] ) ) {
		$host = trim( (string) $_SERVER['HTTP_HOST'] ); // phpcs:ignore
	}

	$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/'; // phpcs:ignore

	// Build the URL.
	$current_url = $scheme . '://' . rtrim( $host, '/' ) . '/' . ltrim( $uri, '/' );

	mu_auth_debug_log(
		'get_service_url',
		array(
			'scheme'   => $scheme,
			'host'     => $host,
			'uri'      => $uri,
			'full_url' => $current_url,
		)
	);

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
	$service_url = urldecode( mu_auth_get_service_url() );
	$parts       = wp_parse_url( $service_url );

	$scheme = $parts['scheme'] ?? 'https';
	$host   = $parts['host'] ?? '';
	$path   = $parts['path'] ?? '/';

	$qs = array();
	if ( ! empty( $parts['query'] ) ) {
		parse_str( $parts['query'], $qs );
		unset( $qs['ticket'] );
	}

	$rebuilt = $scheme . '://' . $host . $path;
	if ( ! empty( $qs ) ) {
		$rebuilt .= '?' . http_build_query( $qs );
	}

	return rawurlencode( $rebuilt );
}

/**
 * Check if user is logged in, if not log the user in.
 *
 * @return void
 */
function mu_auth_check_login() {
	mu_auth_debug_log(
		'check_login called',
		array(
			'is_admin'     => is_admin(),
			'is_logged_in' => is_user_logged_in(),
			'request_uri'  => $_SERVER['REQUEST_URI'] ?? '', // phpcs:ignore
			'has_ticket'   => isset( $_GET['ticket'] ) ? 'yes' : 'no', // phpcs:ignore
		)
	);

	if ( is_admin() && is_user_logged_in() && ( is_user_member_of_blog( get_current_user_id(), get_current_blog_id() ) || is_super_admin() ) ) {
		mu_auth_debug_log( 'check_login: User already authenticated and has access - returning' );
		return;
	}

	// Check for WordPress login page or authenticated user without a blog role.
	if ( mu_auth_is_wordpress_admin_login() || ( is_admin() && is_user_logged_in() && ! is_user_member_of_blog( get_current_user_id(), get_current_blog_id() ) ) ) {
		mu_auth_debug_log( 'check_login: Triggering login process' );

		// Remove existing authentication hook.
		remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );

		// Log User In.
		mu_auth_login_user();
	}
}

/**
 * Debug logging function - REMOVE AFTER DEBUGGING
 *
 * @param string $message The message to log.
 * @param mixed  $data    Optional. Additional data to log.
 * @return void
 */
function mu_auth_debug_log( $message, $data = null ) {
	if ( defined( 'WP_CONTENT_DIR' ) ) {
		$log_file = WP_CONTENT_DIR . '/mu-auth-debug.log';
	} else {
		// Fallback for standard WordPress.
		$log_file = dirname( __FILE__ ) . '/mu-auth-debug.log'; // phpcs:ignore
	}

	$timestamp = date( 'Y-m-d H:i:s' );// phpcs:ignore
	$log_message = "[{$timestamp}] {$message}";

	if ( $data !== null ) { // phpcs:ignore
		$log_message .= ' | Data: ' . print_r( $data, true ); // phpcs:ignore
	}

	$log_message .= "\n";

	file_put_contents( $log_file, $log_message, FILE_APPEND ); // phpcs:ignore
}

if ( isset( $_ENV['PANTHEON_ENVIRONMENT'] ) || getenv( 'MU_AUTH_ENABLE' ) ) {
	add_action( 'init', 'mu_auth_check_login' );
}
