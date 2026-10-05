<?php
/**
 * Plugin Name:     MU Auth
 * Plugin URI:      https://www.marshall.edu
 * Description:     Marshall University SSO authentication for WordPress
 * Author:          Christopher McComas
 * Author URI:      https://www.marshall.edu
 * Version:         1.1.7
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

/**
 * Allow redirects to the CAS host and the logout redirect host.
 *
 * Without the logout host, wp_safe_redirect() falls back to admin_url() on any
 * other domain, which sends logged-out and unauthorized users back through CAS.
 *
 * @param string[] $hosts Allowed redirect hosts.
 * @return string[]
 */
function mu_auth_allowed_redirect_hosts( $hosts ) {
	$hosts[] = wp_parse_url( MUCASAUTH_CAS_HOST, PHP_URL_HOST );
	$hosts[] = wp_parse_url( MUCASAUTH_LOGOUT_REDIRECT_URL, PHP_URL_HOST );
	return $hosts;
}
add_filter( 'allowed_redirect_hosts', 'mu_auth_allowed_redirect_hosts' );

if ( ! class_exists( 'ACF' ) ) {
	return new WP_Error( 'broke', __( 'Advanced Custom Fields is required for this plugin.', 'mu-moments' ) );
}

require plugin_dir_path( __FILE__ ) . '/acf-fields.php';
require plugin_dir_path( __FILE__ ) . '/mu-auth-admin.php';

/**
 * Redirect the user to the homepage after logging out.
 *
 * @return void
 */
function mu_auth_logout_redirect() {
	wp_safe_redirect( MUCASAUTH_LOGOUT_REDIRECT_URL );
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
	$is_evergreen_login = array_key_exists( 'evergreen', $_GET ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

	return (
		( strpos( $current_url, 'wp-login.php' ) !== false || $is_evergreen_login )
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
		'Administrator'    => 'administrator',
		'Editor'           => 'editor',
		'Forms'            => 'gravity_forms_viewer',
		'Profiles'         => 'profiles_manager',
		'Forms & Profiles' => 'forms_profiles_manager',
	);

	return isset( $role_mapping[ $permissions_level ] ) ? $role_mapping[ $permissions_level ] : 'editor';
}

/**
 * Get the role to assign a user on this site.
 *
 * Users listed in the auth_users field get the role for their permissions level.
 * Super users with no auth_users row get Administrator. Anyone else falls back to
 * Editor rather than silently receiving Administrator.
 *
 * @param array $selected_user The matching auth_users row, or an empty array.
 * @param bool  $is_super_user Whether the user is in the mu_auth_super_users list.
 * @return string The WordPress role name.
 */
function mu_auth_get_role_for_user( $selected_user, $is_super_user ) {
	$permissions_level = $selected_user['permissions_level'] ?? '';

	if ( $permissions_level ) {
		return mu_auth_get_role_from_permissions_level( $permissions_level );
	}

	return $is_super_user ? 'administrator' : 'editor';
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

	/**
	 * Filters the list of MU Net IDs that bypass per-site access control checks.
	 * Define this in a private config (e.g. wp-config.php via add_filter) rather
	 * than in this file so NetIDs are not stored in version control.
	 *
	 * @param string[] $supers Array of MU Net IDs.
	 */
	$supers = apply_filters( 'mu_auth_super_users', array() );

	$is_super_user = in_array( $auth_data['user'], $supers, true );

	// Allow users in $supers array to access site.
	if ( $is_super_user ) {
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
		$role = mu_auth_get_role_for_user( $selected_user, $is_super_user );
		$user = mu_auth_create_user(
			$auth_data['user'],
			$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_FIRSTNAME ],
			$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_LASTNAME ],
			$auth_data['attributes'][ MUCASAUTH_CAS_ATTRIBUTE_EMAIL ],
			$role,
		);

		// Check for valid created WordPress user.
		if ( ! $user ) {
			wp_safe_redirect( MUCASAUTH_LOGOUT_REDIRECT_URL . '/?error_code=2' );
			exit;
		}
	}

	// Add WordPress user to blog/site if needed.
	if ( ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) && ! is_super_admin( $user->ID ) ) {
		$role = mu_auth_get_role_for_user( $selected_user, $is_super_user );
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
		'user_pass'     => wp_generate_password( 32 ),
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
	if ( ! mu_auth_is_ticket_present() ) {
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		wp_safe_redirect( $login_url );
		exit;
	}

	$ticket = mu_auth_get_ticket();

	if ( ! $ticket ) {
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		wp_safe_redirect( $login_url );
		exit;
	}

	$cas_response = (object) mu_auth_validate_cas_ticket( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH, $ticket );

	if ( ! isset( $cas_response->authenticationSuccess ) ) { // phpcs:ignore
		$login_url = mu_auth_get_login_url( MUCASAUTH_CAS_HOST, MUCASAUTH_CAS_PATH );
		wp_safe_redirect( $login_url );
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
	if ( function_exists( 'vip_safe_wp_remote_get' ) ) {
		// VIP's defaults (1s timeout, breaker after 3 failures) cause login loops
		// when CAS is slow. Allow 3s, 3 failures, and a 20s retry window.
		$data = vip_safe_wp_remote_get( $validation_url, '', 3, 3, 20 );
	} else {
		// Keep the plugin functional outside WordPress VIP environments.
		$data = wp_remote_get( $validation_url, array( 'timeout' => 3 ) ); // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.wp_remote_get_wp_remote_get
	}

	if ( is_wp_error( $data ) ) {
		return array();
	}

	$xml = simplexml_load_string( wp_remote_retrieve_body( $data ) );

	if ( false === $xml ) {
		return array();
	}

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

	if (
		( isset( $_SERVER['HTTPS'] ) && 'off' !== strtolower( wp_unslash( $_SERVER['HTTPS'] ) ) ) || // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 'https' === strtolower( wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) ) || // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		( isset( $_SERVER['HTTP_USER_AGENT_HTTPS'] ) && 'ON' === $_SERVER['HTTP_USER_AGENT_HTTPS'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
	) {
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
	parse_str( $service_url_parts['query'] ?? '', $query_string_parts );

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
		remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );

		// Log User In.
		mu_auth_login_user();
	}
}

/**
 * Check whether this request is running on a hosted WordPress VIP environment.
 *
 * Uses marshall_is_hosted() when the VIP repo provides it. Otherwise checks
 * VIP_GO_APP_ENVIRONMENT and skips 'local', which vip dev-env also defines.
 *
 * @return bool
 */
function mu_auth_is_vip_hosted() {
	if ( function_exists( 'marshall_is_hosted' ) ) {
		return (bool) marshall_is_hosted();
	}

	return defined( 'VIP_GO_APP_ENVIRONMENT' ) && 'local' !== VIP_GO_APP_ENVIRONMENT;
}

/**
 * Determine whether CAS authentication should be active.
 *
 * Auto-enables on hosted WordPress VIP environments (not vip dev-env) and on
 * Pantheon (which exposes PANTHEON_ENVIRONMENT in the environment), or anywhere
 * MU_AUTH_ENABLE is set.
 *
 * @return bool
 */
function mu_auth_is_enabled() {
	$enabled = mu_auth_is_vip_hosted()
		|| isset( $_ENV['PANTHEON_ENVIRONMENT'] )
		|| getenv( 'MU_AUTH_ENABLE' );

	/**
	 * Filters whether CAS authentication is active.
	 *
	 * Add this filter from a mu-plugin to force CAS on or off on a host that is
	 * not auto-detected.
	 *
	 * @param bool $enabled Whether CAS authentication is enabled.
	 */
	return (bool) apply_filters( 'mu_auth_enabled', $enabled );
}

add_action(
	'plugins_loaded',
	function () {
		if ( mu_auth_is_enabled() ) {
			add_action( 'init', 'mu_auth_check_login' );

			// CAS already enforces MFA, so VIP's forced two-factor would only strip
			// capabilities from CAS users. Return true from this filter to keep it.
			if ( ! apply_filters( 'mu_auth_vip_two_factor_forced', false ) ) {
				add_filter( 'wpcom_vip_is_two_factor_forced', '__return_false' );
			}
		}
	}
);

/**
 * Add a role using the WordPress VIP helper when available.
 *
 * @param string $role The role name.
 * @param string $display_name The role display name.
 * @param array  $capabilities The role capabilities.
 * @return WP_Role|void
 */
function mu_auth_add_role( $role, $display_name, $capabilities ) {
	if ( function_exists( 'wpcom_vip_add_role' ) ) {
		return wpcom_vip_add_role( $role, $display_name, $capabilities );
	}

	// Keep the plugin functional outside WordPress VIP environments.
	return add_role( // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.custom_role_add_role
		$role,
		$display_name,
		$capabilities
	);
}

/**
 * Add capabilities to a role using the WordPress VIP helper when available.
 *
 * The VIP helper saves all capabilities in one write instead of one per cap.
 *
 * @param string   $role_name    The role name.
 * @param string[] $capabilities The capabilities to grant.
 * @return void
 */
function mu_auth_add_role_caps( $role_name, $capabilities ) {
	if ( function_exists( 'wpcom_vip_add_role_caps' ) ) {
		wpcom_vip_add_role_caps( $role_name, $capabilities );
		return;
	}

	$role = get_role( $role_name );

	if ( ! $role ) {
		return;
	}

	// Keep the plugin functional outside WordPress VIP environments.
	foreach ( $capabilities as $capability ) {
		$role->add_cap( $capability ); // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.custom_role_add_cap
	}
}

/**
 * Gravity Forms Viewer Role functionality for MU Auth plugin.
 *
 * @package MU_Auth
 * @since 1.0.2
 */

/**
 * Create the Gravity Forms Viewer role.
 *
 * @return void
 */
function mu_auth_create_gravity_forms_viewer_role() {
	// Check if role already exists to avoid unnecessary processing.
	if ( get_role( 'gravity_forms_viewer' ) ) {
		return;
	}

	// Add the custom role with minimal capabilities.
	mu_auth_add_role(
		'gravity_forms_viewer',
		'Gravity Forms Viewer',
		array(
			// Basic WordPress capabilities needed for admin access.
			'read'                          => true,

			// Gravity Forms specific capabilities.
			'gravityforms_view_entries'     => true,
			'gravityforms_export_entries'   => true,
			'gravityforms_view_entry_notes' => true,
			'gravityforms_edit_entry_notes' => true,
		)
	);
}

/**
 * Check if current user has Gravity Forms Viewer role.
 *
 * @return bool True if user has the role, false otherwise.
 */
function mu_auth_is_gravity_forms_viewer() {
	$user = wp_get_current_user();

	if ( ! $user->exists() ) {
		return false;
	}

	return in_array( 'gravity_forms_viewer', $user->roles, true );
}

/**
 * Remove admin menu items except Gravity Forms for the viewer role.
 *
 * @return void
 */
function mu_auth_restrict_admin_menu_for_gravity_forms_viewer() {
	if ( ! mu_auth_is_gravity_forms_viewer() ) {
		return;
	}

	$menu_items_to_remove = array(
		'index.php',                     // Dashboard.
		'edit.php',                      // Posts.
		'upload.php',                    // Media.
		'edit.php?post_type=page',       // Pages.
		'edit-comments.php',             // Comments.
		'themes.php',                    // Appearance.
		'plugins.php',                   // Plugins.
		'users.php',                     // Users.
		'tools.php',                     // Tools.
		'options-general.php',           // Settings.
	);

	// Remove standard menu items.
	foreach ( $menu_items_to_remove as $menu_item ) {
		remove_menu_page( $menu_item );
	}

	// Remove custom post type menus.
	$custom_post_types = get_post_types(
		array(
			'public'   => true,
			'_builtin' => false,
		)
	);
	foreach ( $custom_post_types as $post_type ) {
		remove_menu_page( 'edit.php?post_type=' . $post_type );
	}
}

/**
 * Hide admin bar items for the Gravity Forms viewer role.
 *
 * @return void
 */
function mu_auth_hide_admin_bar_items_for_gravity_forms_viewer() {
	if ( ! mu_auth_is_gravity_forms_viewer() ) {
		return;
	}

	global $wp_admin_bar;

	// Remove WordPress logo and menu.
	$wp_admin_bar->remove_menu( 'wp-logo' );

	// Remove site name menu.
	$wp_admin_bar->remove_menu( 'site-name' );

	// Remove updates menu.
	$wp_admin_bar->remove_menu( 'updates' );

	// Remove comments menu.
	$wp_admin_bar->remove_menu( 'comments' );

	// Remove new content menu.
	$wp_admin_bar->remove_menu( 'new-content' );
}

/**
 * Redirect Gravity Forms viewer to entries page after login.
 *
 * @param string           $redirect_to The redirect destination URL.
 * @param string           $request     The requested redirect destination URL passed as a parameter.
 * @param WP_User|WP_Error $user        WP_User object on success, WP_Error object on failure.
 *
 * @return string The redirect URL.
 */
function mu_auth_redirect_gravity_forms_viewer_after_login( $redirect_to, $request, $user ) {
	// Ensure we have a valid user object.
	if ( ! is_a( $user, 'WP_User' ) ) {
		return $redirect_to;
	}

	if ( in_array( 'gravity_forms_viewer', $user->roles, true ) ) {
		return admin_url( 'admin.php?page=gf_entries' );
	}

	return $redirect_to;
}

/**
 * Prevent access to other admin pages for Gravity Forms viewer role.
 *
 * @return void
 */
function mu_auth_restrict_admin_access_for_gravity_forms_viewer() {
	if ( ! mu_auth_is_gravity_forms_viewer() ) {
		return;
	}

	global $pagenow;

	// Allow access to admin-ajax.php for AJAX requests.
	if ( 'admin-ajax.php' === $pagenow ) {
		return;
	}

	// Allow access to Gravity Forms pages only.
	$allowed_pages = array(
		'admin.php',
		'admin-post.php', // For form submissions/exports.
	);

	// Check if we're on an allowed page.
	if ( ! in_array( $pagenow, $allowed_pages, true ) ) {
		wp_safe_redirect( admin_url( 'admin.php?page=gf_entries' ) );
		exit;
	}

	// If on admin.php, make sure it's a Gravity Forms page.
	if ( 'admin.php' === $pagenow ) {
		$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$allowed_gf_pages = array(
			'gf_entries',
			'gf_entry_detail',
			'gf_export',
		);

		if ( ! empty( $page ) && ! in_array( $page, $allowed_gf_pages, true ) ) {
			wp_safe_redirect( admin_url( 'admin.php?page=gf_entries' ) );
			exit;
		}
	}
}

/**
 * Customize the admin footer for Gravity Forms viewer role.
 *
 * @param string $text The current admin footer text.
 *
 * @return string The modified admin footer text.
 */
function mu_auth_custom_admin_footer_for_gravity_forms_viewer( $text ) {
	if ( mu_auth_is_gravity_forms_viewer() ) {
		return '<p style="text-align: center; color: #666;">Form Data Viewer Dashboard</p>';
	}

	return $text;
}

/**
 * Initialize Gravity Forms Viewer role functionality.
 * Add this to your plugin's initialization.
 *
 * @return void
 */
function mu_auth_init_gravity_forms_viewer() {
	// Create the role.
	mu_auth_create_gravity_forms_viewer_role();

	// Add hooks.
	add_action( 'admin_menu', 'mu_auth_restrict_admin_menu_for_gravity_forms_viewer', 999 );
	add_action( 'wp_before_admin_bar_render', 'mu_auth_hide_admin_bar_items_for_gravity_forms_viewer' );
	add_filter( 'login_redirect', 'mu_auth_redirect_gravity_forms_viewer_after_login', 10, 3 );
	add_action( 'admin_init', 'mu_auth_restrict_admin_access_for_gravity_forms_viewer' );
	add_filter( 'admin_footer_text', 'mu_auth_custom_admin_footer_for_gravity_forms_viewer' );
}

// Initialize the Gravity Forms Viewer functionality.
add_action( 'init', 'mu_auth_init_gravity_forms_viewer' );

/**
 * Profiles Role functionality for MU Auth plugin.
 *
 * All users with dashboard access can manage Employee posts and Department taxonomy.
 * Users with the "Profiles Manager" role can ONLY manage employees and departments
 * (restricted from all other dashboard functionality).
 *
 * @package MU_Auth
 * @since 1.0.3
 */

/**
 * Create the Profiles Manager role.
 *
 * @return void
 */
function mu_auth_create_profiles_manager_role() {
	// Check if role already exists to avoid unnecessary processing.
	if ( get_role( 'profiles_manager' ) ) {
		return;
	}

	// Add the custom role with employee and department management capabilities.
	mu_auth_add_role(
		'profiles_manager',
		'Profiles Manager',
		array(
			// Basic WordPress capabilities needed for admin access.
			'read'                       => true,

			// Employee post type capabilities.
			'edit_employee'              => true,
			'edit_employees'             => true,
			'edit_others_employees'      => true,
			'publish_employees'          => true,
			'read_employee'              => true,
			'read_private_employees'     => true,
			'delete_employee'            => true,
			'delete_employees'           => true,
			'delete_others_employees'    => true,
			'delete_private_employees'   => true,
			'delete_published_employees' => true,
			'edit_published_employees'   => true,

			// Department taxonomy capabilities.
			'manage_department'          => true,
			'edit_department'            => true,
			'delete_department'          => true,
			'assign_department'          => true,

			// Media library access (usually needed for profile images).
			'upload_files'               => true,
		)
	);
}

/**
 * Grant employee and department capabilities to standard roles.
 * This allows Administrators, Editors, etc. to manage profiles alongside their other duties.
 *
 * @return void
 */
function mu_auth_grant_employee_caps_to_standard_roles() {
	$roles_to_update = array( 'administrator', 'editor', 'author', 'contributor' );

	foreach ( $roles_to_update as $role_name ) {
		$role = get_role( $role_name );

		if ( ! $role ) {
			continue;
		}

		// Check if capabilities are already granted (to avoid running this repeatedly).
		if ( $role->has_cap( 'edit_employees' ) ) {
			continue;
		}

		mu_auth_add_role_caps(
			$role_name,
			array(
				// Employee post type capabilities.
				'edit_employee',
				'edit_employees',
				'edit_others_employees',
				'publish_employees',
				'read_employee',
				'read_private_employees',
				'delete_employee',
				'delete_employees',
				'delete_others_employees',
				'delete_private_employees',
				'delete_published_employees',
				'edit_published_employees',

				// Department taxonomy capabilities.
				'manage_department',
				'edit_department',
				'delete_department',
				'assign_department',
			)
		);
	}
}

/**
 * Check if current user has Profiles Manager role.
 *
 * @return bool True if user has the role, false otherwise.
 */
function mu_auth_is_profiles_manager() {
	$user = wp_get_current_user();

	if ( ! $user->exists() ) {
		return false;
	}

	return in_array( 'profiles_manager', $user->roles, true );
}

/**
 * Remove admin menu items except Employee-related items for the profiles manager role.
 *
 * @return void
 */
function mu_auth_restrict_admin_menu_for_profiles_manager() {
	if ( ! mu_auth_is_profiles_manager() ) {
		return;
	}

	$menu_items_to_remove = array(
		'index.php',                     // Dashboard.
		'edit.php',                      // Posts.
		'edit.php?post_type=page',       // Pages.
		'edit-comments.php',             // Comments.
		'themes.php',                    // Appearance.
		'plugins.php',                   // Plugins.
		'users.php',                     // Users.
		'tools.php',                     // Tools.
		'options-general.php',           // Settings.
	);

	// Remove standard menu items.
	foreach ( $menu_items_to_remove as $menu_item ) {
		remove_menu_page( $menu_item );
	}

	// Remove all custom post type menus except 'employee'.
	$custom_post_types = get_post_types(
		array(
			'public'   => true,
			'_builtin' => false,
		)
	);
	foreach ( $custom_post_types as $post_type ) {
		if ( 'employee' !== $post_type ) {
			remove_menu_page( 'edit.php?post_type=' . $post_type );
		}
	}
}

/**
 * Hide admin bar items for the Profiles Manager role.
 *
 * @return void
 */
function mu_auth_hide_admin_bar_items_for_profiles_manager() {
	if ( ! mu_auth_is_profiles_manager() ) {
		return;
	}

	global $wp_admin_bar;

	// Remove WordPress logo and menu.
	$wp_admin_bar->remove_menu( 'wp-logo' );

	// Remove site name menu (but keep view site).
	$wp_admin_bar->remove_menu( 'site-name' );

	// Remove updates menu.
	$wp_admin_bar->remove_menu( 'updates' );

	// Remove comments menu.
	$wp_admin_bar->remove_menu( 'comments' );

	// Remove new content menu (we'll add specific ones back).
	$wp_admin_bar->remove_menu( 'new-content' );
}

/**
 * Add custom "New Employee" button to admin bar for Profiles Manager.
 *
 * @return void
 */
function mu_auth_add_new_employee_admin_bar() {
	if ( ! mu_auth_is_profiles_manager() ) {
		return;
	}

	global $wp_admin_bar;

	// Add new employee link.
	$wp_admin_bar->add_menu(
		array(
			'id'     => 'new-employee',
			'title'  => '+ New Employee',
			'href'   => admin_url( 'post-new.php?post_type=employee' ),
			'parent' => 'top-secondary',
		)
	);
}

/**
 * Redirect Profiles Manager to employee list after login.
 *
 * @param string           $redirect_to The redirect destination URL.
 * @param string           $request     The requested redirect destination URL passed as a parameter.
 * @param WP_User|WP_Error $user        WP_User object on success, WP_Error object on failure.
 *
 * @return string The redirect URL.
 */
function mu_auth_redirect_profiles_manager_after_login( $redirect_to, $request, $user ) {
	// Ensure we have a valid user object.
	if ( ! is_a( $user, 'WP_User' ) ) {
		return $redirect_to;
	}

	if ( in_array( 'profiles_manager', $user->roles, true ) ) {
		return admin_url( 'edit.php?post_type=employee' );
	}

	return $redirect_to;
}

/**
 * Prevent access to other admin pages for Profiles Manager role.
 *
 * @return void
 */
function mu_auth_restrict_admin_access_for_profiles_manager() {
	if ( ! mu_auth_is_profiles_manager() ) {
		return;
	}

	global $pagenow, $typenow;

	// Allow access to admin-ajax.php for AJAX requests.
	if ( 'admin-ajax.php' === $pagenow ) {
		return;
	}

	// Allow access to media upload for profile images.
	$allowed_pages = array(
		'post.php',
		'post-new.php',
		'edit.php',
		'edit-tags.php',
		'term.php',
		'upload.php',
		'media-upload.php',
		'async-upload.php',
	);

	// Check if we're on an allowed page.
	if ( ! in_array( $pagenow, $allowed_pages, true ) ) {
		wp_safe_redirect( admin_url( 'edit.php?post_type=employee' ) );
		exit;
	}

	// If editing posts, make sure it's the employee post type.
	if ( in_array( $pagenow, array( 'post.php', 'post-new.php', 'edit.php' ), true ) ) {
		$post_type = '';

		if ( 'post-new.php' === $pagenow || 'edit.php' === $pagenow ) {
			$post_type = isset( $_GET['post_type'] ) ? sanitize_text_field( wp_unslash( $_GET['post_type'] ) ) : 'post'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		} elseif ( 'post.php' === $pagenow ) {
			// Check GET parameter first (for viewing/editing).
			if ( isset( $_GET['post'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$post_id   = intval( $_GET['post'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$post_type = get_post_type( $post_id );
			} elseif ( isset( $_POST['post_ID'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$post_id   = intval( $_POST['post_ID'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$post_type = get_post_type( $post_id );
			} elseif ( ! empty( $typenow ) ) {
				$post_type = $typenow;
			}
		}

		if ( 'employee' !== $post_type ) {
			wp_safe_redirect( admin_url( 'edit.php?post_type=employee' ) );
			exit;
		}
	}

	// If editing taxonomies, make sure it's the department taxonomy.
	if ( in_array( $pagenow, array( 'edit-tags.php', 'term.php' ), true ) ) {
		$taxonomy = isset( $_GET['taxonomy'] ) ? sanitize_text_field( wp_unslash( $_GET['taxonomy'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( 'department' !== $taxonomy ) {
			wp_safe_redirect( admin_url( 'edit.php?post_type=employee' ) );
			exit;
		}
	}
}

/**
 * Customize the admin footer for Profiles Manager role.
 *
 * @param string $text The current admin footer text.
 *
 * @return string The modified admin footer text.
 */
function mu_auth_custom_admin_footer_for_profiles_manager( $text ) {
	if ( mu_auth_is_profiles_manager() ) {
		return '<p style="text-align: center; color: #666;">Employee Profiles Dashboard</p>';
	}

	return $text;
}

/**
 * Initialize Profiles Manager role functionality.
 *
 * @return void
 */
function mu_auth_init_profiles_manager() {
	// Create the role.
	mu_auth_create_profiles_manager_role();

	// Grant capabilities to standard roles so they can also manage employees/departments.
	mu_auth_grant_employee_caps_to_standard_roles();

	// Add hooks - restrictions only apply to profiles_manager role.
	add_action( 'admin_menu', 'mu_auth_restrict_admin_menu_for_profiles_manager', 999 );
	add_action( 'wp_before_admin_bar_render', 'mu_auth_hide_admin_bar_items_for_profiles_manager' );
	add_action( 'admin_bar_menu', 'mu_auth_add_new_employee_admin_bar', 999 );
	add_filter( 'login_redirect', 'mu_auth_redirect_profiles_manager_after_login', 10, 3 );
	add_action( 'admin_init', 'mu_auth_restrict_admin_access_for_profiles_manager' );
	add_filter( 'admin_footer_text', 'mu_auth_custom_admin_footer_for_profiles_manager' );
}

// Initialize the Profiles Manager functionality.
add_action( 'init', 'mu_auth_init_profiles_manager' );

/**
 * Forms & Profiles Manager Role functionality for MU Auth plugin.
 *
 * Combined role for users who need access to both Gravity Forms entries
 * and Employee profile management.
 *
 * @package MU_Auth
 * @since 1.1.4
 */

/**
 * Create the Forms & Profiles Manager role.
 *
 * @return void
 */
function mu_auth_create_forms_profiles_manager_role() {
	if ( get_role( 'forms_profiles_manager' ) ) {
		return;
	}

	mu_auth_add_role(
		'forms_profiles_manager',
		'Forms & Profiles Manager',
		array(
			'read'                          => true,

			// Gravity Forms capabilities.
			'gravityforms_view_entries'     => true,
			'gravityforms_export_entries'   => true,
			'gravityforms_view_entry_notes' => true,
			'gravityforms_edit_entry_notes' => true,

			// Employee post type capabilities.
			'edit_employee'                 => true,
			'edit_employees'                => true,
			'edit_others_employees'         => true,
			'publish_employees'             => true,
			'read_employee'                 => true,
			'read_private_employees'        => true,
			'delete_employee'               => true,
			'delete_employees'              => true,
			'delete_others_employees'       => true,
			'delete_private_employees'      => true,
			'delete_published_employees'    => true,
			'edit_published_employees'      => true,

			// Department taxonomy capabilities.
			'manage_department'             => true,
			'edit_department'               => true,
			'delete_department'             => true,
			'assign_department'             => true,

			// Media library access for profile images.
			'upload_files'                  => true,
		)
	);
}

/**
 * Check if current user has Forms & Profiles Manager role.
 *
 * @return bool True if user has the role, false otherwise.
 */
function mu_auth_is_forms_profiles_manager() {
	$user = wp_get_current_user();

	if ( ! $user->exists() ) {
		return false;
	}

	return in_array( 'forms_profiles_manager', $user->roles, true );
}

/**
 * Remove admin menu items for the Forms & Profiles Manager role,
 * keeping Gravity Forms and Employee post type menus.
 *
 * @return void
 */
function mu_auth_restrict_admin_menu_for_forms_profiles_manager() {
	if ( ! mu_auth_is_forms_profiles_manager() ) {
		return;
	}

	$menu_items_to_remove = array(
		'index.php',               // Dashboard.
		'edit.php',                // Posts.
		'edit.php?post_type=page', // Pages.
		'edit-comments.php',       // Comments.
		'themes.php',              // Appearance.
		'plugins.php',             // Plugins.
		'users.php',               // Users.
		'tools.php',               // Tools.
		'options-general.php',     // Settings.
	);

	foreach ( $menu_items_to_remove as $menu_item ) {
		remove_menu_page( $menu_item );
	}

	// Remove custom post type menus except 'employee'.
	$custom_post_types = get_post_types(
		array(
			'public'   => true,
			'_builtin' => false,
		)
	);
	foreach ( $custom_post_types as $post_type ) {
		if ( 'employee' !== $post_type ) {
			remove_menu_page( 'edit.php?post_type=' . $post_type );
		}
	}
}

/**
 * Hide admin bar items for the Forms & Profiles Manager role.
 *
 * @return void
 */
function mu_auth_hide_admin_bar_items_for_forms_profiles_manager() {
	if ( ! mu_auth_is_forms_profiles_manager() ) {
		return;
	}

	global $wp_admin_bar;

	$wp_admin_bar->remove_menu( 'wp-logo' );
	$wp_admin_bar->remove_menu( 'site-name' );
	$wp_admin_bar->remove_menu( 'updates' );
	$wp_admin_bar->remove_menu( 'comments' );
	$wp_admin_bar->remove_menu( 'new-content' );
}

/**
 * Add custom "New Employee" button to admin bar for Forms & Profiles Manager.
 *
 * @return void
 */
function mu_auth_add_new_employee_admin_bar_for_forms_profiles_manager() {
	if ( ! mu_auth_is_forms_profiles_manager() ) {
		return;
	}

	global $wp_admin_bar;

	$wp_admin_bar->add_menu(
		array(
			'id'     => 'new-employee',
			'title'  => '+ New Employee',
			'href'   => admin_url( 'post-new.php?post_type=employee' ),
			'parent' => 'top-secondary',
		)
	);
}

/**
 * Redirect Forms & Profiles Manager to employee list after login.
 *
 * @param string           $redirect_to The redirect destination URL.
 * @param string           $request     The requested redirect destination URL passed as a parameter.
 * @param WP_User|WP_Error $user        WP_User object on success, WP_Error object on failure.
 *
 * @return string The redirect URL.
 */
function mu_auth_redirect_forms_profiles_manager_after_login( $redirect_to, $request, $user ) {
	if ( ! is_a( $user, 'WP_User' ) ) {
		return $redirect_to;
	}

	if ( in_array( 'forms_profiles_manager', $user->roles, true ) ) {
		return admin_url( 'edit.php?post_type=employee' );
	}

	return $redirect_to;
}

/**
 * Prevent access to other admin pages for the Forms & Profiles Manager role.
 *
 * @return void
 */
function mu_auth_restrict_admin_access_for_forms_profiles_manager() {
	if ( ! mu_auth_is_forms_profiles_manager() ) {
		return;
	}

	global $pagenow, $typenow;

	if ( 'admin-ajax.php' === $pagenow ) {
		return;
	}

	$allowed_pages = array(
		'admin.php',       // Gravity Forms.
		'admin-post.php',  // GF exports.
		'post.php',
		'post-new.php',
		'edit.php',
		'edit-tags.php',
		'term.php',
		'upload.php',
		'media-upload.php',
		'async-upload.php',
	);

	if ( ! in_array( $pagenow, $allowed_pages, true ) ) {
		wp_safe_redirect( admin_url( 'edit.php?post_type=employee' ) );
		exit;
	}

	// Restrict admin.php to Gravity Forms pages.
	if ( 'admin.php' === $pagenow ) {
		$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$allowed_gf_pages = array(
			'gf_entries',
			'gf_entry_detail',
			'gf_export',
		);

		if ( ! empty( $page ) && ! in_array( $page, $allowed_gf_pages, true ) ) {
			wp_safe_redirect( admin_url( 'edit.php?post_type=employee' ) );
			exit;
		}
	}

	// Restrict post editing to employee post type.
	if ( in_array( $pagenow, array( 'post.php', 'post-new.php', 'edit.php' ), true ) ) {
		$post_type = '';

		if ( 'post-new.php' === $pagenow || 'edit.php' === $pagenow ) {
			$post_type = isset( $_GET['post_type'] ) ? sanitize_text_field( wp_unslash( $_GET['post_type'] ) ) : 'post'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		} elseif ( 'post.php' === $pagenow ) {
			if ( isset( $_GET['post'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$post_id   = intval( $_GET['post'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$post_type = get_post_type( $post_id );
			} elseif ( isset( $_POST['post_ID'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$post_id   = intval( $_POST['post_ID'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$post_type = get_post_type( $post_id );
			} elseif ( ! empty( $typenow ) ) {
				$post_type = $typenow;
			}
		}

		if ( 'employee' !== $post_type ) {
			wp_safe_redirect( admin_url( 'edit.php?post_type=employee' ) );
			exit;
		}
	}

	// Restrict taxonomy editing to department taxonomy.
	if ( in_array( $pagenow, array( 'edit-tags.php', 'term.php' ), true ) ) {
		$taxonomy = isset( $_GET['taxonomy'] ) ? sanitize_text_field( wp_unslash( $_GET['taxonomy'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( 'department' !== $taxonomy ) {
			wp_safe_redirect( admin_url( 'edit.php?post_type=employee' ) );
			exit;
		}
	}
}

/**
 * Customize the admin footer for Forms & Profiles Manager role.
 *
 * @param string $text The current admin footer text.
 *
 * @return string The modified admin footer text.
 */
function mu_auth_custom_admin_footer_for_forms_profiles_manager( $text ) {
	if ( mu_auth_is_forms_profiles_manager() ) {
		return '<p style="text-align: center; color: #666;">Forms & Profiles Dashboard</p>';
	}

	return $text;
}

/**
 * Initialize Forms & Profiles Manager role functionality.
 *
 * @return void
 */
function mu_auth_init_forms_profiles_manager() {
	mu_auth_create_forms_profiles_manager_role();

	add_action( 'admin_menu', 'mu_auth_restrict_admin_menu_for_forms_profiles_manager', 999 );
	add_action( 'wp_before_admin_bar_render', 'mu_auth_hide_admin_bar_items_for_forms_profiles_manager' );
	add_action( 'admin_bar_menu', 'mu_auth_add_new_employee_admin_bar_for_forms_profiles_manager', 999 );
	add_filter( 'login_redirect', 'mu_auth_redirect_forms_profiles_manager_after_login', 10, 3 );
	add_action( 'admin_init', 'mu_auth_restrict_admin_access_for_forms_profiles_manager' );
	add_filter( 'admin_footer_text', 'mu_auth_custom_admin_footer_for_forms_profiles_manager' );
}

// Initialize the Forms & Profiles Manager functionality.
add_action( 'init', 'mu_auth_init_forms_profiles_manager' );
