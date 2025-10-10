<?php
/**
 * Forms Users
 *
 * @package mu-auth
 */

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
	add_role(
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
