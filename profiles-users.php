<?php
/**
 * Profiles Users
 *
 * @package mu-auth
 */

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
	add_role(
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

		// Employee post type capabilities.
		$role->add_cap( 'edit_employee' );
		$role->add_cap( 'edit_employees' );
		$role->add_cap( 'edit_others_employees' );
		$role->add_cap( 'publish_employees' );
		$role->add_cap( 'read_employee' );
		$role->add_cap( 'read_private_employees' );
		$role->add_cap( 'delete_employee' );
		$role->add_cap( 'delete_employees' );
		$role->add_cap( 'delete_others_employees' );
		$role->add_cap( 'delete_private_employees' );
		$role->add_cap( 'delete_published_employees' );
		$role->add_cap( 'edit_published_employees' );

		// Department taxonomy capabilities.
		$role->add_cap( 'manage_department' );
		$role->add_cap( 'edit_department' );
		$role->add_cap( 'delete_department' );
		$role->add_cap( 'assign_department' );
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
