<?php
/**
 * WordPress Dashboard Settings for MU Auth plugin.
 *
 * @package MU_Auth
 */

if ( is_multisite() ) {
	$capability = 'manage_sites';
} else {
	$capability = 'manage_options';
}

/**
 * Add the options page to the settings menu.
 */
if ( function_exists( 'acf_add_options_page' ) ) {
	acf_add_options_sub_page(
		array(
			'page_title'  => 'MU Auth Settings',
			'menu_title'  => 'MU Auth Settings',
			'parent_slug' => 'options-general.php',
			'capability'  => $capability,
		)
	);
}
