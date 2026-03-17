<?php
/**
 * WordPress Dashboard Settings for MU Auth plugin.
 *
 * @package MU_Auth
 */

/**
 * Add the options page to the settings menu.
 */
add_action(
	'acf/init',
	function () {
		if ( ! function_exists( 'acf_add_options_sub_page' ) ) {
			return;
		}

		$capability = is_multisite() ? 'manage_sites' : 'manage_options';

		acf_add_options_sub_page(
			array(
				'page_title'  => 'MU Auth Settings',
				'menu_title'  => 'MU Auth Settings',
				'parent_slug' => 'options-general.php',
				'capability'  => $capability,
			)
		);
	}
);
