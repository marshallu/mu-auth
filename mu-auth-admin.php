<?php
/**
 * WordPress Dashboard Settings for MU Auth plugin.
 *
 * @package MU_Auth
 */

/**
 * Add the options page to the settings menu.
 */
if ( function_exists( 'acf_add_options_page' ) ) {
	acf_add_options_sub_page(
		array(
			'page_title'    => 'MU Auth Settings',
			'menu_title'    => 'MU Auth Settings',
			'parent_slug'   => 'options-general.php',
			'capability'    => 'manage_sites',
		)
	);
}

// function mu_auth_confirm_email() {
// 	$screen = get_current_screen();
// 	$old = get_field( 'auth_users', 'option' );
// 	$munets = [];

// 	foreach ( $old as $key => $value ) {
// 		$munets[] = $value['munet'];
// 	}

// 	if ( true == strpos( $screen->id, 'mu-auth-settings' ) ) {
// 		$new = $_POST['acf'];

// 		foreach ( $new['field_662a8863eb9d6'] as $key => $value ) {
// 			foreach( $value as $k => $v ) {
// 				if ( ! in_array( $v, $munets ) ) {
// 					print( 'key: ' . $k . ' value: ' . $v );
// 				}
// 			}
// 			// $to = $value;
// 			// $subject = 'Confirm your email address';
// 			// $message = 'Please confirm your email address by clicking the link below';
// 			// $headers = array( 'Content-Type: text/html; charset=UTF-8' );

// 			// wp_mail( $to, $subject, $message, $headers );
// 		}
// 		die('her');
// 	}
// }
// add_action( 'acf/save_post', 'mu_auth_confirm_email', 20 );
