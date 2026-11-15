<?php
/**
 * Uninstall handler for Password Policy.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wpp_settings' );
delete_metadata( 'user', 0, '_wpp_password_history', '', true );
delete_metadata( 'user', 0, '_wpp_must_change_password', '', true );
