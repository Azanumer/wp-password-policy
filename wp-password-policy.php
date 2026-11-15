<?php
/**
 * Plugin Name: Password Policy
 * Plugin URI: https://github.com/Azanumer/wp-password-policy
 * Description: Enforce a real password policy — minimum length, character classes, a common-password blocklist and password-reuse history — and force users with weak passwords to change them on next login.
 * Version: 1.0.0
 * Author: Azan Umer
 * Author URI: https://azanumer.cv
 * License: MIT
 * Text Domain: wp-password-policy
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPP_VERSION', '1.0.0' );
define( 'WPP_OPTION', 'wpp_settings' );
define( 'WPP_META_HISTORY', '_wpp_password_history' );
define( 'WPP_META_MUST_CHANGE', '_wpp_must_change_password' );

/**
 * Default settings.
 *
 * @return array
 */
function wpp_default_settings() {
	return array(
		'min_length'    => 12,
		'require_upper' => 1,
		'require_lower' => 1,
		'require_digit' => 1,
		'require_symbol' => 1,
		'history_count' => 5,
		'custom_blocked' => '',
	);
}

/**
 * Get merged settings.
 *
 * @return array
 */
function wpp_get_settings() {
	$saved = get_option( WPP_OPTION, array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}
	return array_merge( wpp_default_settings(), $saved );
}

/**
 * Built-in blocklist of common passwords (lowercase).
 *
 * @return string[]
 */
function wpp_common_passwords() {
	$list = array(
		'password', 'password1', 'passw0rd', '123456', '123456789', '12345678',
		'1234567', '1234567890', '12345', '1234', '123123', '123321', '111111',
		'000000', '654321', 'qwerty', 'qwerty123', 'qwertyuiop', 'abc123',
		'1qaz2wsx', '1q2w3e4r', 'qazwsx', 'letmein', 'welcome', 'admin',
		'admin123', 'changeme', 'wordpress', 'monkey', 'dragon', 'master',
		'football', 'iloveyou', 'sunshine', 'princess', 'shadow', 'superman',
		'michael', '696969', 'trustno1', 'whatever', 'freedom', 'hello',
		'charlie', 'thomas', 'jordan', 'hunter', 'buster', 'soccer', 'harley',
		'batman', 'andrew', 'tigger', 'robert', 'daniel', 'jessica', 'ashley',
		'bailey', 'liverpool', 'chelsea', 'arsenal',
	);
	return apply_filters( 'wpp_common_passwords', $list );
}

/**
 * Full blocklist: built-in plus the admin's custom entries.
 *
 * @return string[]
 */
function wpp_blocked_passwords() {
	$blocked  = wpp_common_passwords();
	$settings = wpp_get_settings();
	$custom   = isset( $settings['custom_blocked'] ) ? (string) $settings['custom_blocked'] : '';
	foreach ( preg_split( "/\r\n|\r|\n/", $custom ) as $line ) {
		$line = strtolower( trim( $line ) );
		if ( '' !== $line ) {
			$blocked[] = $line;
		}
	}
	return array_unique( $blocked );
}

/**
 * Validate a password against the policy.
 *
 * @param string $password Password to check.
 * @param int    $user_id  User ID for the reuse-history check (0 to skip).
 * @return string[] List of failure messages; empty means the password passes.
 */
function wpp_validate_password( $password, $user_id = 0 ) {
	$settings = wpp_get_settings();
	$errors   = array();

	$min = max( 1, (int) $settings['min_length'] );
	if ( strlen( $password ) < $min ) {
		/* translators: %d: minimum password length. */
		$errors[] = sprintf( __( 'Password must be at least %d characters long.', 'wp-password-policy' ), $min );
	}
	if ( ! empty( $settings['require_upper'] ) && ! preg_match( '/[A-Z]/', $password ) ) {
		$errors[] = __( 'Password must contain at least one uppercase letter.', 'wp-password-policy' );
	}
	if ( ! empty( $settings['require_lower'] ) && ! preg_match( '/[a-z]/', $password ) ) {
		$errors[] = __( 'Password must contain at least one lowercase letter.', 'wp-password-policy' );
	}
	if ( ! empty( $settings['require_digit'] ) && ! preg_match( '/[0-9]/', $password ) ) {
		$errors[] = __( 'Password must contain at least one number.', 'wp-password-policy' );
	}
	if ( ! empty( $settings['require_symbol'] ) && ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
		$errors[] = __( 'Password must contain at least one symbol.', 'wp-password-policy' );
	}
	if ( in_array( strtolower( $password ), wpp_blocked_passwords(), true ) ) {
		$errors[] = __( 'That password is too common. Please choose a different one.', 'wp-password-policy' );
	}

	// Reuse check: compare against the stored history hashes.
	if ( $user_id > 0 && ! empty( $settings['history_count'] ) ) {
		$history = get_user_meta( $user_id, WPP_META_HISTORY, true );
		if ( is_array( $history ) ) {
			foreach ( $history as $hash ) {
				if ( wp_check_password( $password, $hash ) ) {
					$errors[] = __( 'You cannot reuse a recent password.', 'wp-password-policy' );
					break;
				}
			}
		}
	}

	return apply_filters( 'wpp_validate_password', $errors, $password, $user_id );
}

/**
 * Record a password hash in the user's reuse history, capped at the
 * configured count. The current password hash is included first so a
 * user can never "reuse" the password they are changing away from.
 *
 * @param int    $user_id  User ID.
 * @param string $password Plaintext password just set.
 */
function wpp_record_password_history( $user_id, $password ) {
	$settings = wpp_get_settings();
	$count    = (int) $settings['history_count'];
	if ( $count <= 0 ) {
		return;
	}
	$history = get_user_meta( $user_id, WPP_META_HISTORY, true );
	if ( ! is_array( $history ) ) {
		$history = array();
	}
	$user = get_userdata( $user_id );
	if ( $user && ! empty( $user->user_pass ) && ! wp_check_password( $password, $user->user_pass ) ) {
		// The stored hash is still the OLD password (profile flow validates
		// before the save) — keep it so the old password cannot be reused.
		// In the reset flow the stored hash already IS the new password,
		// so it is skipped here and recorded once below.
		array_unshift( $history, $user->user_pass );
	}
	$history[] = wp_hash_password( $password );
	$history   = array_values( array_unique( $history ) );
	$history   = array_slice( $history, 0, $count );
	update_user_meta( $user_id, WPP_META_HISTORY, $history );
}

/**
 * Validate on registration.
 *
 * @param WP_Error $errors               Registration errors.
 * @param string   $sanitized_user_login Username.
 * @param string   $user_email           Email address.
 * @return WP_Error
 */
function wpp_registration_errors( $errors, $sanitized_user_login, $user_email ) {
	if ( ! empty( $_POST['user_pass'] ) ) {
		foreach ( wpp_validate_password( wp_unslash( $_POST['user_pass'] ) ) as $message ) {
			$errors->add( 'wpp_password', $message );
		}
	}
	return $errors;
}
add_filter( 'registration_errors', 'wpp_registration_errors', 10, 3 );

/**
 * Validate on profile / user-edit saves, and record the new password in
 * the reuse history when it passes. The plaintext comes from the form
 * field itself — $user->user_pass is not relied on, as its contents at
 * this point differ between WordPress versions.
 *
 * @param WP_Error $errors Registration/profile errors object.
 * @param bool     $update Whether this is an update.
 * @param stdClass $user   User object being saved.
 */
function wpp_profile_update_errors( $errors, $update, $user ) {
	if ( empty( $_POST['pass1'] ) ) {
		return;
	}
	$password = wp_unslash( $_POST['pass1'] );
	$user_id  = isset( $user->ID ) ? (int) $user->ID : 0;
	$failures = wpp_validate_password( $password, $user_id );
	foreach ( $failures as $message ) {
		$errors->add( 'wpp_password', $message );
	}
	if ( empty( $failures ) && $user_id > 0 ) {
		wpp_record_password_history( $user_id, $password );
	}
}
add_action( 'user_profile_update_errors', 'wpp_profile_update_errors', 10, 3 );

/**
 * Validate on password reset.
 *
 * @param WP_Error $errors Reset errors.
 * @param WP_User  $user   User resetting the password.
 */
function wpp_validate_password_reset( $errors, $user ) {
	if ( ! empty( $_POST['pass1'] ) ) {
		foreach ( wpp_validate_password( wp_unslash( $_POST['pass1'] ), $user->ID ) as $message ) {
			$errors->add( 'wpp_password', $message );
		}
	}
}
add_action( 'validate_password_reset', 'wpp_validate_password_reset', 10, 2 );

/**
 * Record the new password in the reuse history after a reset.
 *
 * @param WP_User $user     User who reset.
 * @param string  $new_pass New plaintext password.
 */
function wpp_password_reset_history( $user, $new_pass ) {
	wpp_record_password_history( $user->ID, $new_pass );
	delete_user_meta( $user->ID, WPP_META_MUST_CHANGE );
}
add_action( 'password_reset', 'wpp_password_reset_history', 10, 2 );

/**
 * Flag weak passwords at login time. Runs after the default username/
 * password check (priority 20), so $user is a real user only when the
 * credentials were correct.
 *
 * @param WP_User|WP_Error|null $user     Authenticated user or error.
 * @param string                $username Username.
 * @param string                $password Plaintext password just used.
 * @return WP_User|WP_Error|null
 */
function wpp_flag_weak_password_on_login( $user, $username, $password ) {
	if ( $user instanceof WP_User && '' !== $password ) {
		if ( ! empty( wpp_validate_password( $password, $user->ID ) ) ) {
			update_user_meta( $user->ID, WPP_META_MUST_CHANGE, 1 );
		}
	}
	return $user;
}
add_filter( 'authenticate', 'wpp_flag_weak_password_on_login', 30, 3 );

/**
 * Send users flagged for a password change straight to their profile.
 */
function wpp_redirect_for_password_change() {
	if ( ! is_user_logged_in() ) {
		return;
	}
	$user_id = get_current_user_id();
	if ( ! get_user_meta( $user_id, WPP_META_MUST_CHANGE, true ) ) {
		return;
	}
	// Let AJAX, the profile screen itself and logout through.
	if ( wp_doing_ajax() || ( isset( $GLOBALS['pagenow'] ) && in_array( $GLOBALS['pagenow'], array( 'profile.php', 'user-edit.php' ), true ) ) ) {
		return;
	}
	wp_safe_redirect( admin_url( 'profile.php?wpp_must_change=1' ) );
	exit;
}
add_action( 'admin_init', 'wpp_redirect_for_password_change' );

/**
 * Show the "change your password" notice on the profile screen.
 */
function wpp_must_change_notice() {
	if ( ! is_user_logged_in() ) {
		return;
	}
	$screen = get_current_screen();
	if ( ! $screen || 'profile' !== $screen->id ) {
		return;
	}
	if ( ! get_user_meta( get_current_user_id(), WPP_META_MUST_CHANGE, true ) ) {
		return;
	}
	echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Your password does not meet the current password policy. Please choose a stronger password below.', 'wp-password-policy' ) . '</strong></p></div>';
}
add_action( 'admin_notices', 'wpp_must_change_notice' );

/**
 * Clear the flag once the user saves a compliant password. The flag is
 * removed here rather than in the validation hook because the validation
 * hook runs even when the save is blocked by other errors.
 */
function wpp_clear_must_change_on_save( $user_id ) {
	if ( ! empty( $_POST['pass1'] ) ) {
		delete_user_meta( $user_id, WPP_META_MUST_CHANGE );
	}
}
add_action( 'profile_update', 'wpp_clear_must_change_on_save' );

/**
 * Settings page under Settings → Password Policy.
 */
function wpp_register_settings_page() {
	add_options_page(
		__( 'Password Policy', 'wp-password-policy' ),
		__( 'Password Policy', 'wp-password-policy' ),
		'manage_options',
		'wpp-settings',
		'wpp_render_settings_page'
	);
}
add_action( 'admin_menu', 'wpp_register_settings_page' );

/**
 * Render the settings page.
 */
function wpp_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-password-policy' ) );
	}

	if ( isset( $_POST['wpp_save'] ) ) {
		check_admin_referer( 'wpp_save_settings' );
		$input = wp_unslash( $_POST );
		update_option(
			WPP_OPTION,
			array(
				'min_length'     => max( 1, (int) ( $input['min_length'] ?? 12 ) ),
				'require_upper'  => isset( $input['require_upper'] ) ? 1 : 0,
				'require_lower'  => isset( $input['require_lower'] ) ? 1 : 0,
				'require_digit'  => isset( $input['require_digit'] ) ? 1 : 0,
				'require_symbol' => isset( $input['require_symbol'] ) ? 1 : 0,
				'history_count'  => max( 0, min( 20, (int) ( $input['history_count'] ?? 5 ) ) ),
				'custom_blocked' => isset( $input['custom_blocked'] ) ? sanitize_textarea_field( $input['custom_blocked'] ) : '',
			)
		);
		echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved.', 'wp-password-policy' ) . '</p></div>';
	}

	$settings = wpp_get_settings();
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Password Policy', 'wp-password-policy' ); ?></h1>
		<p><?php esc_html_e( 'Applies to registration, profile password changes and password resets. Users logging in with a password that no longer meets the policy are sent to their profile to change it.', 'wp-password-policy' ); ?></p>
		<form method="post">
			<?php wp_nonce_field( 'wpp_save_settings' ); ?>
			<table class="form-table">
				<tr>
					<th scope="row"><label for="wpp-min"><?php esc_html_e( 'Minimum length', 'wp-password-policy' ); ?></label></th>
					<td><input type="number" id="wpp-min" name="min_length" value="<?php echo (int) $settings['min_length']; ?>" min="1" max="64" /></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Require', 'wp-password-policy' ); ?></th>
					<td>
						<label><input type="checkbox" name="require_upper" value="1" <?php checked( ! empty( $settings['require_upper'] ) ); ?> /> <?php esc_html_e( 'Uppercase letter', 'wp-password-policy' ); ?></label><br />
						<label><input type="checkbox" name="require_lower" value="1" <?php checked( ! empty( $settings['require_lower'] ) ); ?> /> <?php esc_html_e( 'Lowercase letter', 'wp-password-policy' ); ?></label><br />
						<label><input type="checkbox" name="require_digit" value="1" <?php checked( ! empty( $settings['require_digit'] ) ); ?> /> <?php esc_html_e( 'Number', 'wp-password-policy' ); ?></label><br />
						<label><input type="checkbox" name="require_symbol" value="1" <?php checked( ! empty( $settings['require_symbol'] ) ); ?> /> <?php esc_html_e( 'Symbol', 'wp-password-policy' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wpp-history"><?php esc_html_e( 'Remember last N passwords', 'wp-password-policy' ); ?></label></th>
					<td><input type="number" id="wpp-history" name="history_count" value="<?php echo (int) $settings['history_count']; ?>" min="0" max="20" /> <span class="description"><?php esc_html_e( '0 disables the reuse check.', 'wp-password-policy' ); ?></span></td>
				</tr>
				<tr>
					<th scope="row"><label for="wpp-blocked"><?php esc_html_e( 'Extra blocked passwords', 'wp-password-policy' ); ?></label></th>
					<td>
						<textarea id="wpp-blocked" name="custom_blocked" rows="6" cols="40"><?php echo esc_textarea( $settings['custom_blocked'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One per line, in addition to the built-in list of common passwords (e.g. your company or site name).', 'wp-password-policy' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save Settings', 'wp-password-policy' ), 'primary', 'wpp_save' ); ?>
		</form>
	</div>
	<?php
}
