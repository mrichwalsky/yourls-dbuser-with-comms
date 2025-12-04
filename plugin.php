<?php
/*
Plugin Name: Better User Management for YouRLs
Plugin URI: https://github.com/mrichwalsky/yourls-dbuser-with-comms
Description: Enhanced user management for YOURLS with email support, temporary password generation, and password reset functionality. A fork of https://github.com/RayHollister/database-users-for-YOURLS that adds email notifications and improved security features including temporary password generation and mbanner promoting password reset on first login.
Version: 2.0.0
Author: Gas Mark 8, Ltd.
Author URI: https://gasmark8.com
*/

// No direct access.
if( !defined( 'YOURLS_ABSPATH' ) ) {
    die();
}

db_users_bootstrap();

yourls_add_action( 'plugins_loaded', 'db_users_register_pages' );
yourls_add_action( 'login', 'db_users_handle_login' );
yourls_add_filter( 'admin_sublinks', 'db_users_move_menu_link' );

// Hook into admin page head to add banner styles
yourls_add_action( 'html_head', 'db_users_add_banner_styles' );

// Hook into admin page after logo to show banner if needed
yourls_add_action( 'html_logo', 'db_users_display_password_reset_banner' );

/**
 * Prepare database and credential cache.
 *
 * @return void
 */
function db_users_bootstrap() {
    $created  = db_users_ensure_table_exists();
    $migrated = db_users_migrate_schema();
    $imported = db_users_import_legacy_credentials();

    db_users_initialize_credentials_cache( $created || $imported );
}

/**
 * Return table name used by the plugin.
 *
 * @return string
 */
function db_users_table_name() {
    return YOURLS_DB_PREFIX . 'user_credentials';
}

/**
 * Get database helper.
 *
 * @return \YOURLS\Database\YDB
 */
function db_users_db() {
    return yourls_get_db();
}

/**
 * Retrieve a stored plugin option.
 *
 * @param string $name
 * @param mixed $default
 * @return mixed
 */
function db_users_get_option( $name, $default = null ) {
    $value = yourls_get_option( $name );

    return $value === false ? $default : $value;
}

/**
 * Persist a plugin option value.
 *
 * @param string $name
 * @param mixed  $value
 * @return void
 */
function db_users_set_option( $name, $value ) {
    yourls_update_option( $name, $value );
}

/**
 * Ensure the credential table exists.
 *
 * @return bool True when the table creation SQL ran.
 */
function db_users_ensure_table_exists() {
    $option_flag = (int) db_users_get_option( 'db_users_table_created', 0 );
    if( $option_flag === 1 ) {
        return false;
    }

    $table = db_users_table_name();

    $sql = 'CREATE TABLE IF NOT EXISTS `' . $table . '` (' .
        '`id` int unsigned NOT NULL AUTO_INCREMENT,' .
        '`user_login` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,' .
        '`user_pass` varchar(255) COLLATE utf8mb4_bin NOT NULL,' .
        '`user_role` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT \'user\',' .
        '`email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,' .
        '`needs_password_reset` tinyint(1) NOT NULL DEFAULT 0,' .
        '`created_at` datetime NOT NULL,' .
        '`updated_at` datetime NOT NULL,' .
        'PRIMARY KEY (`id`),' .
        'UNIQUE KEY `user_login` (`user_login`)' .
    ') DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;';

    try {
        db_users_db()->perform( $sql );
        db_users_set_option( 'db_users_table_created', 1 );
        return true;
    } catch ( \Exception $e ) {
        yourls_debug_log( 'db-users table creation failed: ' . $e->getMessage() );
        return false;
    }
}

/**
 * Migrate database schema to add new columns if they don't exist.
 *
 * @return bool True when migration SQL ran.
 */
function db_users_migrate_schema() {
    $option_flag = (int) db_users_get_option( 'db_users_schema_migrated', 0 );
    if( $option_flag === 1 ) {
        return false;
    }

    $table = db_users_table_name();
    $migrated = false;

    try {
        // Check if email column exists
        $email_exists = db_users_db()->fetchValue(
            "SELECT COUNT(*) FROM information_schema.COLUMNS 
             WHERE TABLE_SCHEMA = DATABASE() 
             AND TABLE_NAME = :table 
             AND COLUMN_NAME = 'email'",
            [ 'table' => $table ]
        );

        if( !$email_exists ) {
            db_users_db()->perform( "ALTER TABLE `$table` ADD COLUMN `email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL" );
            $migrated = true;
        }

        // Check if needs_password_reset column exists
        $reset_exists = db_users_db()->fetchValue(
            "SELECT COUNT(*) FROM information_schema.COLUMNS 
             WHERE TABLE_SCHEMA = DATABASE() 
             AND TABLE_NAME = :table 
             AND COLUMN_NAME = 'needs_password_reset'",
            [ 'table' => $table ]
        );

        if( !$reset_exists ) {
            db_users_db()->perform( "ALTER TABLE `$table` ADD COLUMN `needs_password_reset` tinyint(1) NOT NULL DEFAULT 0" );
            $migrated = true;
        }

        if( $migrated ) {
            db_users_set_option( 'db_users_schema_migrated', 1 );
        }

        return $migrated;
    } catch ( \Exception $e ) {
        // Fallback: try simpler ALTER TABLE without information_schema check
        try {
            db_users_db()->perform( "ALTER TABLE `$table` ADD COLUMN `email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL" );
            $migrated = true;
        } catch ( \Exception $e2 ) {
            // Column might already exist, ignore
        }

        try {
            db_users_db()->perform( "ALTER TABLE `$table` ADD COLUMN `needs_password_reset` tinyint(1) NOT NULL DEFAULT 0" );
            $migrated = true;
        } catch ( \Exception $e3 ) {
            // Column might already exist, ignore
        }

        if( $migrated ) {
            db_users_set_option( 'db_users_schema_migrated', 1 );
        }

        return $migrated;
    }
}

/**
 * Import credentials from config.php if table is empty.
 *
 * @return bool True when any credentials were imported.
 */
function db_users_import_legacy_credentials() {
    $option_flag = (int) db_users_get_option( 'db_users_legacy_imported', 0 );
    if( $option_flag === 1 ) {
        return false;
    }

    $table = db_users_table_name();
    $count = (int) db_users_db()->fetchValue( "SELECT COUNT(*) FROM `$table`" );

    $imported = false;

    if( $count === 0 ) {
        global $yourls_user_passwords;

        if( !empty( $yourls_user_passwords ) && is_array( $yourls_user_passwords ) ) {
            $now = db_users_now();

            foreach( $yourls_user_passwords as $username => $password ) {
                $username = db_users_sanitize_username( $username );
                if( $username === '' ) {
                    continue;
                }

                $stored_password = db_users_normalize_password_storage( $password );
                // Preserve current access level for existing users.
                // Legacy imports don't need password reset (they already have valid passwords)
                if( db_users_insert_user( $username, $stored_password, 'admin', null, false, $now ) ) {
                    $imported = true;
                }
            }
        }
    }

    db_users_set_option( 'db_users_legacy_imported', 1 );

    return $imported;
}

/**
 * Refresh the global YOURLS credential cache with DB values.
 *
 * @return array<string,string>
 */
function db_users_refresh_credentials_cache() {
    $table = db_users_table_name();
    $rows  = db_users_db()->fetchObjects( "SELECT user_login, user_pass, user_role FROM `$table` ORDER BY user_login ASC" );

    $credentials = [];
    $roles       = [];

    if( $rows ) {
        foreach( $rows as $row ) {
            $credentials[ $row->user_login ] = $row->user_pass;
            $roles[ $row->user_login ]       = $row->user_role;
        }
    }

    $GLOBALS['yourls_user_passwords'] = $credentials;
    $GLOBALS['db_users_roles']         = $roles;

    db_users_store_cached_credentials_payload( $credentials, $roles );

    return $credentials;
}

/**
 * Initialize cached credentials, optionally forcing a refresh.
 *
 * @param bool $force_refresh
 * @return array<string,string>
 */
function db_users_initialize_credentials_cache( $force_refresh = false ) {
    if( $force_refresh ) {
        return db_users_refresh_credentials_cache();
    }

    $payload = db_users_get_cached_credentials_payload();

    if( is_array( $payload ) ) {
        $credentials = isset( $payload['credentials'] ) && is_array( $payload['credentials'] ) ? $payload['credentials'] : [];
        $roles       = isset( $payload['roles'] ) && is_array( $payload['roles'] ) ? $payload['roles'] : [];

        $GLOBALS['yourls_user_passwords'] = $credentials;
        $GLOBALS['db_users_roles']         = $roles;

        return $credentials;
    }

    return db_users_refresh_credentials_cache();
}

/**
 * Fetch cached credentials payload from options.
 *
 * @return array<string,mixed>|null
 */
function db_users_get_cached_credentials_payload() {
    $payload = db_users_get_option( 'db_users_credentials_cache' );

    return is_array( $payload ) ? $payload : null;
}

/**
 * Store credential and role cache in options.
 *
 * @param array<string,string> $credentials
 * @param array<string,string> $roles
 * @return void
 */
function db_users_store_cached_credentials_payload( array $credentials, array $roles ) {
    db_users_set_option( 'db_users_credentials_cache', [
        'credentials' => $credentials,
        'roles'       => $roles,
        'updated_at'  => db_users_now(),
    ] );
}

/**
 * Record user role after login succeeds.
 *
 * @return void
 */
function db_users_handle_login() {
    if( !defined( 'YOURLS_USER' ) ) {
        return;
    }

    $role = db_users_get_role( YOURLS_USER );
    if( !defined( 'YOURLS_USER_ROLE' ) ) {
        define( 'YOURLS_USER_ROLE', $role ?: 'user' );
    }
}


/**
 * Register plugin admin pages (implemented later).
 *
 * @return void
 */
function db_users_register_pages() {
    yourls_register_plugin_page( 'db_users', yourls__( 'User Accounts' ), 'db_users_render_admin_page' );
    yourls_register_plugin_page( 'db_users_reset_password', yourls__( 'Reset Password' ), 'db_users_render_password_reset_page' );
}

/**
 * Insert a new user row.
 *
 * @param string $username            Username.
 * @param string $stored_password     Stored password with prefix (phpass/md5/plain).
 * @param string $role                Role name.
 * @param string|null $email          Optional email address.
 * @param bool $needs_password_reset  Whether user needs to reset password (default true).
 * @param string|null $timestamp      Optional timestamp to reuse for creation/update.
 * @return bool
 */
function db_users_insert_user( $username, $stored_password, $role = 'user', $email = null, $needs_password_reset = true, $timestamp = null ) {
    $username        = db_users_sanitize_username( $username );
    $stored_password = (string) $stored_password;
    $role            = db_users_sanitize_role( $role );
    $email           = $email ? db_users_sanitize_email( $email ) : null;
    $needs_reset     = (bool) $needs_password_reset;

    if( $username === '' || $stored_password === '' ) {
        return false;
    }

    $now = $timestamp ?: db_users_now();

    $sql = "INSERT INTO `" . db_users_table_name() . "` (user_login, user_pass, user_role, email, needs_password_reset, created_at, updated_at)
            VALUES (:login, :pass, :role, :email, :needs_reset, :created, :updated)";

    try {
        db_users_db()->fetchAffected( $sql, [
            'login'       => $username,
            'pass'        => $stored_password,
            'role'        => $role,
            'email'       => $email,
            'needs_reset' => $needs_reset ? 1 : 0,
            'created'     => $now,
            'updated'     => $now,
        ] );

        return true;
    } catch ( \Exception $e ) {
        yourls_debug_log( 'db-users insert failed: ' . $e->getMessage() );
        return false;
    }
}

/**
 * Public helper to add a user with a plain password.
 *
 * @param string $username
 * @param string $password
 * @param string $role
 * @param string|null $email
 * @param bool $needs_password_reset
 * @return bool
 */
function db_users_add_user( $username, $password, $role = 'user', $email = null, $needs_password_reset = true ) {
    $username = db_users_sanitize_username( $username );
    $password = (string) $password;

    if( $username === '' || $password === '' ) {
        return false;
    }

    $stored = db_users_normalize_password_storage( $password );

    return db_users_insert_user( $username, $stored, $role, $email, $needs_password_reset );
}

/**
 * Generate a secure temporary password.
 *
 * @param int $length Password length (default 16).
 * @return string
 */
function db_users_generate_temp_password( $length = 16 ) {
    // Generate a cryptographically secure random password
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    $password = '';
    $max = strlen( $characters ) - 1;

    // Use random_bytes for cryptographically secure randomness
    for( $i = 0; $i < $length; $i++ ) {
        if( function_exists( 'random_int' ) ) {
            $password .= $characters[ random_int( 0, $max ) ];
        } else {
            // Fallback to mt_rand if random_int is not available
            $password .= $characters[ mt_rand( 0, $max ) ];
        }
    }

    return $password;
}

/**
 * Normalize stored password format.
 *
 * @param mixed $password Raw password or stored hash from config.
 * @return string
 */
function db_users_normalize_password_storage( $password ) {
    $password = (string) $password;

    if( db_users_is_phpass_password( $password ) ) {
        $hash = substr( $password, 7 );
        $hash = str_replace( '!', '$', $hash );

        return 'phpass:' . $hash;
    }

    if( db_users_is_md5_password( $password ) ) {
        return $password;
    }

    $hash = yourls_phpass_hash( $password );

    return 'phpass:' . $hash;
}

/**
 * Tell if stored password is a phpass hash.
 *
 * @param string $password
 * @return bool
 */
function db_users_is_phpass_password( $password ) {
    return ( strpos( $password, 'phpass:' ) === 0 );
}

/**
 * Tell if stored password is an md5 hash.
 *
 * @param string $password
 * @return bool
 */
function db_users_is_md5_password( $password ) {
    return ( strpos( $password, 'md5:' ) === 0 );
}

/**
 * Check if a submitted password matches stored credentials.
 *
 * @param string $stored
 * @param string $submitted
 * @return bool
 */
function db_users_password_matches( $stored, $submitted ) {
    $stored    = (string) $stored;
    $submitted = (string) $submitted;

    if( db_users_is_phpass_password( $stored ) ) {
        $hash = substr( $stored, 7 );
        $hash = str_replace( '!', '$', $hash );

        return yourls_phpass_check( $submitted, $hash );
    }

    if( db_users_is_md5_password( $stored ) ) {
        $parts = explode( ':', $stored );
        if( count( $parts ) === 3 ) {
            list( , $salt, ) = $parts;
            return $stored === 'md5:' . $salt . ':' . md5( $salt . $submitted );
        }
    }

    return $stored === $submitted;
}

/**
 * Verify a user's password against stored credentials.
 *
 * @param string $username
 * @param string $password
 * @return bool
 */
function db_users_verify_password( $username, $password ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    $credentials = $GLOBALS['yourls_user_passwords'] ?? [];

    if( !isset( $credentials[ $username ] ) ) {
        db_users_refresh_credentials_cache();
        $credentials = $GLOBALS['yourls_user_passwords'] ?? [];
    }

    if( !isset( $credentials[ $username ] ) ) {
        return false;
    }

    return db_users_password_matches( $credentials[ $username ], $password );
}

/**
 * Sanitize usernames.
 *
 * @param string $username
 * @return string
 */
function db_users_sanitize_username( $username ) {
    $username = trim( (string) $username );

    return preg_replace( '/[^A-Za-z0-9_\-\.@]/', '', $username );
}

/**
 * Sanitize role string.
 *
 * @param string $role
 * @return string
 */
function db_users_sanitize_role( $role ) {
    $role = strtolower( trim( (string) $role ) );

    if( !in_array( $role, [ 'admin', 'user' ], true ) ) {
        $role = 'user';
    }

    return $role;
}

/**
 * Sanitize email address.
 *
 * @param string $email
 * @return string
 */
function db_users_sanitize_email( $email ) {
    $email = trim( (string) $email );
    $email = filter_var( $email, FILTER_SANITIZE_EMAIL );

    return $email;
}

/**
 * Provide the current timestamp string.
 *
 * @return string
 */
function db_users_now() {
    return date( 'Y-m-d H:i:s' );
}

/**
 * Load PHPMailer library.
 *
 * @return bool True if PHPMailer is available.
 */
function db_users_load_phpmailer() {
    static $phpmailer_loaded = null;
    
    if( $phpmailer_loaded !== null ) {
        return $phpmailer_loaded;
    }
    
    $phpmailer_loaded = false;
    
    // Try to load from plugin directory first (most reliable)
    $plugin_path = dirname( __FILE__ );
    if( file_exists( $plugin_path . '/vendor/autoload.php' ) ) {
        require_once $plugin_path . '/vendor/autoload.php';
        if( class_exists( 'PHPMailer\PHPMailer\PHPMailer' ) ) {
            $phpmailer_loaded = true;
            return true;
        }
    }

    // Try to load via Composer autoload from YOURLS root
    if( file_exists( YOURLS_ABSPATH . '/vendor/autoload.php' ) ) {
        require_once YOURLS_ABSPATH . '/vendor/autoload.php';
        if( class_exists( 'PHPMailer\PHPMailer\PHPMailer' ) ) {
            $phpmailer_loaded = true;
            return true;
        }
    }

    return false;
}

/**
 * Send email using PHPMailer.
 *
 * @param string $to      Recipient email address.
 * @param string $subject Email subject.
 * @param string $body    Email body (plain text).
 * @return bool True on success, false on failure.
 */
function db_users_send_email( $to, $subject, $body ) {
    if( !db_users_load_phpmailer() ) {
        yourls_debug_log( 'db-users: PHPMailer not available. Install via Composer: composer require phpmailer/phpmailer' );
        return false;
    }

    // Get SMTP settings from YOURLS config
    $smtp_host = defined( 'YOURLS_SMTP_HOST' ) ? YOURLS_SMTP_HOST : '';
    $smtp_user = defined( 'YOURLS_SMTP_USER' ) ? YOURLS_SMTP_USER : '';
    $smtp_pass = defined( 'YOURLS_SMTP_PASS' ) ? YOURLS_SMTP_PASS : '';
    $smtp_port = defined( 'YOURLS_SMTP_PORT' ) ? YOURLS_SMTP_PORT : 587;

    if( empty( $smtp_host ) || empty( $smtp_user ) || empty( $smtp_pass ) ) {
        yourls_debug_log( 'db-users: SMTP settings not configured in config.php. Define YOURLS_SMTP_HOST, YOURLS_SMTP_USER, YOURLS_SMTP_PASS, and YOURLS_SMTP_PORT.' );
        return false;
    }

    try {
        $mail = new \PHPMailer\PHPMailer\PHPMailer( true );

        // SMTP configuration
        $mail->isSMTP();
        $mail->Host       = $smtp_host;
        $mail->SMTPAuth   = true;
        $mail->Username   = $smtp_user;
        $mail->Password   = $smtp_pass;
        $mail->SMTPSecure = $smtp_port == 465 ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = $smtp_port;
        $mail->CharSet    = 'UTF-8';

        // Email content
        $from_email = defined( 'YOURLS_SMTP_FROM' ) ? YOURLS_SMTP_FROM : $smtp_user;
        $from_name  = defined( 'YOURLS_SMTP_FROM_NAME' ) ? YOURLS_SMTP_FROM_NAME : 'YOURLS Admin';
        $mail->setFrom( $from_email, $from_name );
        $mail->addAddress( $to );
        $mail->Subject = $subject;
        $mail->Body    = $body;
        $mail->isHTML( false );

        $mail->send();
        return true;
    } catch ( \Exception $e ) {
        yourls_debug_log( 'db-users: Email sending failed: ' . $e->getMessage() );
        return false;
    }
}

/**
 * Retrieve cached roles.
 *
 * @return array<string,string>
 */
function db_users_get_role_map() {
    return $GLOBALS['db_users_roles'] ?? [];
}

/**
 * Get role for a username.
 *
 * @param string $username
 * @return string|null
 */
function db_users_get_role( $username ) {
    $roles = db_users_get_role_map();

    return $roles[ $username ] ?? null;
}

/**
 * Check if a username has the admin role.
 *
 * @param string|null $username
 * @return bool
 */
function db_users_is_admin( $username = null ) {
    if( $username === null ) {
        if( !defined( 'YOURLS_USER' ) ) {
            return false;
        }
        $username = YOURLS_USER;
    }

    return db_users_get_role( $username ) === 'admin';
}

/**
 * Add CSS styles for password reset banner.
 *
 * @return void
 */
function db_users_add_banner_styles() {
    // Only show on admin pages
    if( !defined( 'YOURLS_USER' ) ) {
        return;
    }
    
    // Check if we're on the password reset page
    $current_page = isset( $_GET['page'] ) ? $_GET['page'] : '';
    $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
    $is_reset_page = ( $current_page === 'db_users_reset_password' || strpos( $request_uri, 'page=db_users_reset_password' ) !== false );
    
    $current_user = db_users_get_user( YOURLS_USER );
    if( $current_user && ( $current_user->needs_password_reset == 1 || $current_user->needs_password_reset === '1' ) ) {
        echo '<style>
        .db-users-password-reset-banner {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 4px;
            padding: 1.5em;
            margin: 1em 0 2em;
            color: #856404;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .db-users-password-reset-banner h3 {
            margin-top: 0;
            color: #856404;
            font-size: 1.2em;
        }
        .db-users-password-reset-banner p {
            margin: 0.5em 0;
        }
        .db-users-password-reset-banner .button-primary {
            background: #ffc107;
            border-color: #ff9800;
            color: #000;
            font-weight: bold;
            padding: 0.5em 1.5em;
            text-decoration: none;
            display: inline-block;
            border-radius: 3px;
        }
        .db-users-password-reset-banner .button-primary:hover {
            background: #ff9800;
            border-color: #f57c00;
        }
        </style>';
    }
}

/**
 * Display password reset banner on admin pages if user needs to reset.
 *
 * @return void
 */
function db_users_display_password_reset_banner() {
    // Only show if user is logged in
    if( !defined( 'YOURLS_USER' ) ) {
        return;
    }
    
    // Don't show banner on password reset page
    $current_page = $_GET['page'] ?? '';
    if( $current_page === 'db_users_reset_password' ) {
        return;
    }
    
    $current_user = db_users_get_user( YOURLS_USER );
    // Only show banner if user actually needs to reset (needs_password_reset = 1)
    if( $current_user && ( $current_user->needs_password_reset == 1 || $current_user->needs_password_reset === '1' ) ) {
        $reset_url = yourls_admin_url( 'plugins.php?page=db_users_reset_password' );
        echo '<div class="db-users-password-reset-banner">';
        echo '<h3>' . yourls__( '⚠️ Password Reset Required' ) . '</h3>';
        echo '<p style="font-size: 1.1em;"><strong>' . yourls__( 'You are using a temporary password. For your security, please reset it now.' ) . '</strong></p>';
        echo '<p><a href="' . yourls_esc_attr( $reset_url ) . '" class="button button-primary">' . yourls__( 'Reset Password Now' ) . '</a></p>';
        echo '</div>';
    }
}

/**
 * Render password reset page for first-time login.
 *
 * @return void
 */
function db_users_render_password_reset_page() {
    // Check if user is logged in - if not, they shouldn't reach this page
    if( !defined( 'YOURLS_USER' ) || YOURLS_USER === false ) {
        // User not logged in - show message and link to login
        echo '<div class="wrap">';
        echo '<h2>' . yourls__( 'Reset Password' ) . '</h2>';
        echo '<p>' . yourls__( 'You must be logged in to reset your password.' ) . '</p>';
        echo '<p><a href="' . yourls_admin_url( 'index.php' ) . '" class="button">' . yourls__( 'Go to login' ) . '</a></p>';
        echo '</div>';
        return;
    }

    $messages = [];
    $errors   = [];

    // Handle password reset form submission
    if( $_SERVER['REQUEST_METHOD'] === 'POST' && isset( $_POST['db_users_action'] ) && $_POST['db_users_action'] === 'reset_password' ) {
        db_users_process_password_reset_action( $messages, $errors );
        
        // If reset was successful, the function will redirect
        // If there were errors, we continue to show the form
    }

    $user = db_users_get_user( YOURLS_USER );
    if( !$user ) {
        echo '<p>' . yourls__( 'User not found.' ) . '</p>';
        return;
    }
    
    // Note: We don't redirect if they don't need reset - they can still access this page

    echo '<h2>' . yourls__( 'Reset Your Password' ) . '</h2>';
    echo '<style>
    .db-users-form { max-width: 480px; margin: 2em auto; padding: 2em; border: 1px solid #d9d9d9; border-radius: 4px; background: #fff; }
    .db-users-form p { margin: 0.8em 0; }
    .db-users-warning { background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 1em; margin: 1em 0; color: #856404; }
    </style>';

    foreach( $errors as $error ) {
        echo yourls_notice_box( yourls_esc_html( $error ), 'error' );
    }

    foreach( $messages as $message ) {
        echo yourls_notice_box( yourls_esc_html( $message ), 'success' );
    }

    // echo '<div class="db-users-warning">';
    // echo '<p><strong>' . yourls__( 'Password Reset Required' ) . '</strong></p>';
    // echo '<p>' . yourls__( 'You must reset your password before you can access the admin area.' ) . '</p>';
    // echo '</div>';

    echo '<form method="post" class="db-users-form">';
    echo '<input type="hidden" name="db_users_action" value="reset_password" />';
    yourls_nonce_field( 'db_users_reset_password' );
    echo '<p><label for="db-users-reset-current">' . yourls__( 'Current Password (Temporary)' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-reset-current" name="current_password" autocomplete="current-password" required /></p>';
    echo '<p><label for="db-users-reset-new">' . yourls__( 'New Password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-reset-new" name="new_password" autocomplete="new-password" required /></p>';
    echo '<p><label for="db-users-reset-confirm">' . yourls__( 'Confirm New Password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-reset-confirm" name="confirm_password" autocomplete="new-password" required /></p>';
    echo '<p><button type="submit" class="button button-primary">' . yourls__( 'Reset Password' ) . '</button></p>';
    echo '</form>';
}

/**
 * Process password reset form submission.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_password_reset_action( array &$messages, array &$errors ) {
    if( !defined( 'YOURLS_USER' ) ) {
        $errors[] = yourls__( 'You must be logged in to reset your password.' );
        return;
    }

    yourls_verify_nonce( 'db_users_reset_password' );

    $username = YOURLS_USER;
    $current  = (string) ( $_POST['current_password'] ?? '' );
    $new      = trim( (string) ( $_POST['new_password'] ?? '' ) );
    $confirm  = trim( (string) ( $_POST['confirm_password'] ?? '' ) );

    if( $current === '' ) {
        $errors[] = yourls__( 'Current password is required.' );
        return;
    }

    if( $new === '' ) {
        $errors[] = yourls__( 'New password is required.' );
        return;
    }

    if( $new !== $confirm ) {
        $errors[] = yourls__( 'New passwords do not match.' );
        return;
    }

    if( !db_users_verify_password( $username, $current ) ) {
        $errors[] = yourls__( 'Current password is incorrect.' );
        return;
    }

    // Update password and clear needs_password_reset flag
    if( db_users_update_user_password( $username, $new, true ) ) {
        db_users_refresh_credentials_cache();
        db_users_mark_password_reset_complete( $username );
        yourls_store_cookie( $username );
        // Redirect immediately to admin
        yourls_redirect( yourls_admin_url(), 302 );
        exit;
    } else {
        $errors[] = yourls__( 'Could not reset your password.' );
    }
}

/**
 * Render plugin administration page.
 *
 * @return void
 */
function db_users_render_admin_page() {
    $messages = [];
    $errors   = [];

    db_users_handle_admin_post( $messages, $errors );

    $users = db_users_get_all_users();

    echo '<h2>' . yourls__( 'User Accounts' ) . '</h2>';
    
    // Show banner if current user needs to reset password
    if( defined( 'YOURLS_USER' ) ) {
        $current_user = db_users_get_user( YOURLS_USER );
        if( $current_user && !empty( $current_user->needs_password_reset ) ) {
            $reset_url = yourls_admin_url( 'plugins.php?page=db_users_reset_password' );
            echo '<div style="background: #fff3cd; border: 2px solid #ffc107; border-radius: 4px; padding: 1.5em; margin: 1em 0 2em; color: #856404;">';
            echo '<h3 style="margin-top: 0; color: #856404;">' . yourls__( '⚠️ Password Reset Required' ) . '</h3>';
            echo '<p style="margin: 0.5em 0; font-size: 1.1em;"><strong>' . yourls__( 'You are using a temporary password. For your security, please reset it now.' ) . '</strong></p>';
            echo '<p style="margin: 0.5em 0;"><a href="' . yourls_esc_attr( $reset_url ) . '" class="button button-primary" style="background: #ffc107; border-color: #ff9800; color: #000; font-weight: bold; padding: 0.5em 1.5em; text-decoration: none; display: inline-block;">' . yourls__( 'Reset Password Now' ) . '</a></p>';
            echo '</div>';
        }
    }
    echo '<style>
    .db-users-form { max-width: 480px; margin: 0 0 1.5em; padding: 1em; border: 1px solid #d9d9d9; border-radius: 4px; background: #fff; }
    .db-users-form p { margin: 0.4em 0; }
    .db-users-form select { min-width: 160px; }
    .db-users-table { width: 100%; max-width: 720px; margin: 1.5em 0; border-collapse: collapse; background: #fff; }
    .db-users-table th, .db-users-table td { padding: 0.6em 0.8em; border: 1px solid #d9d9d9; text-align: left; }
    .db-users-table tbody tr:nth-child(odd) { background: #fafafa; }
    .db-users-table .db-users-toggle { font-weight: 600; text-decoration: none; }
    .db-users-table .db-users-toggle:focus, .db-users-table .db-users-toggle:hover { text-decoration: underline; }
    .db-users-current { font-weight: 600; color: #444; }
    .db-users-current-note { color: #777; font-size: 0.85em; margin-left: 0.4em; }
    .db-users-edit-row { background: #fefefe; }
    .db-users-edit-row .db-users-edit-form { padding: 1em 0.4em; }
    .db-users-edit-row form p { margin: 0.4em 0; }
    .db-users-edit-header { display: flex; justify-content: space-between; align-items: center; gap: 1em; margin-bottom: 0.8em; }
    .db-users-header-actions { display: flex; align-items: center; gap: 0.6em; }
    .db-users-delete-form { margin: 0; }
    .db-users-delete-form .button-delete { background: #e74c3c; border-color: #c0392b; color: #fff; }
    .db-users-delete-form .button-delete:hover { background: #c0392b; }
    .db-users-delete-form .button-delete[disabled] { opacity: 0.5; cursor: not-allowed; background: #aaa; border-color: #999; }
    .db-users-delete-note { color: #777; font-size: 0.85em; }
    </style>';

    foreach( $errors as $error ) {
        echo yourls_notice_box( yourls_esc_html( $error ), 'error' );
    }

    foreach( $messages as $message ) {
        echo yourls_notice_box( yourls_esc_html( $message ), 'success' );
    }

    if( db_users_is_admin() ) {
        db_users_render_admin_create_form();
        db_users_render_admin_users_list( $users );
    }

    db_users_render_self_service_form();
}

/**
 * Handle POST actions for the admin page.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_handle_admin_post( array &$messages, array &$errors ) {
    if( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
        return;
    }

    $action = $_POST['db_users_action'] ?? '';
    if( $action === '' ) {
        return;
    }

    switch( $action ) {
        case 'create_user':
            db_users_process_create_user_action( $messages, $errors );
            break;
        case 'update_user':
            db_users_process_update_user_action( $messages, $errors );
            break;
        case 'self_update_password':
            db_users_process_self_update_action( $messages, $errors );
            break;
        case 'delete_user':
            db_users_process_delete_user_action( $messages, $errors );
            break;
    }
}

/**
 * Process create user request.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_create_user_action( array &$messages, array &$errors ) {
    if( !db_users_is_admin() ) {
        $errors[] = yourls__( 'Only administrators can create new users.' );
        return;
    }

    yourls_verify_nonce( 'db_users_create_user' );

    $username = db_users_sanitize_username( $_POST['new_username'] ?? '' );
    $email    = db_users_sanitize_email( $_POST['new_email'] ?? '' );
    $role     = db_users_sanitize_role( $_POST['new_role'] ?? 'user' );

    if( $username === '' ) {
        $errors[] = yourls__( 'Username is required.' );
        return;
    }

    if( db_users_user_exists( $username ) ) {
        $errors[] = yourls__( 'That username already exists.' );
        return;
    }

    if( $email === '' || !filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
        $errors[] = yourls__( 'A valid email address is required.' );
        return;
    }

    // Generate temporary password
    $temp_password = db_users_generate_temp_password( 16 );

    // Create user with temporary password and needs_password_reset flag
    if( db_users_add_user( $username, $temp_password, $role, $email, true ) ) {
        db_users_refresh_credentials_cache();

        // Send email with temporary password
        $login_url = yourls_admin_url( 'index.php' );
        $subject = sprintf( yourls__( 'Your YOURLS Account Credentials - %s' ), YOURLS_SITE );
        $body = sprintf(
            yourls__( "Hello,\n\nA new account has been created for you on %s.\n\nUsername: %s\nTemporary Password: %s\n\nPlease log in at: %s\n\nFor your security, you are strongly encouraged to reset your password after logging in.\n\nBest regards,\nYOURLS Admin" ),
            YOURLS_SITE,
            $username,
            $temp_password,
            $login_url
        );

        $email_sent = db_users_send_email( $email, $subject, $body );

        if( $email_sent ) {
            $messages[] = sprintf( yourls__( 'User %s created and temporary password sent to %s.' ), $username, $email );
        } else {
            $messages[] = sprintf( yourls__( 'User %s created, but email could not be sent. Temporary password: %s' ), $username, $temp_password );
            yourls_debug_log( 'db-users: Failed to send email to ' . $email . ' for user ' . $username );
        }
    } else {
        $errors[] = yourls__( 'Could not create user. Check logs for details.' );
    }
}

/**
 * Process update user request.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_update_user_action( array &$messages, array &$errors ) {
    if( !db_users_is_admin() ) {
        $errors[] = yourls__( 'Only administrators can modify users.' );
        return;
    }

    yourls_verify_nonce( 'db_users_update_user' );

    $username = db_users_sanitize_username( $_POST['target_user'] ?? '' );
    if( $username === '' ) {
        $errors[] = yourls__( 'Unknown user.' );
        return;
    }

    if( defined( 'YOURLS_USER' ) && $username === YOURLS_USER ) {
        $errors[] = yourls__( 'Use the self-service form to manage your own account.' );
        return;
    }

    $user = db_users_get_user( $username );
    if( !$user ) {
        $errors[] = yourls__( 'Unknown user.' );
        return;
    }

    $new_email = db_users_sanitize_email( $_POST['new_email'] ?? '' );
    $new_role  = db_users_sanitize_role( $_POST['new_role'] ?? $user->user_role );
    $password  = trim( (string) ( $_POST['new_password'] ?? '' ) );
    $confirm   = trim( (string) ( $_POST['confirm_password'] ?? '' ) );
    $changed   = false;

    $current_email = isset( $user->email ) ? $user->email : '';
    if( $new_email !== $current_email ) {
        if( $new_email !== '' && !filter_var( $new_email, FILTER_VALIDATE_EMAIL ) ) {
            $errors[] = yourls__( 'Invalid email address.' );
        } else {
            if( db_users_update_email( $username, $new_email ) ) {
                $messages[] = sprintf( yourls__( 'Email updated for %s.' ), $username );
                $changed = true;
            } else {
                $errors[] = sprintf( yourls__( 'Could not update email for %s.' ), $username );
            }
        }
    }

    if( $password !== '' ) {
        if( $password !== $confirm ) {
            $errors[] = sprintf( yourls__( 'Passwords do not match for %s.' ), $username );
        } else {
            if( db_users_update_user_password( $username, $password ) ) {
                $messages[] = sprintf( yourls__( 'Password updated for %s.' ), $username );
                $changed = true;

                if( defined( 'YOURLS_USER' ) && $username === YOURLS_USER ) {
                    yourls_store_cookie( $username );
                }
            } else {
                $errors[] = sprintf( yourls__( 'Could not update password for %s.' ), $username );
            }
        }
    }

    if( $new_role !== $user->user_role ) {
        if( $new_role !== 'admin' && db_users_is_last_admin( $username ) ) {
            $errors[] = yourls__( 'Cannot remove the final administrator.' );
        } else {
            if( db_users_update_user_role( $username, $new_role ) ) {
                $messages[] = sprintf( yourls__( 'Role updated for %s.' ), $username );
                $changed = true;
            } else {
                $errors[] = sprintf( yourls__( 'Could not update role for %s.' ), $username );
            }
        }
    }

    if( $changed ) {
        db_users_refresh_credentials_cache();
    } elseif( empty( $errors ) ) {
        $messages[] = yourls__( 'No changes made.' );
    }
}

/**
 * Process delete user request.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_delete_user_action( array &$messages, array &$errors ) {
    if( !db_users_is_admin() ) {
        $errors[] = yourls__( 'Only administrators can delete users.' );
        return;
    }

    yourls_verify_nonce( 'db_users_delete_user' );

    $username = db_users_sanitize_username( $_POST['target_user'] ?? '' );
    if( $username === '' ) {
        $errors[] = yourls__( 'Unknown user.' );
        return;
    }

    if( defined( 'YOURLS_USER' ) && $username === YOURLS_USER ) {
        $errors[] = yourls__( 'You cannot delete the account you are logged in with.' );
        return;
    }

    if( !db_users_user_exists( $username ) ) {
        $errors[] = yourls__( 'Unknown user.' );
        return;
    }

    if( db_users_is_last_admin( $username ) ) {
        $errors[] = yourls__( 'Cannot delete the last remaining administrator.' );
        return;
    }

    if( db_users_delete_user( $username ) ) {
        db_users_refresh_credentials_cache();
        $messages[] = sprintf( yourls__( 'User %s deleted.' ), $username );
    } else {
        $errors[] = yourls__( 'Could not delete user. Check logs for details.' );
    }
}

/**
 * Process a self-service password change request.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_self_update_action( array &$messages, array &$errors ) {
    if( !defined( 'YOURLS_USER' ) ) {
        $errors[] = yourls__( 'You must be logged in to update your password.' );
        return;
    }

    yourls_verify_nonce( 'db_users_change_own_password' );

    $username = YOURLS_USER;
    $current  = (string) ( $_POST['current_password'] ?? '' );
    $new      = trim( (string) ( $_POST['self_new_password'] ?? '' ) );
    $confirm  = trim( (string) ( $_POST['self_confirm_password'] ?? '' ) );

    if( $current === '' ) {
        $errors[] = yourls__( 'Current password is required.' );
        return;
    }

    if( $new === '' ) {
        $errors[] = yourls__( 'New password is required.' );
        return;
    }

    if( $new !== $confirm ) {
        $errors[] = yourls__( 'New passwords do not match.' );
        return;
    }

    if( !db_users_verify_password( $username, $current ) ) {
        $errors[] = yourls__( 'Current password is incorrect.' );
        return;
    }

    if( db_users_update_user_password( $username, $new ) ) {
        db_users_refresh_credentials_cache();
        yourls_store_cookie( $username );
        $messages[] = yourls__( 'Your password has been updated.' );
    } else {
        $errors[] = yourls__( 'Could not update your password.' );
    }
}

/**
 * Render administrator create user form.
 *
 * @return void
 */
function db_users_render_admin_create_form() {
    echo '<h3>' . yourls__( 'Create User' ) . '</h3>';
    echo '<form method="post" class="db-users-form">';
    echo '<input type="hidden" name="db_users_action" value="create_user" />';
    yourls_nonce_field( 'db_users_create_user' );
    echo '<p><label for="db-users-new-username">' . yourls__( 'Username' ) . '</label><br />';
    echo '<input type="text" class="text" id="db-users-new-username" name="new_username" required /></p>';
    echo '<p><label for="db-users-new-email">' . yourls__( 'Email' ) . '</label><br />';
    echo '<input type="email" class="text" id="db-users-new-email" name="new_email" required /></p>';
    echo '<p><small>' . yourls__( 'A temporary password will be generated and sent to this email address.' ) . '</small></p>';
    echo '<p><label for="db-users-new-role">' . yourls__( 'Role' ) . '</label><br />';
    echo '<select id="db-users-new-role" name="new_role">';
    echo '<option value="user">' . yourls__( 'User' ) . '</option>';
    echo '<option value="admin">' . yourls__( 'Administrator' ) . '</option>';
    echo '</select></p>';
    echo '<p><button type="submit" class="button button-primary">' . yourls__( 'Create user' ) . '</button></p>';
    echo '</form>';
}

/**
 * Render administrator list of existing users.
 *
 * @param array $users
 * @return void
 */
function db_users_render_admin_users_list( array $users ) {
    echo '<h3>' . yourls__( 'Existing Users' ) . '</h3>';

    if( empty( $users ) ) {
        echo '<p>' . yourls__( 'No users found.' ) . '</p>';
        return;
    }

    echo '<table class="db-users-table">';
    echo '<thead><tr><th>' . yourls__( 'Username' ) . '</th><th>' . yourls__( 'Email' ) . '</th><th>' . yourls__( 'Role' ) . '</th><th>' . yourls__( 'Last updated' ) . '</th></tr></thead>';
    echo '<tbody>';

    foreach( $users as $user ) {
        $raw_username  = $user->user_login;
        $display_name  = yourls_esc_html( $raw_username );
        $attr_username = yourls_esc_attr( $raw_username );
        $user_email    = isset( $user->email ) ? yourls_esc_html( $user->email ) : '<em>' . yourls__( 'No email' ) . '</em>';
        $role_label    = $user->user_role === 'admin' ? yourls__( 'Administrator' ) : yourls__( 'User' );
        $unique_id     = 'db-users-edit-' . md5( $raw_username );
        $updated       = yourls_esc_html( $user->updated_at );
        $role_admin    = $user->user_role === 'admin' ? 'selected="selected"' : '';
        $role_user     = $user->user_role === 'user' ? 'selected="selected"' : '';
        $is_current    = defined( 'YOURLS_USER' ) && YOURLS_USER === $raw_username;
        $is_last_admin = db_users_is_last_admin( $raw_username );

        echo '<tr>';
        if( $is_current ) {
            echo '<td><span class="db-users-current">' . $display_name . '</span><span class="db-users-current-note">' . yourls__( '(You)' ) . '</span></td>';
        } else {
            echo '<td><a href="#" class="db-users-toggle" data-target="' . $unique_id . '">' . $display_name . '</a></td>';
        }
        echo '<td>' . $user_email . '</td>';
        echo '<td>' . yourls_esc_html( $role_label ) . '</td>';
        echo '<td>' . $updated . '</td>';
        echo '</tr>';

        if( $is_current ) {
            continue;
        }

        $delete_disabled = $is_last_admin ? ' disabled="disabled"' : '';
        $delete_note_text = $is_last_admin ? yourls__( 'At least one administrator is required.' ) : '';
        $confirm_text    = yourls_esc_js( sprintf( yourls__( 'Delete user %s? This cannot be undone.' ), $raw_username ) );

        echo '<tr id="' . $unique_id . '" class="db-users-edit-row" style="display:none">';
        echo '<td colspan="4">';
        echo '<div class="db-users-edit-form">';
        echo '<div class="db-users-edit-header">';
        echo '<strong>' . sprintf( yourls__( 'Editing %s' ), $display_name ) . '</strong>';
        echo '<div class="db-users-header-actions">';
        echo '<form method="post" class="db-users-delete-form" onsubmit="return confirm(\'' . $confirm_text . '\');">';
        echo '<input type="hidden" name="db_users_action" value="delete_user" />';
        echo '<input type="hidden" name="target_user" value="' . $attr_username . '" />';
        yourls_nonce_field( 'db_users_delete_user' );
        echo '<button type="submit" class="button button-delete"' . $delete_disabled . '>' . yourls__( 'Delete user' ) . '</button>';
        echo '</form>';
        if( $delete_note_text !== '' ) {
            echo '<span class="db-users-delete-note">' . yourls_esc_html( $delete_note_text ) . '</span>';
        }
        echo '</div>';
        echo '</div>';
        echo '<form method="post">';
        echo '<input type="hidden" name="db_users_action" value="update_user" />';
        echo '<input type="hidden" name="target_user" value="' . $attr_username . '" />';
        yourls_nonce_field( 'db_users_update_user' );
        echo '<p><label>' . yourls__( 'Email' ) . '</label><br />';
        $current_email = isset( $user->email ) ? yourls_esc_attr( $user->email ) : '';
        echo '<input type="email" class="text" name="new_email" value="' . $current_email . '" /></p>';
        echo '<p><label>' . yourls__( 'Role' ) . '</label><br />';
        echo '<select name="new_role">';
        echo '<option value="admin" ' . $role_admin . '>' . yourls__( 'Administrator' ) . '</option>';
        echo '<option value="user" ' . $role_user . '>' . yourls__( 'User' ) . '</option>';
        echo '</select></p>';
        echo '<p><label>' . yourls__( 'Set new password (optional)' ) . '</label><br />';
        echo '<input type="password" class="text" name="new_password" autocomplete="new-password" />';
        echo '</p>';
        echo '<p><label>' . yourls__( 'Confirm new password' ) . '</label><br />';
        echo '<input type="password" class="text" name="confirm_password" autocomplete="new-password" />';
        echo '</p>';
        echo '<p><button type="submit" class="button">' . yourls__( 'Save changes' ) . '</button></p>';
        echo '</form>';
        echo '</div>';
        echo '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';

    static $script_rendered = false;
    if( !$script_rendered ) {
        $script_rendered = true;
        echo '<script>
        document.addEventListener("click", function(event) {
            var trigger = event.target.closest(".db-users-toggle");
            if (!trigger) {
                return;
            }
            event.preventDefault();
            var targetId = trigger.getAttribute("data-target");
            if (!targetId) {
                return;
            }
            var row = document.getElementById(targetId);
            if (!row) {
                return;
            }
            if (row.style.display === "none" || row.style.display === "") {
                row.style.display = "table-row";
            } else {
                row.style.display = "none";
            }
        });
        </script>';
    }
}

/**
 * Move plugin admin page link under the Admin interface menu.
 *
 * @param array $sublinks
 * @return array
 */
function db_users_move_menu_link( array $sublinks ) {
    if( isset( $sublinks['plugins']['db_users'] ) ) {
        $link = $sublinks['plugins']['db_users'];
        unset( $sublinks['plugins']['db_users'] );
        if( empty( $sublinks['plugins'] ) ) {
            unset( $sublinks['plugins'] );
        }
        if( !isset( $sublinks['admin'] ) || !is_array( $sublinks['admin'] ) ) {
            $sublinks['admin'] = [];
        }
        $sublinks['admin']['db_users'] = $link;
    }

    return $sublinks;
}

/**
 * Placeholder for user self-service form (implemented later).
 *
 * @return void
 */
function db_users_render_self_service_form() {
    if( !defined( 'YOURLS_USER' ) ) {
        return;
    }

    $username = YOURLS_USER;

    echo '<h3>' . yourls__( 'Change Your Password' ) . '</h3>';
    echo '<form method="post" class="db-users-form">';
    echo '<input type="hidden" name="db_users_action" value="self_update_password" />';
    yourls_nonce_field( 'db_users_change_own_password' );
    echo '<p>' . sprintf( yourls__( 'You are logged in as %s.' ), yourls_esc_html( $username ) ) . '</p>';
    echo '<p><label for="db-users-current-password">' . yourls__( 'Current password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-current-password" name="current_password" autocomplete="current-password" required /></p>';
    echo '<p><label for="db-users-self-new-password">' . yourls__( 'New password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-self-new-password" name="self_new_password" autocomplete="new-password" required /></p>';
    echo '<p><label for="db-users-self-confirm-password">' . yourls__( 'Confirm new password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-self-confirm-password" name="self_confirm_password" autocomplete="new-password" required /></p>';
    echo '<p><button type="submit" class="button button-primary">' . yourls__( 'Update password' ) . '</button></p>';
    echo '</form>';
}

/**
 * Update a user password.
 *
 * @param string $username
 * @param string $password
 * @param bool $clear_reset_flag Whether to clear needs_password_reset flag (default true).
 * @return bool
 */
function db_users_update_user_password( $username, $password, $clear_reset_flag = true ) {
    $username = db_users_sanitize_username( $username );
    $password = (string) $password;

    if( $username === '' || $password === '' ) {
        return false;
    }

    $stored = db_users_normalize_password_storage( $password );

    $sql = "UPDATE `" . db_users_table_name() . "` SET user_pass = :pass, needs_password_reset = :needs_reset, updated_at = :updated WHERE user_login = :login";
    $affected = db_users_db()->fetchAffected( $sql, [
        'pass'        => $stored,
        'needs_reset' => $clear_reset_flag ? 0 : 1,
        'updated'     => db_users_now(),
        'login'       => $username,
    ] );

    return $affected !== false;
}

/**
 * Update a user's email address.
 *
 * @param string $username
 * @param string $email
 * @return bool
 */
function db_users_update_email( $username, $email ) {
    $username = db_users_sanitize_username( $username );
    $email    = $email ? db_users_sanitize_email( $email ) : null;

    if( $username === '' ) {
        return false;
    }

    $sql = "UPDATE `" . db_users_table_name() . "` SET email = :email, updated_at = :updated WHERE user_login = :login";
    $affected = db_users_db()->fetchAffected( $sql, [
        'email'   => $email,
        'updated' => db_users_now(),
        'login'   => $username,
    ] );

    return $affected !== false;
}

/**
 * Mark that a user has completed password reset.
 *
 * @param string $username
 * @return bool
 */
function db_users_mark_password_reset_complete( $username ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    $sql = "UPDATE `" . db_users_table_name() . "` SET needs_password_reset = 0, updated_at = :updated WHERE user_login = :login";
    $affected = db_users_db()->fetchAffected( $sql, [
        'updated' => db_users_now(),
        'login'   => $username,
    ] );

    return $affected !== false;
}

/**
 * Update a user role.
 *
 * @param string $username
 * @param string $role
 * @return bool
 */
function db_users_update_user_role( $username, $role ) {
    $username = db_users_sanitize_username( $username );
    $role     = db_users_sanitize_role( $role );

    if( $username === '' ) {
        return false;
    }

    $sql = "UPDATE `" . db_users_table_name() . "` SET user_role = :role, updated_at = :updated WHERE user_login = :login";
    $affected = db_users_db()->fetchAffected( $sql, [
        'role'    => $role,
        'updated' => db_users_now(),
        'login'   => $username,
    ] );

    return $affected !== false;
}

/**
 * Retrieve all users with metadata.
 *
 * @return array
 */
function db_users_get_all_users() {
    $table = db_users_table_name();
    $rows  = db_users_db()->fetchObjects( "SELECT user_login, user_role, email, needs_password_reset, created_at, updated_at FROM `$table` ORDER BY user_login ASC" );

    return $rows ? (array) $rows : [];
}

/**
 * Fetch a user row.
 *
 * @param string $username
 * @return object|false
 */
function db_users_get_user( $username ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    return db_users_db()->fetchObject(
        "SELECT user_login, user_role, email, needs_password_reset, created_at, updated_at FROM `" . db_users_table_name() . "` WHERE user_login = :login LIMIT 1",
        [ 'login' => $username ]
    );
}

/**
 * Determine if a user exists.
 *
 * @param string $username
 * @return bool
 */
function db_users_user_exists( $username ) {
    return (bool) db_users_get_user( $username );
}

/**
 * Delete a user.
 *
 * @param string $username
 * @return bool
 */
function db_users_delete_user( $username ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    $sql = "DELETE FROM `" . db_users_table_name() . "` WHERE user_login = :login LIMIT 1";
    $affected = db_users_db()->fetchAffected( $sql, [
        'login' => $username,
    ] );

    return $affected !== false && $affected > 0;
}

/**
 * Count administrators.
 *
 * @return int
 */
function db_users_count_admins() {
    $table = db_users_table_name();

    return (int) db_users_db()->fetchValue( "SELECT COUNT(*) FROM `$table` WHERE user_role = 'admin'" );
}

/**
 * Determine if a given username is the final admin.
 *
 * @param string $username
 * @return bool
 */
function db_users_is_last_admin( $username ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    $role = db_users_db()->fetchValue(
        "SELECT user_role FROM `" . db_users_table_name() . "` WHERE user_login = :login LIMIT 1",
        [ 'login' => $username ]
    );

    if( $role !== 'admin' ) {
        return false;
    }

    return db_users_count_admins() <= 1;
}
