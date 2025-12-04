# Installing PHPMailer for Better User Management Plugin

This plugin requires PHPMailer to send emails. Here are two ways to install it:

## Option 1: Install in Plugin Directory (Recommended)

This is the easiest method and keeps dependencies isolated to the plugin.

1. Navigate to the plugin directory in your terminal:
   ```bash
   cd C:\Users\Mike\Code\yourls-dbuser-with-comms
   ```
   (Or wherever you placed the plugin folder)

2. A `composer.json` file has been created for you. Install PHPMailer via Composer:
   ```bash
   composer install --ignore-platform-reqs
   ```
   
   **Note:** The `--ignore-platform-reqs` flag is needed if you get dependency conflicts with other packages (like PHP version requirements). This ensures PHPMailer installs even if other dependencies have different PHP version requirements.

3. Verify it worked - you should see a `vendor` folder created in the plugin directory with PHPMailer inside.

## Option 2: Install in YOURLS Root Directory

If you want to share PHPMailer across multiple plugins:

1. Navigate to your YOURLS root directory:
   ```bash
   cd /path/to/yourls
   ```

2. If you don't have a `composer.json` file, create one:
   ```bash
   composer init --no-interaction
   ```

3. Install PHPMailer:
   ```bash
   composer require phpmailer/phpmailer
   ```

## Verify Installation

After installation, check your YOURLS debug logs. If PHPMailer is loaded correctly, you shouldn't see any "PHPMailer not available" messages when creating a user.

To enable debug logging, add this to your YOURLS `config.php`:
```php
define('YOURLS_DEBUG', true);
```

## Troubleshooting

- **"PHPMailer not available" error**: Make sure the `vendor` folder exists in either the plugin directory or YOURLS root
- **Composer not installed**: Install Composer from https://getcomposer.org/ (Windows users can download Composer-Setup.exe)
- **Dependency conflicts (PHP version errors)**: Use the `--ignore-platform-reqs` flag when running `composer install` or `composer require`
- **Composer command not found**: Make sure Composer is in your system PATH, or use the full path to `composer.phar`
- **Email still not sending**: Check your SMTP settings in `config.php` and verify they're correct. Also check the debug logs for specific SMTP errors.

