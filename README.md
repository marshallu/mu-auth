# MU Auth

A WordPress plugin that provides Single Sign-On (SSO) authentication for Marshall University via CAS (Central Authentication Service).

## Requirements

- WordPress
- ACF Pro
- Gravity Forms (optional, required for the Gravity Forms Viewer role)

## Installation

Install via Composer:

```bash
composer require marshallu/mu-auth
```

Or place the plugin in your `wp-content/plugins/` directory and activate it.

## Configuration

CAS authentication activates automatically on supported hosts:

- **WordPress VIP** — when the platform-defined `VIP_GO_APP_ENVIRONMENT` constant is present (all environment types, including `local`)
- **Pantheon** — when `PANTHEON_ENVIRONMENT` is set in the environment

On any other host, enable it with an environment variable:

```bash
MU_AUTH_ENABLE=true
```

Note that this only gates the CAS login redirect. The custom roles, their admin restrictions, the settings page, and the logout redirect are always registered.

Once active, configure access via the **Settings > MU Auth Settings** page in the WordPress admin. This requires ACF Pro.

### Auth Users

Add MU Net IDs and assign each a permissions level:

| Permissions Level | WordPress Role |
|---|---|
| Administrator | administrator |
| Editor | editor |
| Forms | gravity_forms_viewer |
| Profiles | profiles_manager |

### Site Visibility

- **Public** - Site accessible to all visitors
- **Admins** - Only users listed in Auth Users
- **Extras** - Admins plus additional view-only users

### Super Users

To grant certain MU Net IDs unconditional access across all sites without storing them in version control, add a filter in a mu-plugin (e.g. `wp-content/mu-plugins/super-users.php`):

```php
add_filter( 'mu_auth_super_users', function( $users ) {
    return array( 'netid1', 'netid2' );
} );
```

### Forcing CAS On or Off

To override host auto-detection — for example to turn CAS off on a specific environment, or on for a host the plugin does not detect — add a filter in a mu-plugin:

```php
add_filter( 'mu_auth_enabled', function( $enabled ) {
    return false;
} );
```

## Custom Roles

### Gravity Forms Viewer

Can view, export, and annotate Gravity Forms entries. Restricted to Gravity Forms pages only in the admin.

### Profiles Manager

Can create and edit Employee posts and Department taxonomy terms. Restricted to those post types in the admin.

## Development

```bash
composer lint      # Check coding standards
composer format    # Auto-fix formatting
composer analyse   # Run PHPStan static analysis
```
