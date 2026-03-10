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

The plugin must be enabled via environment variable:

```bash
MU_AUTH_ENABLE=true
```

On Pantheon, the plugin activates automatically when `PANTHEON_ENVIRONMENT` is set.

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

To grant certain MU Net IDs unconditional access across all sites without storing them in version control, add a filter in `wp-config.php` or a private plugin:

```php
add_filter( 'mu_auth_super_users', function( $users ) {
    return array( 'netid1', 'netid2' );
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
