# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WordPress MU (must-use) plugin for Marshall University that provides Single Sign-On (SSO) authentication via CAS (Central Authentication Service) at `https://auth.marshall.edu`. Manages user access control configured via ACF fields and supports WordPress multisite environments.

**Requires:** WordPress, ACF Pro, and optionally Gravity Forms (for the `gravity_forms_viewer` role).

## Commands

```bash
# Lint PHP code against WordPress coding standards
composer lint

# Auto-fix PHP formatting
composer format
```

A `lefthook` pre-commit hook automatically runs `composer lint` before each commit. There are no automated tests.

## Architecture

The plugin consists of three PHP files:

- **`mu-auth.php`** — Core plugin logic (~945 lines). All authentication, user management, and role restriction logic lives here as global functions prefixed `mu_auth_`.
- **`mu-auth-admin.php`** — Registers the ACF options sub-page under WordPress Settings.
- **`acf-fields.php`** — Defines ACF field groups for the options page: `auth_users` (repeater of NetID + permissions level), `site_visibility` (public/admins/extras), and `view_users`.

### Authentication Flow

1. `mu_auth_check_login()` fires on WordPress `init` hook — hooked on `plugins_loaded` only when `mu_auth_is_enabled()` returns true, i.e. the `VIP_GO_APP_ENVIRONMENT` constant is defined (WordPress VIP), `$_ENV['PANTHEON_ENVIRONMENT']` is set (Pantheon), or `MU_AUTH_ENABLE=true`. Overridable via the `mu_auth_enabled` filter.
2. If the user is not authenticated and on a login/admin page, redirects to CAS login.
3. CAS redirects back with a `ticket` query parameter; `mu_auth_validate_cas_ticket()` calls `/cas/p3/serviceValidate`, parses the XML response.
4. `mu_auth_login_user()` looks up or creates the WordPress user, checks them against the `auth_users` ACF field, assigns the appropriate role, sets auth cookies, and redirects.

### Custom Roles

**`gravity_forms_viewer`** — Can only view Gravity Forms entries. The plugin restricts their admin menu, admin bar, and page access to Gravity Forms pages only.

**`profiles_manager`** — Can manage employee posts and department taxonomy. Similarly restricted to those post types in the admin.

### ACF-Driven Access Control

The `auth_users` repeater on the options page drives who can log in. Each row has a `munet` (NetID) field and a `permissions_level` select that maps to WordPress roles: Administrator, Editor, `gravity_forms_viewer`, or `profiles_manager`. A hardcoded `$mu_auth_super_users` array in `mu-auth.php` bypasses this check for certain users.

### CAS Constants

Defined at the top of `mu-auth.php`:
- `MUCASAUTH_CAS_HOST` — `https://auth.marshall.edu`
- `MUCASAUTH_CAS_PATH` — `/cas`
- `MUCASAUTH_LOGOUT_REDIRECT_URL` — `https://www.marshall.edu`
- `MUCASAUTH_CAS_ATTRIBUTE_*` — CAS attribute names for group, name, and email

## Coding Conventions

- Function-based architecture (no classes), all functions prefixed `mu_auth_`
- WordPress coding standards enforced via PHPCS (`phpcs.xml.dist`)
- `wp_safe_redirect()` for all redirects; `sanitize_text_field()` + `wp_unslash()` for user input
- Use `// phpcs:ignore` comments when superglobal access is intentional and necessary
