# Changelog

## Unreleased

---

## [1.1.2] - 2026-03-11

### Fixed

- **HTTPS detection in `mu_auth_get_service_url()`** — The function previously only checked the Pantheon-specific `HTTP_USER_AGENT_HTTPS` server header to determine the request scheme. On non-Pantheon hosts (e.g. Laravel Forge/nginx), this header is never set, causing the service URL passed to CAS to always use `http://` even when the site is served over HTTPS. CAS issues the ticket for the `http://` service URL, which triggers an HTTP→HTTPS redirect on the server before WordPress can validate the ticket, resulting in a service URL mismatch and an infinite redirect loop.

  Updated the HTTPS check to also cover standard server headers:
  - `$_SERVER['HTTPS']` — set by PHP-FPM/Apache when serving HTTPS directly
  - `$_SERVER['HTTP_X_FORWARDED_PROTO']` — set by nginx/load balancers proxying HTTPS
  - `$_SERVER['HTTP_USER_AGENT_HTTPS']` — Pantheon-specific (retained for backwards compatibility)

---

## [1.1.1] - 2026-03-10

### Added

- `README.md` with setup instructions, configuration options, and usage examples

---

## [1.1.0] - 2026-03-10

### Added

- PHPStan static analysis with `phpstan/phpstan` and `szepeviktor/phpstan-wordpress`; added `composer analyse` script
- `phpcs.xml` replacing `phpcs.xml.dist` (simplified config); updated `format`/`lint` scripts accordingly
- `CLAUDE.md` with project guidance for AI-assisted development

### Fixed

- Replaced `md5(microtime())` with `wp_generate_password()` for more secure user creation
- Added `WP_Error` and `simplexml_load_string()` failure handling in `mu_auth_validate_cas_ticket()`
- Added `allowed_redirect_hosts` filter for CAS host; enforced `wp_safe_redirect()` consistently throughout
- Replaced hardcoded super-user NetIDs with `mu_auth_super_users` filter hook to keep privileged accounts out of version control
- Fixed return type of `mu_auth_get_user_by_username()` to `WP_User|false`
- Removed extraneous `$selected_user` argument from `mu_auth_create_user()` call
- Removed invalid 4th argument from `remove_filter()` call
- Fixed undefined array key warning in `mu_auth_get_service_url()` when the service URL has no query string
