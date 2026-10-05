# Changelog

## Unreleased

---

## [1.1.7] - 2026-10-05

### Fixed

- **Logout and unauthorized-user redirect loops on VIP.** The `www.marshall.edu` logout host is now an allowed redirect host. Before, `wp_safe_redirect()` fell back to `admin_url()` on other domains and sent users straight back through CAS.
- **CAS ticket validation timeout.** Validation now uses a 3s timeout. On VIP, the circuit breaker also allows 3 failures and a 20s retry window instead of the 1s default. A slow CAS response no longer causes login loops.
- **Unknown permission levels no longer grant Administrator.** An unrecognized level now maps to Editor. A super user with no `auth_users` row still gets Administrator, and the undefined-key warning is gone.
- **CAS no longer turns on in `vip dev-env`.** VIP detection now uses `marshall_is_hosted()` when it's available and otherwise skips the `local` environment.

### Changed

- **VIP forced two-factor is off for CAS logins**, because CAS already enforces MFA. Return `true` from the `mu_auth_vip_two_factor_forced` filter to keep it on.
- **Employee capabilities are granted with `wpcom_vip_add_role_caps()`** when it's available: one write per role instead of 16.

### Removed

- **Activation and deactivation hooks.** They never run for a mu-plugin or for a plugin loaded with `wpcom_vip_load_plugin()`.

---

## [1.1.6] - 2026-08-20

### Fixed

- **Evergreen login detection** — detect the `evergreen` query parameter explicitly instead of matching it anywhere in the request URL.

---

## [1.1.5] - 2026-07-27

### Added

- **WordPress VIP environment detection** — CAS authentication now auto-enables on WordPress VIP by checking for the platform-defined `VIP_GO_APP_ENVIRONMENT` constant, alongside the existing Pantheon (`PANTHEON_ENVIRONMENT`) and `MU_AUTH_ENABLE` checks. Supports running Pantheon and VIP side by side during the migration.
- **`mu_auth_enabled` filter** — the host check now lives in `mu_auth_is_enabled()` and can be overridden from a mu-plugin to force CAS on or off on a host that is not auto-detected.

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
