# Password Policy

Enforce a real password policy — minimum length, character classes, a common-password blocklist and password-reuse history — and force users with weak passwords to change them on next login.

## Features

- **Length + character classes** — minimum length (default 12) with optional uppercase, lowercase, number and symbol requirements, all configurable under **Settings → Password Policy**.
- **Common-password blocklist** — 60+ built-in common passwords (`password`, `qwerty123`, `letmein`, …) plus your own extra entries, one per line. Extend it in code with the `wpp_common_passwords` filter.
- **Reuse history** — the last N password hashes (default 5) are stored per user and a password that matches any of them is rejected. History is recorded on profile changes and password resets.
- **Weak-password flagging** — when a user logs in with a password that no longer meets the policy, they are flagged and redirected to their profile to choose a stronger one, with a notice explaining why.
- **Applies everywhere passwords are set** — registration, profile/user-edit saves and password resets.
- **Filter** — `wpp_validate_password` lets other code add its own rules.

## Installation

1. Upload the `wp-password-policy` folder to `/wp-content/plugins/`.
2. Activate the plugin through **Plugins** in WordPress admin.
3. Tune the policy under **Settings → Password Policy**.

## Notes

- Password history stores only hashes (via `wp_hash_password()`), never plaintext.
- The reuse history is recorded when a password change passes this plugin's validation. If another plugin blocks the save afterwards, the attempted password may appear in history even though it was never set — a fail-closed edge case, not a security issue.

## Uninstall

Deleting the plugin removes its settings and all `_wpp_password_history` / `_wpp_must_change_password` user meta.

## License

MIT — see [LICENSE](LICENSE).
