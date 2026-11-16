# Changelog

This project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] (2026-11-16)
First release.
- `scripts/loom.py` with subcommands: `profile`, `init`, `adopt`, `rollback`, `add`, `attach`, `status`, `next`, `gate`, `advance`, `approve`, `build`, `stage`, `publish`, `schedule`.
- Strict versioned schemas for `loom.config.json`, `Loom/ledger.json`, `Loom/install_manifest.json` and the user profile: unknown fields, duplicate keys, NaN, oversized files, traversal, absolute paths and denied folders are refused.
- Gates: command checks (argv list, no shell, timeout, environment allow-list, capped and sanitised output, exit-code semantics), facts expiry, required files, ticked checklists.
- Approvals are recorded per item, channel and time, expire (default 72 h), and are consumed on use. `publish` and `schedule` refuse without one. `LOOM_NO_PUBLISH=1` refuses approvals and publishing in unattended runs.
- Adoption: dry run by default, pre-adopt snapshot of config and state files, additive files only, hash manifest, shadow mode, hash-checked rollback.
- Skills `loom` (status, next and gate only are pre-approved) and `loom-adopt`.
- Mkdir lock with stale handling, atomic writes, `.bak` of the previous ledger, junction and symlink refusal.
- TODO before publishing: icon (square PNG) and the privacy, support and terms links the directory asks for.
