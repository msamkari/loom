# Changelog

This project follows [Semantic Versioning](https://semver.org/).

## [0.1.1] (2026-11-16)
Fix batch from the round-2 adversarial report. Behaviour changes on purpose.
### Changed (trust model)
- Trust pin: `gate`, `build`, `stage`, `publish`, `schedule` run a config command only if the SHA-256 of all configured commands (argv, env names, timeouts, pass codes, named commands, channels, absolute root, resolved program paths) is recorded in `$LOOM_HOME/trust.json`. New subcommand `trust` (not pre-approved; prints every command; `--yes` writes the pin). `status`/`next`/`gate` accept no root, never write outside `Loom/`; `gate` discards its result when the config or the ledger's approvals changed while it ran. A `LOOM_HOME` inside the project is refused.
- Approvals are HMAC-SHA256 signed with `$LOOM_HOME/secret.key` (project root, item, channel, what, when, date, nonce); unsigned, edited and copied approvals are refused by `publish`, `schedule`, `advance` and `next`. `--when` is strict ISO-8601 with a zone and must be in the future. An approval is reserved while the adapter runs and consumed only on success; spent signatures are also kept in `$LOOM_HOME/spent.json`. `publish`/`schedule` need the publish stage; `allowed_stages` can only narrow. `LOOM_NOW` only works with `LOOM_TEST=1`.
- Command execution: bare program names only, resolved through PATH (project and current folder excluded, `.exe` only on Windows, path stored in the pin); `.bat/.cmd/.com/.ps1/.vbs/.js/.wsf`, shells, launchers and name tricks refused. Whole process tree killed on timeout and on normal exit (Windows Job Object, taskkill fallback; POSIX process group). Child environment is a small allow-list plus names in both the config and `$LOOM_HOME/env_allow.json`. Redaction covers reversed, base64 and hex forms.
- Output: one sanitiser for everything printed (ANSI/CSI/OSC, C0/C1, bidi, zero-width, tags, U+2028/9; newlines become a visible separator); adapter output lines are prefixed; `status`/`next` capped at 200 items; stored ledger strings refuse controls, C1 and line separators; regexes use `\Z`.
- Item ids: no trailing dot, no reserved device names, case-insensitively unique; scaffold files are written before the ledger is saved.
- Adopt is crash-safe: the manifest is written first (`pending`), files are created exclusively, then `complete`; `rollback` and a repeated `adopt` resume. The manifest HMAC is recorded in `$LOOM_HOME`; rollback refuses unverified manifests and any path outside `loom.config.json`, `Loom/` and the CLAUDE.md block. Secret-like files (`settings.local*`, `.env*`, `*.key`, `*.pem`, `credentials*`, `tokens*`) are not snapshotted (name and sha256 only). `rollback --purge-snapshot`. A second init/adopt over an existing manifest is refused.
- Lock lives in `Loom/` (root for init/adopt/rollback); takeover needs age and a dead pid; no `rmtree`; ownership re-checked before each replace; bad `LOOM_LOCK_*` values give a clean error.
### Known limits
- A pinned command runs with the user's rights and can still write files, including secrets it was given. The user's secret key is readable by any process of the same user.
- POSIX descendants that call `setsid` escape the group kill; redaction cannot cover every re-encoding of a secret.
- Used-flag replay protection and the trust pin live in `$LOOM_HOME`; moving to another machine needs `trust` again and old approvals/manifests are refused.
- A crashed adapter leaves its approval reserved for 15 minutes (then it can be reused: possible double run after a crash).
- Argv tokens containing `{` or `}` that are not whole placeholders are refused (no inline JSON arguments).
- Windows 8.3 short names are not resolved before the deny-list check; stale gate results after file edits are not detected; manifests and approvals from 0.1.0 are refused (re-adopt or re-approve).
- Not verified: POSIX/macOS runtime, Python 3.8 runtime, CI, the real Claude Code permission prompts for `trust`, real Dropbox sync.

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
