# Changelog

This project follows [Semantic Versioning](https://semver.org/).

## [0.1.2] (2026-11-17)
Fix batch from the round-3 adversarial reports (trust models; operator misuse and durability). Behaviour changes on purpose; pins written by 0.1.1 are refused with a clear message and need one new `trust`.
### Fixed
- Trust pin content (L-H1): the pin now holds the SHA-256 of the script an interpreter runs, of every project file a `python -m module` could load (including the pinned absence of files that do not exist), and of any other argument naming an existing project file; editing one after `trust` makes `gate` refuse. Inline `-c` code is pinned verbatim. Interpreter options the pin cannot read are refused at `trust`.
- Trust review (L-H2): `trust` prints each argv expanded (named commands included), as a JSON list, never truncated, plus the program path and hash and every pinned file; an argv over 4000 characters is refused with the reason.
- Mismatch handling (B11): the pin record stores the absolute interpreter path and the SHA-256 of the program file; a refusal prints what changed line by line (PATH-resolved program, program content, script hash, argv, env names, settings) and never suggests `--yes`; it says that confirming without reading defeats the pin. A 0.1.1 string pin is refused as "older loom".
- Structure (low): the whole config is in the pin, so removing or changing stages or checks changes it; `gate` also enforces the pin for a command-less stage once a pin exists for the folder.
- Helpers (L-M1, B1): `icacls` and `taskkill` are started only by absolute path under `%SystemRoot%/System32` (never from the current folder or PATH); if missing, loom refuses before writing anything private.
- Spent approvals (B6): the spent signature is written (fsync, bounded retries) BEFORE the adapter runs; if it cannot be written, `publish`/`schedule`/`advance` refuse and run nothing; a restored older ledger cannot publish twice; a failed adapter releases the reservation; entries are pruned by age (800 h), not by count; the 0.1.1 list format is still read.
- Locks (B2, B3): the lock owner records the process start time (Windows creation time, Linux `/proc`), so a reused pid no longer keeps a stale lock alive; where it cannot be read, only a 24 h hard age frees a live pid. The message names the lock folder and the safe manual step instead of promising a takeover. A lock dated in the future ages out.
- Serialised home writes (B16): `trust --yes`, spent records and the rollback manifest record are read-modify-written under a lock in `$LOOM_HOME` (12 parallel `trust --yes` keep 12 pins); `secret.key` is created exclusively so two first runs share one key.
- Hard links: a ledger, config or backup file with more than one hard link is refused.
- Sanitiser: also removes variation selectors, tag and private-use characters and invisible fillers (U+3164, U+115F, U+2800, U+034F, U+17B4 ...); Arabic tashkeel and real letters are kept.
- `next` at the publish stage points to `approve` and `publish`/`schedule` instead of `advance`, which would close the item unpublished.
- Docs (B18): README says which commands write (`add`, `attach`, `approve`, `advance` write immediately; the false "without --yes nothing is written" is gone), command examples use the plugin folder, quoting for paths with spaces and the PowerShell form are documented in README and skill, the "No icon yet" line is gone.
- Repo hygiene (B20): `.gitattributes` (`* text=auto eol=lf`), CHANGELOG/LICENSE/CI/test files normalised to LF, tests check no tracked text file has CRLF and that `.claude-plugin/` holds only `plugin.json` and the square PNG icon.
### Known limits
- A pinned interpreter command can still do anything the user's account can. Modules a pinned script imports from the project (`import helper`) and code that `-c` imports are not pinned. A script can change between the pin check and its start.
- B12: the program file content is part of the pin, so an interpreter or tool upgrade needs `trust` again; a writable PATH folder remains part of the trust boundary.
- On Windows a process started through WMI, a scheduled-task API or a service outlives the run (no process tree contains it). Paths over about 258 characters are not supported.
- Not fixed, on purpose: B5 upper-case hex in `secret.key` is rejected (deleting it is safe, accepting hand-restored keys is a convenience, not security); B7 no retry on reads of a transiently locked ledger (the message is honest); B9 no archive command for a ledger near 1 MB (needs a design, not a patch); B10 orphan `.loom-*.tmp` files are not swept; B13 a virtualenv `python` inside the project is not refused; B15 `--when` is compared as a string; B19 a few older tests still wait on child processes (the live-holder lock test no longer sleeps); the `LOOM_TEST=1`+`LOOM_NOW` pair set by hand still shifts approval expiry (it is a test hook, off unless both are set).
- Not verified: POSIX/macOS runtime, Python 3.8 and 3.12 runtime, CI, the planted-`icacls` repro with the current-folder search enabled, the real Claude Code permission prompts, real Dropbox sync.

## [0.1.1] (2026-11-16)
- Plugin icon added (square 1024 px PNG, generated with Gemini and chosen by the author).
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
