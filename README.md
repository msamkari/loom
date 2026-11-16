# loom

A content-pipeline orchestrator for Claude Code. One config per project says which formats you make (reel, carousel, thread, guide...), which stages each format has, which deterministic checks guard each stage, and which channels exist. One ledger file says where every item is. Nothing is published without a recorded approval.

Python 3.8+, standard library only. MIT.

## What it does
- Keeps a per-item ledger (`Loom/ledger.json`): stage, status, gate results with dates, artifacts, approvals.
- `gate` runs the checks configured for a stage and records pass or fail. It never advances an item.
- `advance` moves an item only if its latest gate passed and any required approval is recorded.
- `build`, `stage`, `publish`, `schedule` run adapters: named commands from your config. Nothing is hard-coded; media builders, voice tools and staging tools are all adapters.
- `adopt` adds loom to an existing folder: dry run first, snapshot of config and state files, additive files only, shadow mode, and a hash-checked `rollback`.

## Install and first run
Install from the marketplace:

    /plugin marketplace add msamkari/samkari-plugins
    /plugin install loom@samkari-plugins

Then in a project folder:

    python scripts/loom.py init --formats reel,carousel --pack saudi --channels demo_channel
    python scripts/loom.py init --formats reel,carousel --pack saudi --channels demo_channel --yes
    python scripts/loom.py add ep-001 --format reel --scaffold
    python scripts/loom.py gate ep-001 script
    python scripts/loom.py next

Without `--yes` every writing command prints its plan and writes nothing. `init` never overwrites. An answers file can replace the flags (`--answers file.json`, keys: kind, formats, pack, channels, identity, excluded_folders, shadow_mode, commands). A no-project profile (identity, default pack, formats, channels) lives in `~/.loom/profile.json` (`LOOM_HOME` relocates it); `loom profile --name ... --pack ... --yes` creates it and `init` uses its pack as a default.

## Commands
| Command | Writes | Pre-approved in the skill |
|---|---|---|
| `status`, `next` | nothing | yes |
| `gate <item> <stage>` | one gate record, only inside `Loom/`; runs only commands you pinned with `trust` | yes |
| `trust [--yes]` | `$LOOM_HOME/trust.json` (outside the project) | no |
| `profile`, `init`, `adopt`, `rollback` | files, only with `--yes` | no |
| `add`, `attach`, `approve`, `advance` | ledger | no |
| `build <item> <adapter>` | ledger, adapter output | no |
| `stage`, `publish`, `schedule` | ledger, external tool | no |

Exit codes: 0 ok, 1 error, 2 a check failed or a rule refused.

## Configuration (`loom.config.json`, schema 1)
Top level: `schema`, `formats` (required); `pack`, `project_kind`, `shadow_mode`, `excluded_folders`, `identity` (name to relative path), `channels`, `commands` (named argv prefixes), `adapters`, `approval_ttl_hours`. Unknown fields are rejected.

A format is `{"stages": [{"name", "checks": [...], "requires_approval": bool}]}`. Check types:
- `command`: `argv` list, optional `pass_codes` (default `[0]`), `timeout` (1-600 s, default 60), `env` (names of variables to pass through), `max_output`. Exit-code semantics follow the tool, for example the lahja linter: 0 clean, 2 findings (a failure), 1 error (a failure).
- `facts`: a `facts.json` of `{"facts": [{"id", "claim", "source", "verified", "expires"}]}` (dates `YYYY-MM-DD`). Fails if a source is missing, a date is malformed, verified is in the future or a fact has expired.
- `files`: required files exist and are not empty.
- `checklist`: a markdown file where every `- [ ]` item must be ticked.

Adapters live in `adapters.build|stage|publish|schedule` as `{name: {argv, timeout, env, max_output, pass_codes, allowed_stages, produces}}`. Gate commands and adapters are separate namespaces: `gate` can never run an adapter.

Placeholders must be whole argv tokens: `{item}`, `{format}`, `{stage}`, `{pack}`, `{python}`, `{cmd:NAME}` (expands to the argv prefix `commands.NAME`), `{itempath:FILE}` (becomes `Loom/items/<item>/FILE`), and in stage, publish and schedule adapters `{channel}` and `{when}`. Paths in `files`, `facts`, `checklist` and `produces` may use `{item}` inside the string.

### Trust pin (what the pre-approved `gate` may run)
`gate`, `build`, `stage`, `publish` and `schedule` run a command from `loom.config.json` only if the SHA-256 of all configured commands (every gate and adapter spec: argv, env names, timeout, pass codes, named commands, channels, the absolute project root and the absolute path each program resolves to) is recorded in `$LOOM_HOME/trust.json` (default `~/.loom`, never inside the project). Only `trust --yes` writes that record. `trust` is not pre-approved: Claude Code asks you, `trust` without `--yes` prints every command in full and writes nothing, and the skill tells Claude to run `--yes` only after you reviewed the list. Any change to a command makes `gate` refuse with a message to review and run `trust` again. The pre-approved `gate` only runs commands you have pinned. `status`, `next` and `gate` take no `--root`: they always use the current folder, write nothing outside `Loom/`, and `gate` discards its result if the config or the ledger's approvals changed while its commands ran.

### How commands run
No shell is ever started. `argv[0]` must be a bare program name, `{python}` or `{cmd:NAME}`. Refused: `.bat .cmd .com .ps1 .vbs .js .wsf` and similar, shells and launchers (`cmd`, `powershell`, `pwsh`, `bash`, `sh`, `zsh`, `forfiles`, `wscript`, `cscript`, `mshta`, `rundll32`, `env`, ...) including names with trailing dots or spaces, other case, extensions or paths. The program is found only through `PATH` (relative entries, the project folder and the current folder are skipped; Windows accepts `.exe` only) and its absolute path is part of the trust pin. The working folder is the project root, stdin is closed, and the environment is a small allow-list (`PATH`, `TEMP`/`TMP`, `LANG`/`LC_*`, `PYTHONIOENCODING`, and `SYSTEMROOT`/`WINDIR` on Windows). A variable named in a check's `env` is passed only if it is ALSO listed in your own `$LOOM_HOME/env_allow.json` (`{"allow": ["NAME"]}`). Output is capped, sanitised and has the listed values redacted, also in reversed, base64 and hex form (not every possible re-encoding). A command that you pinned can still write a secret to a file; that cannot be prevented, which is why the pin exists. On timeout and on normal exit the whole process tree is killed: a Windows Job Object (`KILL_ON_JOB_CLOSE`, with `taskkill /T /F` as the fallback if a job cannot be used) or, on POSIX, the command's own process group. A POSIX descendant that creates its own session (`setsid`) escapes the group kill. loom never reads keys; a tool that needs one reads its own variable.

### Output hygiene
Everything loom prints goes through one sanitiser: ANSI/CSI/OSC sequences, C0/C1 controls, bidi controls, zero-width and tag characters, U+2028/2029 are removed, newlines become ` | `, lengths are capped, adapter output is prefixed with `  > ` on every line, and `status`/`next` show at most 200 items plus a count. Stored ledger strings may not contain controls or line separators.

## Ledger (`Loom/ledger.json`, schema 1)
`{"schema": 1, "items": [item]}` with item fields: `id` (letters, digits, `.`, `_`, `-`, up to 64), `format`, `stage`, `status` (`active|blocked|done`), `created`, `notes`, `gates[]` (`stage`, `result` pass or fail, `date` UTC, `command`, `detail`), `artifacts[]` (relative paths only), `approvals[]` (`what` = `publish`, `schedule` or `advance:<stage>`, `channel`, `when`, `date`, `note`, `used`), `events[]` (`date`, `action`, `adapter`, `result`, `detail`). Strict validation: unknown fields, duplicate keys, NaN, files over 1 MB, absolute or `..` paths and denied folders are refused. Writes are atomic under a mkdir lock (stale after 120 s), the previous version is kept as `ledger.json.bak`, and a corrupt ledger stops every command with a message; it is never reset. Files may use BOM and CRLF; invalid UTF-8 is an error.

## Approvals and publishing
`approve <item> --what publish --channel <c> [--when ...]` records the user's yes, signed with HMAC-SHA256 using a per-user secret in `$LOOM_HOME/secret.key` (created by the first `approve`, `profile --yes`, `init --yes` or `adopt --yes`; never inside the project, never printed). The signature covers the project root, item, channel, what, when, date and a nonce. `publish`, `schedule` and `advance` refuse unsigned, edited or copied approvals; forging one requires the user's secret key (a process running as the same user can read that file, so this is not protection against malware, which is why `trust` pins commands). The skill tells Claude to run `approve` only after the user said yes in chat for that exact item, channel and time. `--when` is validated at `approve`: strict ISO-8601 with a zone (`2026-12-01T09:00:00+03:00` or `...Z`), not in the past; publish and advance approve `now`. `publish` needs an unused approval for the exact item, channel and `now`; `schedule` for the exact `--when`, still in the future. `publish` and `schedule` run only when the item is at the publish stage (the stage named `publish`, else the last stage); `allowed_stages` can only narrow that. The approval is reserved while the adapter runs and consumed only if it succeeded: a missing placeholder or a failing command does not burn it; a spent signature is also recorded in `$LOOM_HOME/spent.json`, so resetting the `used` field does not replay it. Approvals expire after `approval_ttl_hours` (default 72). `LOOM_NO_PUBLISH=1` makes `approve`, `publish` and `schedule` refuse, for scheduled runs. `LOOM_NOW` is honoured only when `LOOM_TEST=1`. `stage` makes drafts only.

## Private folders
Never read, listed or written by any command, and refused in configs, ledgers, artifacts and snapshots: folders named episodes, characters, followers, analytics, research, prompts, private, secrets, credentials, keys, env (any case, any depth), and files such as `.env*`, `*.pem`, `*.key`, `id_rsa*`, `*secret*`, `*credential*`. `excluded_folders` adds names; the defaults cannot be removed.

## Adoption and rollback
`adopt` guesses formats from file and folder names only. With `--yes` it writes `loom.config.json`, `Loom/` and `Loom/install_manifest.json` (path, sha256 before and after), copies CLAUDE.md, MDs/HANDOVER.md, Jobs/state_manifest.json, `.claude/settings*.json` and any `--snapshot` files into `Jobs/_Archive/loom_pre_adopt_<date>/` (suffix a, b, c on repeats), except secret-like files (`settings.local*`, `.env*`, `*.key`, `*.pem`, `credentials*`, `tokens*`), which are never copied: only their names and sha256 go into the manifest, and turns `shadow_mode` on: loom records, while `stage`, `publish` and `schedule` are refused. `--claude-block` appends one marked block to CLAUDE.md. The manifest is written first as an intent log (`status: pending`), then each file is created exclusively, then it is marked `complete`; an interrupted adopt is resumable by `rollback` or by running `adopt` again. The manifest's HMAC is recorded in `$LOOM_HOME`, and `rollback` refuses a manifest it cannot verify, any path outside `loom.config.json`, `Loom/` and the CLAUDE.md block (never `.git/`, `.claude/`, links or `..`), and never deletes a file loom did not create. `rollback` (dry run by default) removes only files whose hash still matches, restores snapshot copies only for files adopt itself changed and only if they still match what adopt wrote, and leaves and reports everything else. Snapshots are left as an archive unless you pass `--purge-snapshot`.

## How it fits
- persistent-memory: keeps HANDOVER and job logs; loom does not write them. Adopt snapshots them, nothing more.
- vitals: health checks of the project; loom adds the per-item ledger it lacks.
- lahja: dialect linter. Configure it as `commands.lahja` and use it in a `language` stage. loom only runs the command and reads its exit code.
- lahja-voice: configure `dry` as a build adapter and `send` as a separate adapter that you leave out of anything unattended. loom never imports either plugin.
- nightshift: can resume loom work; run it with `LOOM_NO_PUBLISH=1`.

## What it does NOT do
- It does not write scripts, render media, speak, or post by itself; adapters you configure do.
- It does not verify that a post is live, pull analytics or detect duplicate topics (the design's idea and verify gates are not in 0.1).
- It does not know whether a gate result is stale: if you edit a file after a passing gate, run the gate again.
- It does not authenticate the user beyond the secret key: whoever can read `$LOOM_HOME/secret.key` can sign approvals, and the permission prompt of Claude Code is the real second check.
- No icon yet.

## Honest limits
- Commands you pin with `trust` run with your privileges. An interpreter such as `{python}` can run anything its arguments say; the pin is what you review, so review it like code. A pinned command may also write files (including secrets it was given).
- A config you did not write (a cloned project) has no pin: `gate` refuses its commands until you run `trust` and review them.
- `{` or `}` inside an argv token that is not a whole placeholder is refused, so JSON or dict snippets cannot be passed as arguments; put them in a script file.
- Windows 8.3 short names are not resolved by the deny list (not tested here).
- Reparse-point checks use symlink and junction tags; cloud-sync placeholders are not refused. Dropbox sync conflicts on two machines writing at once are only reduced by the lock, which is local.
- The lock is a directory in `Loom/` (project root for init, adopt and rollback). A lock is taken over only when it is older than 120 s AND its recorded process is dead (a lock of another host needs 10 times that); the ledger is re-read inside the lock and the lock is re-checked right before each replace. Dropbox-style sync across machines is not covered.
- Tested on Windows with Python 3.14. The POSIX process-group path, macOS, Python 3.8 at runtime and CI have not been run yet (the grammar is checked against 3.8 in the tests).

## Development
    python -m unittest discover -s tests -v
    claude plugin validate .
