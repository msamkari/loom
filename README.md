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
Install the plugin, then in a project folder:

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
| `gate <item> <stage>` | one gate record | yes |
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

Command safety: argv list, never a shell (a shell as the program is refused), working folder is the project root, stdin closed, environment limited to a small allow-list (PATH and the like) plus the names you list per command, output capped, control characters stripped, listed variable values redacted, process tree killed on timeout. loom never reads keys; a tool that needs one reads its own variable.

## Ledger (`Loom/ledger.json`, schema 1)
`{"schema": 1, "items": [item]}` with item fields: `id` (letters, digits, `.`, `_`, `-`, up to 64), `format`, `stage`, `status` (`active|blocked|done`), `created`, `notes`, `gates[]` (`stage`, `result` pass or fail, `date` UTC, `command`, `detail`), `artifacts[]` (relative paths only), `approvals[]` (`what` = `publish`, `schedule` or `advance:<stage>`, `channel`, `when`, `date`, `note`, `used`), `events[]` (`date`, `action`, `adapter`, `result`, `detail`). Strict validation: unknown fields, duplicate keys, NaN, files over 1 MB, absolute or `..` paths and denied folders are refused. Writes are atomic under a mkdir lock (stale after 120 s), the previous version is kept as `ledger.json.bak`, and a corrupt ledger stops every command with a message; it is never reset. Files may use BOM and CRLF; invalid UTF-8 is an error.

## Approvals and publishing
`approve <item> --what publish --channel <c> [--when ...]` records the user's yes. The skill tells Claude to run it only after the user said yes in chat for that exact item, channel and time. `publish` needs an unused approval for the exact item, channel and `now`; `schedule` for the exact `--when`. The approval is consumed when the adapter starts (a failed run needs a fresh approval) and expires after `approval_ttl_hours` (default 72). `LOOM_NO_PUBLISH=1` makes `approve`, `publish` and `schedule` refuse, for scheduled runs. `stage` makes drafts only.

## Private folders
Never read, listed or written by any command, and refused in configs, ledgers, artifacts and snapshots: folders named episodes, characters, followers, analytics, research, prompts, private, secrets, credentials, keys, env (any case, any depth), and files such as `.env*`, `*.pem`, `*.key`, `id_rsa*`, `*secret*`, `*credential*`. `excluded_folders` adds names; the defaults cannot be removed.

## Adoption and rollback
`adopt` guesses formats from file and folder names only. With `--yes` it writes `loom.config.json`, `Loom/` and `Loom/install_manifest.json` (path, sha256 before and after), copies CLAUDE.md, MDs/HANDOVER.md, Jobs/state_manifest.json, `.claude/settings*.json` and any `--snapshot` files into `Jobs/_Archive/loom_pre_adopt_<date>/` (suffix a, b, c on repeats), and turns `shadow_mode` on: loom records, while `stage`, `publish` and `schedule` are refused. `--claude-block` appends one marked block to CLAUDE.md. `rollback` (dry run by default) removes only files whose hash still matches, restores snapshot copies only for files adopt itself changed and only if they still match what adopt wrote, and leaves and reports everything else.

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
- It does not authenticate the user. The approval is a ledger record, and the permission prompt of Claude Code is the real second check.
- No icon yet.

## Honest limits
- Whoever can edit `loom.config.json` decides which commands `gate` runs without a prompt, because `gate` is pre-approved. Review config changes like code.
- Adapter commands run with your privileges. Refusing shells as the program does not stop an interpreter from running anything it is told to.
- Reparse-point checks use symlink and junction tags; cloud-sync placeholders are not refused. Dropbox sync conflicts on two machines writing at once are only reduced by the lock, which is local.
- The lock is a directory with a timestamp; a stale-lock takeover has a tiny race if two processes break it at the same instant.
- Tested on Windows with Python 3.14. CI covers 3.8 and 3.12 on Ubuntu and Windows but has not been run yet.

## Development
    python -m unittest discover -s tests -v
    claude plugin validate .
