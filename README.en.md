# POPOPX Bot Studio

A self-hosted Bot factory, zero-code auto-reply engine, message router, developer Open API
and plugin gateway for the POPOPX network. One process supervises any number of
`popopx-cli` Bot instances over loopback WebSockets, with a web console (18 locales)
and an offline cold-backup tool.

- Licence: AGPL-3.0-only (see `LICENSE`)
- Zero binary bundling: this repository never contains or ships a compiled `popopx-chat`
  binary. At runtime it only drives external `popopx-cli` processes over
  `ws://127.0.0.1:<port>`; the installer can fetch the binary on demand into
  `/usr/local/bin/popopx-cli`, and `--no-node-download` skips that entirely.
- Self-test gate: `python3 -m app.main --self-test` → **15 groups / 1884 real assertions /
  0 failures / ~18 s / exit code 0**. It only needs `studio/tests/fake_popopx_cli.py`
  (a local stand-in that speaks the same wire protocol and keeps profiles in `bot_chat.db`,
  so it survives a restart like the real CLI) — no network, no SMP server.

Chinese document: [`README.md`](README.md)

---

## 1. Architecture

```
browser console / developer clients
        │  http://127.0.0.1:8090        X-Studio-Token / cookie
┌───────▼────────────────────────────────────────────────────────────┐
│ POPOPX Bot Studio (Python 3.11 + FastAPI, single process)          │
│  main.py           routing, auth, lifecycle                                      │
│  config.py         .env / environment, permission checks (0700·0600)             │
│  database.py       SQLite (WAL) ledger + schema_migrations (currently v4)        │
│  bot_supervisor.py per-Bot isolated data dir, loopback port, wrapper, backoff    │
│  ws_protocol.py    line-protocol frames, /_address /_create /_send commands      │
│  gateway.py        inbound event → rules/router/plugins → outbound send          │
│  rule_engine.py    auto-reply (exact / prefix / regex / default)                 │
│  router_engine.py  keyword routing and ticket hand-off                           │
│  plugin_manager.py plugin bus: discovery, lifecycle, isolated dispatch, masking  │
│  open_api.py       Telegram-style developer API                                   │
│  i18n.py           18 locales, negotiation, welcome templates, parity asserts     │
└───────┬────────────────────────────────────────────────────────────┘
        │  ws://127.0.0.1:5230..5299 (never 0.0.0.0)
   popopx-cli ×N   one process per Bot, data in <data_dir>/bots/<bot_id>/cli-data
        │
   smp1..8.popopx.im (built-in dual-stack cluster, overridable via BOT_SMP_SERVERS)
```

Isolation contract (guarded by the `supervisor`, `config` and `install` groups):

| Aspect | Value |
| --- | --- |
| Console bind | `127.0.0.1:8090` by default; a non-loopback bind requires `STUDIO_ALLOW_LAN=1` or an explicit `--lan` |
| Bot control ports | from `BOT_WS_PORT_BASE` (default 5230, ceiling 5299), loopback only |
| Bot data directory | `<STUDIO_DATA_DIR>/bots/<bot_id>/cli-data`, dirs `0700`, files `0600` |
| Launch wrapper | `run-cli.sh` (`#!/bin/sh` with per-token `shlex.quote`, so quote-stripping supervisors cannot split it), keeps `0755`; carries `--user-display-name <profile>` only while cli-data is still empty, so a headless start never blocks on the interactive prompt |
| Bot profile | provisioning and restarts reuse the stored profile via `/user` → `/users` → `/_user <id>`; `/_create user` is never sent twice |
| SMP cluster | inherits the binary's built-in `smp1..8.popopx.im`, override with `BOT_SMP_SERVERS` |
| Credentials | `STUDIO_ADMIN_TOKEN` is read from `.env` (0600) or the environment only — never inlined into the plist or unit file |

## 2. Layout

```
install_ubuntu22.sh        Ubuntu 22.04 installer (native = service user + /opt + systemd / dev = venv only)
install_macos.sh           macOS installer (LaunchDaemon im.popopx.botstudio)
start_macos.sh             everyday macOS launcher (venv, random token, --check/--self-test)
docker-compose.yml         orchestration (loopback publish only, cap_drop + no-new-privileges)
.env.example               configuration template, 11 keys
official_tools/
  export_bot_bundle.py     offline cold backup: export / list / verify / restore (plain and AES-256-GCM)
studio/
  app/                     engine sources (see the diagram above)
  plugins/                 the four built-in plugins
  static/index.html        web console (zero-build single page, 18 locales)
  site/index.html          product site and tutorial
  tests/fake_popopx_cli.py protocol stand-in used by the self-test
  requirements.txt         pinned dependencies
```

## 3. Installation

### macOS

```bash
./install_macos.sh --check          # diagnostics only, nothing changes
./install_macos.sh --dry-run        # prints every planned action plus the plist
sudo ./install_macos.sh             # installs to /opt/popopx-bot-studio, registers LaunchDaemon
```

For day-to-day work use the launcher (no root; it creates `.venv`, installs
dependencies on demand and writes a random token into `.env` with mode 0600):

```bash
./start_macos.sh                    # 127.0.0.1:8090
./start_macos.sh --check
./start_macos.sh --self-test
```

### Ubuntu 22.04

```bash
sudo ./install_ubuntu22.sh --mode native --check
sudo ./install_ubuntu22.sh --mode native --dry-run
sudo ./install_ubuntu22.sh --mode native
systemctl status popopx-bot-studio
```

`native` creates the `popopx-studio` system user, a Python 3.11 venv and
`/etc/systemd/system/popopx-bot-studio.service` (`Environment=STUDIO_HOST=127.0.0.1`).
The service user's primary group always comes from `--group` (defaulting to `--user`):
`groupadd --system --force` pre-creates it, `useradd --system --gid <group>` uses it, and an
existing user whose primary group differs is converged with `usermod -g` — a matching user is
left alone. `useradd -U/--user-group` is deliberately not used: it creates a group named after
the user and silently bypasses `--group`, after which `Group=` in the unit and the ownership of
the data directory point at a group the service user is not a member of. systemd only checks
that the group exists, so the mismatch produces no error at all. `--check` re-verifies the
primary group, that the group exists in the group database, and the owning group of
`STUDIO_DATA_DIR`, printing the correcting command when they diverge.
`dev` only builds the venv plus `.env` and can run unprivileged. Both installers accept:

| Flag | Effect |
| --- | --- |
| `--dry-run` / `-n` | print all planned actions; no writes, no downloads |
| `--check` | diagnose layout, python, dependencies, `.env` mode, CLI, bind address, service unit, and whether the service user's primary group and the data directory's owning group match `--group` |
| `--uninstall` | remove the service (keeps `.env`, data directory and CLI) |
| `--no-node-download` | do not download `popopx-cli`; Studio then runs in offline-degraded mode |
| `--lan` (macOS) | explicitly bind `0.0.0.0` and set `STUDIO_ALLOW_LAN=1` |

On-demand download: when `/usr/local/bin/popopx-cli` is absent and `--no-node-download`
was not passed, the installer detects OS and CPU architecture, pulls the latest asset
from the `popopx-chat/popopx-chat` GitHub Releases, verifies its SHA-256 and installs it
as `/usr/local/bin/popopx-cli` with mode 755.

### Docker

```bash
cp .env.example .env && chmod 600 .env      # set STUDIO_ADMIN_TOKEN
docker compose up -d
```

Compose publishes on the host loopback only
(`127.0.0.1:${STUDIO_HOST_PORT:-8090}:8090`), never publishes the Bot control ports,
mounts the sources read-only and keeps state in the named volume `studio-data`.

## 4. Console and APIs

Console at `http://127.0.0.1:8090/`: Bot factory (create/start/stop/cold backup),
auto-reply rules, message routing, plugin configuration, message log and the Open API
reference. The admin token comes from `STUDIO_ADMIN_TOKEN`; browsers use the
`studio_token` cookie or the `X-Studio-Token` header.

Admin API, prefix `/api/admin`: `session` `overview` `bots` `bots/{id}` (plus
`qrcode` `qr.png` `send` `contacts` `groups` `rules` `routing` `start` `stop` `restart`)
`rules/{id}` `rules/preview` `routing/{id}` `routing/preview` `plugins` `plugins/{id}`
`logs` `updates` `backup/export` `backup/import` `backups` `config` `i18n/parity`.

Developer API (Telegram-style, prefix `/api/v1`, each method mounted twice: bare path and
`/bot<TOKEN>/…`):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/getMe` | Bot identity, address, online state |
| POST | `/sendMessage` | direct or group send, quote reply, idempotent `message_id` |
| POST | `/broadcastGroup` | multi-group broadcast with throttling and a failure list |
| POST | `/setWebhook` | register the inbound message callback (https or loopback http only) |
| GET | `/getUpdates` | long-poll the buffered updates (`offset`, `limit≤500`, `timeout≤30s`) |

Inbound webhook delivery: `POST /api/v1/hooks/<bot_id>/<secret>`, claimed by whichever
enabled plugin owns that `secret`.

## 5. Built-in plugins

| plugin_id | Priority | Scope | Function |
| --- | --- | --- | --- |
| `webhook_relay` | 40 | message | pushes external monitoring alerts from `POST /api/v1/hooks/<bot>/<secret>` to groups/contacts, and relays inbound messages to the Bot's `webhook_url` |
| `auto_reply` | 60 | message | keyword and command auto-reply, nested command menus, scheduled announcements (rules live in the plugin config, editable in the UI) |
| `msg_router` | 65 | message | cross-chat routing: opens a ticket from a customer's direct chat into a group, replies in the group with the ticket number to hand it back |
| `llm_bridge` | 80 | message | OpenAI-compatible `/chat/completions` bridge with custom base URL, key, model, system prompt and per-session context memory |

Bus discipline: one module in `studio/plugins/` exposes `StudioPlugin` subclasses. Every
lifecycle call and dispatch is wrapped, counted and logged — a raising plugin only
increments `errors` and writes one `status="error"` log line, it can never take the gateway
down. Plugins run in ascending `priority` order and the first `handled=True` result stops
the chain. `password` fields are masked as `********` on both read and write paths.

## 6. Internationalisation

- 18 iOS-aligned locales: `en, zh-Hans, zh-Hant, ja, bg, cs, de, es, fi, fr, hu, it, nl, pl, ru, th, tr, uk`;
  any missing entry falls back to `en`.
- Zero build: the structured JSON catalog is inlined at render time
  (`__I18N_CATALOG_JSON__`); the front-end dictionary engine combines `localStorage` with
  `navigator.languages`, and the top switcher changes language without a reload.
- FastAPI fills each Bot's default welcome template according to its `default_locale`,
  expanding placeholders such as `{bot_name}`.
- The `i18n` self-test group asserts that every locale's key set matches `en` exactly, that
  placeholders never drift and that no entry is empty; `/api/admin/i18n/parity` exposes the
  same check at runtime.

## 7. Offline cold backup

```bash
cd studio
../.venv/bin/python ../official_tools/export_bot_bundle.py list
../.venv/bin/python ../official_tools/export_bot_bundle.py export --bot <id> --out /secure/backups
../.venv/bin/python ../official_tools/export_bot_bundle.py verify /secure/backups/<name>.botbundle
../.venv/bin/python ../official_tools/export_bot_bundle.py restore --bundle <file> --data-dir <new-dir>
```

Artifacts are `.botbundle` (gzip tar) plus the sidecar `<name>.botbundle.json`; with
`--passphrase` (or `--passphrase-stdin`) you get an AES-256-GCM package (magic `PBSB`).
The per-member SHA-256 list inside the manifest is self-referential — only the sidecar's
`payload_sha256` can anchor it, so **a missing sidecar fails verification**.
Restore is idempotent: reply rules upsert on `(bot_id, trigger_type, pattern)`, routing
rules are deduplicated by content signature, and a Bot at the same address reuses the
existing ledger row; `--replace-rules` means "wipe the target's extra rules". Restored
`cli-data` files are clamped to `0600` (`run-cli.sh` keeps its executable bit).

Exit codes: `0` ok / `1` runtime error / `2` usage error / `3` Bot not found /
`4` Bot deleted / `5` destination not writable / `6` corrupt or failed verification /
`7` passphrase problem / `8` ledger write failure.

## 8. Self-test

```bash
cd studio
../.venv/bin/python -m app.main --self-test                 # everything
../.venv/bin/python -m app.main --self-test --group bundle  # one group
../.venv/bin/python -m app.main --check                     # config/permissions/deps only
```

| Group | Assertions | Coverage |
| --- | --- | --- |
| `config` | 62 | environment parsing, loopback constraint, permission warnings |
| `database` | 110 | ledger CRUD, migrations, soft delete, plugin config |
| `ws_protocol` | 103 | line-protocol frames, command grammar, probe commands and error-frame wake-ups, errors and timeouts |
| `supervisor` | 86 | port allocation, isolated dirs, wrapper and first-launch profile name, reconnect backoff |
| `provisioning` | 66 | Bot creation, `/_address`, name and avatar retention, restart and cold-restore idempotency |
| `rules` | 60 | exact/prefix/regex/default matching and priority |
| `router` | 78 | keyword routing, ticket ids, templates and cooldown |
| `gateway` | 94 | inbound pipeline, plugin dispatch, update buffer |
| `plugins` | 94 | discovery, lifecycle, masking, isolation and counters |
| `open_api` | 119 | five methods, auth, idempotency, long polling, webhook |
| `web_admin` | 146 | console routes, CSRF/cookie, authorisation and audit |
| `i18n` | 320 | 18-locale completeness, negotiation, welcome text, page injection |
| `web_live` | 55 | real ASGI lifecycle, WebSocket, cold-backup round trip |
| `bundle` | 250 | export/verify/tamper/cross-ledger migration/idempotency |
| `install` | 241 | script syntax and flags, dry runs, service-user primary group vs `--group` (including a stubbed real run of `create_service_user`), loopback and zero-bundling, no stubs |

## 9. Operations and security notes

- The admin token is the only gate: keep the bind on loopback, or put a TLS reverse proxy
  in front. `--lan` is an explicitly auditable decision.
- `.env` must be `0600` and `STUDIO_DATA_DIR` must be `0700`; both `--check` and startup warn.
- Soft-deleted Bots keep their name and control port; the detail endpoint returns
  `status:"deleted"` rather than 404.
- Protect backup directories yourself — a cold bundle contains Bot identity material.
- Never use the non-existent `/address` or `/auto_accept` commands; addresses and incognito
  handling go through `/_address 1` and `/_address_settings 1 {...}`, keeping
  `acceptIncognito` at `false` so the Bot retains its own name and avatar.
- Profile ownership is decided by the `/users` list, never by error wording: `/user` may answer
  with a `noActiveUser` error frame *or* an `activeUser` frame carrying `user: null`, and both
  shapes must fall back to `/users` plus `/_user <id>` to reactivate the stored profile. While a
  profile exists, `/_create user` is never sent (`CreateActiveUser` answers `userExists`), and
  renaming a Bot never silently overwrites the existing card.
- A restored cold backup brings its own profile, so `boot()` after a Studio restart and a
  Web-side restart of the same Bot must both reuse it. `--user-display-name` is injected on the
  first launch of an empty cli-data only: keeping it resident would turn "rename this Bot" into
  "the CLI never starts again".

## 10. Licence

AGPL-3.0-only, see `LICENSE`. No `popopx-chat` binary is distributed from this repository.
