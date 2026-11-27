# POPOPX Bot Studio

A self-hosted Bot factory, zero-code auto-reply engine, message router, developer Open API
and plugin gateway for the POPOPX network. One process supervises any number of
`popopx-cli` Bot instances over loopback WebSockets, with a web console (21 locales,
including Arabic RTL) and an offline cold-backup tool.

As of this version every Bot can also run a **24/7 stand-in**: a small on-device model extracts
intent, a large model only writes the wording, and the calendar is never touched until the owner
taps confirm. Two stand-ins negotiate over end-to-end-encrypted SMP **exchanging masked candidate
slots only**, while external visitors book through a one-time web link that needs no install, no
account and no e-mail address.

- Licence: code is AGPL-3.0-only (see `LICENSE`); the bundled Needle 3 weights are a third-party
  Apache-2.0 asset — text and attribution live in `studio/assets/models/` (section 11).
- Zero binary bundling: this repository never contains or ships a compiled `popopx-chat`
  binary. At runtime it only drives external `popopx-cli` processes over
  `ws://127.0.0.1:<port>`; the installer can fetch the binary on demand into
  `/usr/local/bin/popopx-cli`, and `--no-node-download` skips that entirely.
- Zero model downloads: `needle3.cact` (33.7 MiB, under 50 MB) ships inside the repository, is
  SHA-256 verified before loading, and is usable the moment the service starts. Without a C
  runtime or SDK the runtime falls back to the deterministic extractor in this repo (section 5).
- Self-test gate: `python3 -m app.main --self-test` → **26 groups / 8287 real assertions /
  0 failures / ~20.4 s / exit code 0**. It only needs `studio/tests/fake_popopx_cli.py`
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
│  database.py       SQLite (WAL) ledger + schema_migrations (currently v6)        │
│  bot_supervisor.py per-Bot isolated data dir, loopback port, wrapper, backoff    │
│  ws_protocol.py    line-protocol frames, /_address /_create /_send commands      │
│  gateway.py        inbound event → rules/router/plugins → outbound send          │
│  rule_engine.py    auto-reply (exact / prefix / regex / default)                 │
│  router_engine.py  keyword routing and ticket hand-off                           │
│  orchestrator.py   cross-agent task dispatch: local grants, hop/concurrency/     │
│                    timeout breakers, fan-out aggregation, audit replay           │
│  orchestrator_local.py  five read-only capability projections, isolated per      │
│                    target Bot                                                    │
│  plugin_manager.py plugin bus: discovery, lifecycle, isolated dispatch, masking  │
│  open_api.py       Telegram-style developer API                                   │
│  i18n.py           21 locales, negotiation, welcome templates, parity asserts     │
│  ── stand-in robot ──────────────────────────────────────────────────────────    │
│  agent_runtime.py      orchestration: intent → preference filter → proposal →    │
│                        card → approval → receipt, every step audited             │
│  needle3_runtime.py    on-device small engine (extracts the 5 tool calls only)   │
│                        plus the deterministic fallback extractor                 │
│  needle_assets.py      bundled weight discovery and the SHA-256 gate             │
│  agent_preferences.py  per-Bot rules: working hours, buffers, blocked periods,   │
│                        keywords, negotiation policy                              │
│  agent_copy.py         12 copy kinds × 21 locales, placeholder/script gates      │
│  reasoner_bridge.py    the large model writes wording only (loopback/https only) │
│  mac_node_bridge.py    local Mac Node bridge: status, availability, approve      │
│  eco_cards.py          ::POPOPX_ECO:: card and ::CB:: receipt codec              │
│  a2a.py                channel A: masked-slot negotiation frames                 │
│  guest_portal.py       channel B: HMAC one-time link, masked slots, .ics         │
│  ics.py                RFC 5545 event generation (escaping, UTC instants)         │
│  agent_admin.py        /api/agent admin routes plus the /book/<token> portal     │
└───────┬───────────────────────┬─────────────────────────────────────┘
        │  ws://127.0.0.1:5230..5299 (never 0.0.0.0)
   popopx-cli ×N   one process per Bot, data in <data_dir>/bots/<bot_id>/cli-data
        │
   smp1..8.popopx.im (built-in dual-stack cluster, overridable via BOT_SMP_SERVERS)
        ▲ channel A: ::POPOPX_A2A:: frames, signed with the peer session key, masked slots only
        │
   http://127.0.0.1:18920  Mac Node: X-PPX-Token, loopback only, non-loopback refused outright
   http(s)://<studio>/book/<one_time_token>  channel B: no session, no cookie, no external assets
```

Isolation contract (guarded by the `supervisor`, `config`, `install`, `mac_node`,
`guest_portal` and `a2a` groups):

| Aspect | Value |
| --- | --- |
| Console bind | `127.0.0.1:8090` by default; a non-loopback bind requires `STUDIO_ALLOW_LAN=1` or an explicit `--lan` |
| Bot control ports | from `BOT_WS_PORT_BASE` (default 5230, ceiling 5299), loopback only |
| Bot data directory | `<STUDIO_DATA_DIR>/bots/<bot_id>/cli-data`, dirs `0700`, files `0600` |
| Stand-in preference dir | `<STUDIO_DATA_DIR>/bots/<bot_id>/agent/preferences.json`, same `0700`/`0600`, one file per Bot and never shared |
| Mac Node bridge | only `http://127.0.0.1:18920` or `http://localhost:18920`; any other host is rejected inside `load_settings()` (anti-SSRF), requests carry `X-PPX-Token` |
| Reasoner endpoint | plaintext `http` is loopback-only, anything remote must be `https`, and userinfo in the URL is refused; the key is read from `.env` and echoed back masked |
| Guest link | `<base>/book/<token>`; the token is a self-verifying HMAC signature (`{v,lid,iat,exp,mus,dur}`), the server creates no session and sets no cookie |
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
.env.example               configuration template, 26 keys (stand-in, Mac Node, guest portal, reasoner)
official_tools/
  export_bot_bundle.py     offline cold backup: export / list / verify / restore / invite (plain and AES-256-GCM)
  verify_needle_assets.py  SHA-256 manifest checker for the bundled Needle 3 weights
studio/
  app/                     engine sources (see the diagram above)
  assets/models/           bundled model assets: needle3.cact, manifest, config, licence text, notes
  plugins/                 the five built-in plugins
  static/index.html        web console (zero-build single page, 21 locales)
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

Model weights are never part of that download: both installers run
`official_tools/verify_needle_assets.py` against the bundled `studio/assets/models/needle3.*`
(manifest, byte counts, per-file SHA-256, licence text present). `--check` only reports the
problem, while a real install aborts when the check fails — a hand-edited manifest or a truncated
weight file is worse than having no on-device model at all.

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
reference, plus two new panels — **Stand-in robot** (extraction engine and on-device weight
state, a try-a-sentence box, the five tool slots, the per-Bot preference rule editor, peer
pairing, pending proposals, negotiation start, and the full-lifecycle audit trail) and
**Guest links** (issue and list one-time links, revoke, fetch the full link on demand,
visit/claim counters). The admin token comes from `STUDIO_ADMIN_TOKEN`; browsers use the
`studio_token` cookie or the `X-Studio-Token` header.

Admin API, prefix `/api/admin`: `session` `overview` `bots` `bots/{id}` (plus
`qrcode` `qr.png` `send` `contacts` `groups` `rules` `routing` `start` `stop` `restart`)
`rules/{id}` `rules/preview` `routing/{id}` `routing/preview` `plugins` `plugins/{id}`
`logs` `updates` `backup/export` `backup/import` `backups` `config` `i18n/parity`.
`qrcode` and `qr.png` return an opaque `https://popopx.chat/i/v1/<Base64URL ciphertext>` invite
link by default (HKDF-SHA256 + ChaCha20-Poly1305, hiding `smpN.popopx.im` node hostnames;
the IKM/salt/info/AAD parameters match `popopx-service-suite`'s
`opaque_invite_codec.py @ a6c1632` byte-for-byte, so clients carry one decryption key; the
codec accepts the same URI-scheme allowlist of `popopx:/`, `popopx://` and `https://`, with
the legacy `smp://` vector kept only as a rejected case); only the collapsed diagnostics block
in the QR dialog and `qr.png?raw=1` reveal the raw `smp://` address.
Failures are separated: an unknown Bot is 404, a Bot without a permanent address is 409, and a
link rejected by the scheme allowlist or the byte cap is 409 as well — the console therefore
still opens the dialog when no image comes back and writes the reason into the raw-diagnostics
drawer instead of showing a blank panel. One measured boundary matters: the codec accepts 2048
bytes of plaintext (aligned with the service suite) while a QR code at version 40 with error
correction Q holds only 1663 bytes, so links in that band "seal but cannot be drawn" — the API
answers 409 with a capacity message, never a 500.

Stand-in admin API, prefix `/api/agent` (same `require_admin` guard): `summary`,
`engine` (GET state / POST switch), `extract` (try a sentence), `prefs/{bot_id}` (GET/POST)
and `prefs/{bot_id}/reset`, `peers` (GET/POST) and `peers/remove`, `proposals` and
`proposals/{id}/decision`, `negotiations` and `negotiate`, `audit`, `guest/links` (GET/POST),
`guest/links/{id}/revoke`, `guest/links/{id}/url` (returns the full link once, nonce-guarded
against replay), `node` (GET) and `node/probe` (POST).

Cross-agent orchestration shares the `/api/agent` prefix (same `require_admin` guard):
`orch` (policy and task snapshot), `orch/grants` (GET/POST), `orch/grants/{id}/toggle`,
`orch/grants/{id}/delete`, `orch/dispatch`, `orch/fanout`, `orch/tasks`, `orch/tasks/{id}`,
`orch/tasks/{id}/cancel` and `orch/replay?correlation_id=`.

Guest channel (no admin token — the token *is* the credential): `GET /book`,
`GET /book/<token>`, `POST /book/<token>` (submit a time preference) and
`GET /book/<token>/invite.ics` (only serves an .ics once the owner has approved).

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

## 5. The stand-in robot (24/7)

Each inbound message is split in two halves: **the small on-device model only extracts intent,
the large model only writes wording**, and no calendar change happens until the owner approves.

### 5.1 Extraction engine and dual-engine routing

- `needle3_runtime.py` loads `Cactus-Compute/needle3` (`needle3.cact`, 33.7 MiB, 121 M parameters,
  engine 3.1.0) and produces one of five tool calls in milliseconds: `calendar.get_availability`,
  `calendar.propose_create`, `calendar.propose_reschedule`, `calendar.propose_cancel`,
  `workspace.summarize_file`. All five tool functions are **read-only echo stubs** (`TOOL_STUBS`):
  they record arguments for the layer above, never write a calendar and never read file contents.
- Weights are loaded from the in-repo path only after `needle_assets.ensure_weights()` passes the
  SHA-256 gate — **no model is ever downloaded at runtime**. The manifest and the re-fetch recipe are
  in `studio/assets/models/needle3.manifest.json`; verify independently with
  `python3 official_tools/verify_needle_assets.py` (both installers and `--check` run it, and an
  install aborts if it fails).
- No C runtime, missing SDK, a failed checksum or a load error all degrade to the built-in
  **deterministic extractor**: Chinese and English patterns for booking, asking availability,
  rescheduling, cancelling and summarising, plus relative dates (tomorrow, 周四, next week),
  clock times (下午三点, 3pm, 15:00), durations (半小时, 45 min) and timezone hints. The clock comes
  in through `hints={"now": …}`, so self-test results never depend on the day they run. The engine
  identity, the degradation reason and the call counters are all exposed via `status()`; extraction
  never raises into the caller. Measured here on the fallback path, 2400 mixed sentences: median
  0.05 ms per message — the same figure `extract()` reports as `latency_ms`.
- `reasoner_bridge.py` writes the copy: Ollama native (`/api/generate`, `/api/chat`) and
  OpenAI-compatible (`/v1/chat/completions`) dialects are normalised from the URL. The system prompt
  forbids adding, changing or guessing any time, date, timezone, duration, name or place, and
  forbids claiming the calendar was written. Every failure (disabled, illegal address, timeout,
  non-200, no copy field) falls back to an `agent_copy` template with the reason recorded, non-200
  counts as an error too, and outbound error text always goes through `redact()` — both key-name
  shapes (`Authorization: Bearer …`, `"api_key": "…"`, `REASONER_API_KEY='…'`, bare `key=…`) and
  token shapes (`sk-`, `ghp_`, `xoxb-`, …). Plaintext `http` is loopback-only, remote endpoints must
  be `https`, and userinfo in the URL is refused.
- Availability and persistence come from the Mac Node; when it is unreachable the runtime reads the
  masked local `calendar_cache`, which stores slots only — never titles.

### 5.2 Per-Bot preference rules

Rules live in `<STUDIO_DATA_DIR>/bots/<bot_id>/agent/preferences.json` (dir `0700`, file `0600`,
one per Bot, never shared). A `version` that disagrees with the code is refused and replaced by the
defaults, and that rescue is recorded. Editable sections: `working_hours` (weekdays and
start/end, where `end` may be `24:00`), `buffers` (pre/post meeting buffers, which only clamp
against the working-hours bounds), `blocked_periods` (fixed blocks, judged against the raw
candidate span), `keywords.boost/block` with `match_fields`, `meeting` (default duration, maximum
duration, minimum gap), `negotiation` and `copy`. Hard limits: `require_owner_approval` must stay
`true` — only the owner taps the final confirmation and no rule can override that; at most 40
keywords per list, blocked-period ids up to 24 characters, durations and buffers bounded. Every
rejected candidate returns a readable reason ("Thursday is not a working day", "with buffers this
falls outside 09:00-18:00 (needs 10:00-11:00 ±15/10 min)", "hits the blocked period 「lunch」",
"that slot is in the past", "a slot spanning days needs the owner's own confirmation"), and those
reasons go to the audit log instead of being swallowed.

### 5.3 Confirmation card and local persistence

Mobile and desktop render the `::POPOPX_ECO::` dynamic confirmation card (codec rules in
`eco_cards.py`, sharing the client constraints of the `::CB::` inbound frame). The owner taps
confirm → the orchestration layer calls `mac_node_bridge.MacNodeBridge.approve` (strict loopback
`http://127.0.0.1:18920` or `http://localhost:18920`, carrying `X-PPX-Token`; non-loopback hosts
are rejected in `load_settings()`) → the proposal becomes `approved` in the ledger → both sides get
an RFC 5545 invite generated by `ics.py`. Restart and cold-restore revival are idempotent.

### 5.4 Channel A: encrypted A2A negotiation

Frame format `::POPOPX_A2A::<base64url(json)>.<base64url(hmac-sha256)>`, signed with the **peer
session key** (the SMP channel already has one), verified with `hmac.compare_digest` plus a version,
a time window and nonce replay protection. "Masked candidate slots only" is enforced structurally by
three independent gates: `mask_slots` rebuilds each slot through a whitelist projection (only
`start/end/tz/free/ref` can survive; a `title` pushed from upstream does not), `encode_frame` walks
the payload before signing and refuses to send if any `FORBIDDEN_KEYS` name appears, and
`intersect_slots` works purely in absolute epochs — wall-clock text never enters the arithmetic, so
timezone and DST errors are not representable. The state machine `open → converged/rejected/expired/
aborted` lives on `a2a_negotiations`, every transition writes one audit row whose detail may contain
only ids, counters and reason codes, and `converged` produces **one `pending` proposal and writes not
a single byte to the calendar**. Rescheduling is an explicit `counter` re-open (the old proposal
becomes `superseded`); `expired/rejected/aborted` rows can never be revived.

### 5.5 Channel B: zero-install guest booking

The owner mints `<base>/book/<one_time_token>`: a self-verifying HMAC token carrying only
`{v,lid,iat,exp,mus,dur}` — the owner's identity and calendar never enter the token. Opening it runs
signature → version → expiry → revocation → visit budget → claim, and the visit counter is a
one-shot check-and-set inside a `threading.Lock` (two concurrent coroutines would otherwise both
pass the budget check). The budget is `min(token mus, max_uses in the ledger)`: raising the stored
number afterwards cannot revive a spent single-use token, and tightening it takes effect immediately,
as does revocation (status is re-read on every request, no authorisation is cached). The visitor
writes a time preference, the portal asks the injected availability source for **masked** free slots
(if it returns nothing it says so honestly rather than inventing slots), and once a single slot
converges it stores a `pending` proposal with `source="guest"` and pushes the `::POPOPX_ECO::` card
to the owner. Before that approval, `GET /book/<token>/invite.ics` serves nothing. The `VEVENT`
contains only a meeting-room link or a "POPOPX Chat call" note — never the owner's real address,
name, e-mail or full schedule. The page is self-contained HTML: no session, no cookie, no
`<script>`, no external reference, visitor input HTML-escaped, the form posts to `action=""`, and
all 21 locales ship with identical placeholders, and the Arabic page is rendered with `dir="rtl"`.

### 5.6 Channel C: in-process multi-agent task orchestration

One Bot's capabilities can be lent to another under an explicit policy, but only inside the
Studio process and only through the five read-only projections in `orchestrator_local.py`
(`reply.compose`, `router.plan`, `calendar.availability`, `workspace.summarize`,
`ledger.profile`) — no extra listening port, no direct SMP connection, no other Bot's ledger rows.

* **Default deny**: a dispatch needs an `(origin, target, capability)` row in
  `agent_task_grants`, otherwise it is refused with `no_grant`. `target` accepts a `*` wildcard,
  but the wildcard still has to be created explicitly and can be disabled or deleted at any time.
* **Budgets**: 3 hops (the `parent_id` ancestry walk refuses cycles), 32 concurrent tasks,
  a 0.5–300 s per-task timeout enforced by `asyncio.wait_for`, and fan-out targets deduplicated
  to at most 8, run under `shield(gather(...))` so one failure never discards the other results.
* **Audit and replay**: every dispatch writes a row into `agent_tasks` with the
  `queued/running/succeeded/failed/timeout/refused/cancelled` state, a `correlation_id`, elapsed
  time, a result summary and the refusal reason. Children inherit the parent's correlation id, so
  `orch/replay` rebuilds the whole tree and the console's orchestration panel draws it. Hard
  deleting a Bot retires its grants and tasks, and the projections immediately report
  `unknown_target`.
* **Scrubbing**: anything reaching `agent_tasks.detail` or the audit text passes shape-based
  redaction first (`sk-…`, `Bearer …`, `key: …`, URLs, multi-label hostnames), including executor
  exception text, so node hostnames never leak into logs.

### 5.7 New configuration keys

| Key | Default | Purpose |
| --- | --- | --- |
| `AGENT_ENABLED` | `1` | master switch for the stand-in (off = messages keep using the existing rules/router/plugin chain) |
| `REASONER_ENABLED` | `0` | let the large model write the copy; off means everything comes from `agent_copy` templates |
| `REASONER_BASE_URL` | empty | reasoner endpoint; plaintext http only for loopback, https required remotely |
| `REASONER_MODEL` | empty | model name (same field in both dialects) |
| `REASONER_API_KEY` | empty | request header only, masked on read and write, never logged or prompted |
| `REASONER_TIMEOUT_SECONDS` | `20.0` | per-request timeout |
| `MAC_NODE_ENABLED` | `0` | enable the Mac Node bridge (availability reads and approval persistence) |
| `MAC_NODE_URL` | `http://127.0.0.1:18920` | only `127.0.0.1` / `localhost` are accepted |
| `MAC_NODE_TOKEN` | empty | sent as the `X-PPX-Token` header |
| `MAC_NODE_TIMEOUT_SECONDS` | `8.0` | bridge timeout |
| `GUEST_ENABLED` | `1` | guest portal switch |
| `GUEST_SECRET` | empty | HMAC key for the links; without it no link can be minted |
| `GUEST_PUBLIC_BASE_URL` | empty | externally reachable base URL (required behind a reverse proxy) |
| `GUEST_DEFAULT_TTL_HOURS` | `72` | default lifetime of a one-time link |
| `AGENT_MEETING_BASE_URL` | empty | base of the meeting-room link written into the .ics |

## 6. Built-in plugins

| plugin_id | Priority | Scope | Function |
| --- | --- | --- | --- |
| `personal_agent` | 30 | message | the 24/7 stand-in: hands inbound messages to Needle 3 for intent extraction, filters slots through the per-Bot preference rules, and produces proposals plus the `::POPOPX_ECO::` card (see section 5) |
| `webhook_relay` | 40 | message | pushes external monitoring alerts from `POST /api/v1/hooks/<bot>/<secret>` to groups/contacts, and relays inbound messages to the Bot's `webhook_url` |
| `auto_reply` | 60 | message | keyword and command auto-reply, nested command menus, scheduled announcements (rules live in the plugin config, editable in the UI) |
| `msg_router` | 65 | message | cross-chat routing: opens a ticket from a customer's direct chat into a group, replies in the group with the ticket number to hand it back |
| `llm_bridge` | 80 | message | OpenAI-compatible `/chat/completions` bridge with custom base URL, key, model, system prompt and per-session context memory |

Bus discipline: one module in `studio/plugins/` exposes `StudioPlugin` subclasses. Every
lifecycle call and dispatch is wrapped, counted and logged — a raising plugin only
increments `errors` and writes one `status="error"` log line, it can never take the gateway
down. Plugins run in ascending `priority` order and the first `handled=True` result stops
the chain. `password` fields are masked as `********` on both read and write paths.

## 7. Internationalisation

- 21 locales: the 18 iOS-aligned ones (`en, zh-Hans, zh-Hant, ja, bg, cs, de, es, fi, fr, hu,
  it, nl, pl, ru, th, tr, uk`) plus the web-only Brazilian Portuguese `pt-BR`, Korean `ko` and
  Arabic `ar`; `pt` / `pt-PT` resolve to `pt-BR`, `ko-KR` / `ar-EG` collapse to their base
  language, and any missing entry falls back to `en`.
- Arabic is the only RTL locale: the root element gets `dir="rtl"` and `lang="ar"`, and the
  other 20 locales restore `dir="ltr"`. Sidebar, drawer, badge and table spacing use logical
  properties (`margin-inline`, `padding-inline`, `inset-inline`) so the browser mirrors the
  layout without hard-coded left/right overrides.
- Technical values stay LTR: `127.0.0.1:8090`, control ports `5230–5299`, `/api/agent/orch*`
  routes, SQLite status fields, SHA-256 hashes and terminal blocks carry `dir="ltr"` plus
  `unicode-bidi:isolate` (or `direction:ltr`), so the bidi algorithm cannot reorder them under
  Arabic.
- Zero build: the structured JSON catalog is inlined at render time
  (`__I18N_CATALOG_JSON__`); the front-end dictionary engine combines `localStorage` with
  `navigator.languages`, and the top switcher changes language without a reload and persists
  the choice.
- FastAPI fills each Bot's default welcome template according to its `default_locale`,
  expanding placeholders such as `{bot_name}`.
- The `i18n` self-test group asserts that every locale's key set matches `en` exactly, that
  placeholders never drift and that no entry is empty; `/api/admin/i18n/parity` exposes the
  same check at runtime.
- The stand-in keeps its own catalog: 12 kinds × 21 locales in `agent_copy.py`, gated by
  `agent_copy.assert_catalog()` on four invariants — identical key sets, identical placeholder
  sets, numbers that come from facts rather than from the translation, and script families (a
  Han character inside a Hungarian sentence is a copy-paste accident the placeholder check cannot
  see). The guest page requires the same 21-locale parity with matching placeholders.
- A skippable browser check covers narrow screens and RTL:
  `node studio/tests/narrow_layout_check.mjs` walks all 21 locales on the console and the site at
  320px, asserting no horizontal overflow, correct `dir`/`lang`, persisted choice, and
  `direction:ltr` + `unicode-bidi:isolate` on technical fields.

## 8. Offline cold backup

```bash
cd studio
../.venv/bin/python ../official_tools/export_bot_bundle.py list
../.venv/bin/python ../official_tools/export_bot_bundle.py invite --bot <id> --qr /secure/invite.png
../.venv/bin/python ../official_tools/export_bot_bundle.py export --bot <id> --out /secure/backups
../.venv/bin/python ../official_tools/export_bot_bundle.py verify /secure/backups/<name>.botbundle
../.venv/bin/python ../official_tools/export_bot_bundle.py restore --bundle <file> --data-dir <new-dir>
```

`list` and `invite` only emit the opaque `https://popopx.chat/i/v1/<Base64URL ciphertext>`
invite link by default; `--raw` / `--raw-links` expose the raw `smp://` address and SMP
server list for advanced diagnostics.

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

## 9. Self-test

```bash
cd studio
../.venv/bin/python -m app.main --self-test                 # everything
../.venv/bin/python -m app.main --self-test --group bundle  # one group
../.venv/bin/python -m app.main --check                     # config/permissions/deps only
```

| Group | Assertions | Coverage |
| --- | --- | --- |
| `config` | 62 | environment parsing, loopback constraint, permission warnings, illegal Mac Node/reasoner endpoints |
| `database` | 110 | ledger CRUD, migrations v1..v6, soft delete, plugin config, proposal/negotiation/guest tables |
| `agent_ledger` | 139 | proposal and negotiation state persistence, audit writes, availability cache, idempotency |
| `ws_protocol` | 103 | line-protocol frames, command grammar, probe commands and error-frame wake-ups, errors and timeouts |
| `supervisor` | 86 | port allocation, isolated dirs, wrapper and first-launch profile name, reconnect backoff |
| `provisioning` | 74 | Bot creation, `/_address`, name and avatar retention, restart and cold-restore idempotency |
| `rules` | 60 | exact/prefix/regex/default matching and priority |
| `router` | 78 | keyword routing, ticket ids, templates and cooldown |
| `gateway` | 94 | inbound pipeline, plugin dispatch, update buffer |
| `plugins` | 104 | discovery, lifecycle, masking, isolation and counters (including `personal_agent`) |
| `open_api` | 119 | five methods, auth, idempotency, long polling, webhook |
| `web_admin` | 146 | console routes, CSRF/cookie, authorisation and audit |
| `i18n` | 444 | 21-locale completeness, RTL metadata, negotiation, welcome text, page injection |
| `web_live` | 60 | real ASGI lifecycle, WebSocket, cold-backup round trip, privacy QR |
| `invite_codec` | 121 | HKDF/ChaCha20 standard vectors, service-suite key and two standard vectors matched byte-for-byte, the `URI_SCHEMES` allowlist (the legacy `smp://` vector is rejected on both decode and encode), `/i/v1/` path-host checks, random nonce, no plaintext leak, tamper rejection |
| `orchestration` | 260 | in-process cross-agent dispatch gates (default-deny, hop budget, cycle guard, concurrency), timeout circuit-breaker, exception scrubbing, result aggregation and partial success, cancellation, replay and task tree, `task_stats`, plus the five projections (profile/reply.compose/router/calendar mask/workspace.summarize) exercised on a real assembled stack rather than stubs |
| `qrcode_diag` | 129 | `/qrcode` and `/qr.png` envelope separation for 404/409/401, the 2048-byte codec cap against the 1663-byte QR capacity boundary, per-call nonce, `contact_address` fallback, `box` clamping, 0700/0600 on-disk modes, and the console drawer's assembly order (clear stale state -> request -> 409 still opens the drawer) |
| `bundle` | 281 | export/verify/tamper/cross-ledger migration/idempotency, CLI `invite` and `--raw-links` |
| `eco_cards` | 89 | `::POPOPX_ECO::` card and `::CB::` receipt codec, rejection of out-of-contract fields |
| `ics` | 65 | RFC 5545 escaping, UTC instants, UID/DUMPSTAMP, durations and day-spanning events |
| `install` | 276 | script syntax and flags, dry runs, service-user primary group vs `--group` (including a stubbed real run of `create_service_user`), loopback and zero-bundling, bundled-weight manifest check, no stubs |
| `mac_node` | 201 | strict loopback and SSRF blocking, `X-PPX-Token`, status/availability/approve, timeouts and degradation |
| `a2a` | 220 | masked projection, the `FORBIDDEN_KEYS` gate, HMAC signing and replay, timezone intersection, state machine |
| `guest_portal` | 598 | token issue/verify/expiry/revocation/visit budget, concurrent claims, masked availability, the .ics gate, page escaping and RTL |
| `agent_engine` | 3978 | Needle 3 extraction and the deterministic fallback, the weight SHA-256 gate, preference rules, copy and reasoner degradation, secret hygiene |
| `agent_console` | 390 | `/api/agent/*` and `/book/*` routes, auth, panel data shapes, 21-locale strings |
| total | **8287** | 26/26 groups, 0 failures, exit code 0 |

## 10. Operations and security notes

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
- Stand-in data is not in the cold bundle: `export_bot_bundle.py` packs `cli-data/` plus the rules
  in the ledger, so `agent/preferences.json` needs its own backup. It is `0700`/`0600` like
  cli-data, but losing it means reconfiguring.
- **A guest link is the credential**: whoever holds `/book/<token>` can spend one visit slot. Share
  it over a private or encrypted channel and revoke it when done. Rotating `GUEST_SECRET`
  invalidates every outstanding link immediately — that is the intent, not a bug.
- After rotating `MAC_NODE_TOKEN`, update `.env` too, or every `approve` fails; a failing bridge
  only degrades to template copy and logs `approve_failed`, so the calendar is never silently
  corrupted, but the proposal stays `pending`.
- A2A adds no new root of trust: only an already-paired peer can write into that SMP queue, so the
  signing key is the peer session key. Negotiation audit rows carry ids, counters and reason codes
  only — never copy or titles.
- To keep the stand-in fully offline: `REASONER_ENABLED=0` makes all copy come from the 21-locale
  templates and the chain touches no network. With `MAC_NODE_ENABLED=0` the persistence and
  availability reads fall back to the masked local cache, and the card flow still works.

## 11. Licence

AGPL-3.0-only, see `LICENSE`. No `popopx-chat` binary is distributed from this repository.

Bundled third-party model asset: `studio/assets/models/needle3.cact` and its
`config-needle3.json` are Needle 3 weights from Cactus-Compute, SHA-256
`c9d915eca282ed42d1a09b143b592adb4cc6744ffe2d294adf5cfc5548170c38` (35,335,380 bytes), licensed
under **Apache-2.0**; the text is `studio/assets/models/LICENSE-needle3.txt` (SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`). Attribution as recorded in the
manifest: *Needle 3 weights (c) Cactus Compute, Apache License 2.0. Not authored or endorsed by the
POPOPX project.* The file ships with this repository and is never fetched at runtime; deleting
`studio/assets/models/needle3.cact` leaves Studio working — `needle_assets` fails the check and the
runtime uses its deterministic extractor instead (section 5.1), it simply stops using the on-device
model.
