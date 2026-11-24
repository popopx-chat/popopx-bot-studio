# POPOPX Bot Studio

自托管的 POPOPX Bot 工厂 + 零代码自动回复 + 消息路由 + 开发者 Open API + 插件网关。
一个进程管理任意多个 `popopx-cli` Bot 实例，全部通过本机回环 WebSocket 控制，
配套 Web 控制台（18 语种）与离线冷备工具。

- 许可：AGPL-3.0-only（见 `LICENSE`）
- 零二进制捆绑：本仓库不包含、不下载分发任何 `popopx-chat` 编译产物；运行期只通过
  `ws://127.0.0.1:<port>` 驱动外部 `popopx-cli` 进程，二进制由安装脚本按需拉取到
  `/usr/local/bin/popopx-cli`，或用 `--no-node-download` 完全跳过。
- 自检门禁：`python3 -m app.main --self-test` → **15 组 / 1884 条真实断言 / 0 失败 / 约 18 秒 / 退出码 0**，
  只依赖 `studio/tests/fake_popopx_cli.py`（同样讲真协议、且把 profile 存在 `bot_chat.db` 里的有状态替身），不联网、不连 SMP。

English document: [`README.en.md`](README.en.md)

---

## 1. 架构

```
浏览器控制台 / 开发者客户端
        │  http://127.0.0.1:8090        X-Studio-Token / Cookie
┌───────▼────────────────────────────────────────────────────────────┐
│ POPOPX Bot Studio (Python 3.11 + FastAPI, 单进程)                  │
│  main.py        路由、鉴权、生命周期                                            │
│  config.py      .env / 环境变量 / 权限校验（0700·0600）                          │
│  database.py    SQLite(WAL) 账本 + schema_migrations（当前 v4）                 │
│  bot_supervisor.py  每 Bot 独立数据目录 + 回环端口 + 包装脚本 + 重连退避          │
│  ws_protocol.py 与 popopx-cli 的行协议帧、/_address /_create /_send 等指令       │
│  gateway.py     入站事件 → 规则/路由/插件 → 出站发送，更新缓冲（≤500 条）         │
│  rule_engine.py 自动回复（exact / prefix / regex / default）                    │
│  router_engine.py 关键词路由与工单转接                                          │
│  plugin_manager.py 插件总线：发现、生命周期、隔离派发、脱敏配置                   │
│  open_api.py    Telegram 风格开发者 API（/getMe /sendMessage …）                │
│  i18n.py        18 语种词条、协商、欢迎语模板与完整性断言                        │
└───────┬────────────────────────────────────────────────────────────┘
        │  ws://127.0.0.1:5230..5299（严禁监听 0.0.0.0）
   popopx-cli ×N   每个 Bot 一个进程，数据目录 <data_dir>/bots/<bot_id>/cli-data
        │
   smp1..8.popopx.im（二进制内置双栈集群，可用 BOT_SMP_SERVERS 覆写）
```

隔离契约（由 `supervisor` / `config` / `install` 分组断言把关）：

| 项目 | 取值 |
| --- | --- |
| 控制台监听 | 默认 `127.0.0.1:8090`，`STUDIO_ALLOW_LAN=1` 或显式 `--lan` 才允许非回环 |
| Bot 控制端口 | `BOT_WS_PORT_BASE` 起（默认 5230，上限 5299），只绑回环 |
| Bot 数据目录 | `<STUDIO_DATA_DIR>/bots/<bot_id>/cli-data`，目录 `0700`、文件 `0600` |
| 启动包装 | `run-cli.sh`（`#!/bin/sh` + 逐 token `shlex.quote`，防 systemd/launchd 剥引号拆词），保留 `0755`；仅当 cli-data 为空库时额外带 `--user-display-name <名片>`，避免无 TTY 卡在交互提问 |
| Bot 名片 | 开通与重启都先 `/user` → `/users` → `/_user <id>` 复用既有 profile，绝不重复 `/_create user` |
| SMP 集群 | 继承二进制内置 `smp1..8.popopx.im`，`BOT_SMP_SERVERS` 可覆写 |
| 凭据 | `STUDIO_ADMIN_TOKEN` 只从 `.env`（0600）或环境读取，绝不写进 plist/unit 明文 |

## 2. 目录

```
install_ubuntu22.sh        Ubuntu 22.04 安装器（native=系统用户+/opt+systemd / dev=只建 venv）
install_macos.sh           macOS 安装器（LaunchDaemon im.popopx.botstudio）
start_macos.sh             macOS 日常启动器（自动 venv + 随机令牌 + --check/--self-test）
docker-compose.yml         容器编排（只发布 127.0.0.1，cap_drop + no-new-privileges）
.env.example               11 个键的配置模板
official_tools/
  export_bot_bundle.py     离线冷备：export / list / verify / restore（明文与 AES-256-GCM 包）
studio/
  app/                     引擎源码（见上图模块分工）
  plugins/                 四个内置插件
  static/index.html        Web 控制台（零构建单页，18 语种）
  site → 顶层 site/        产品站与教程
  tests/fake_popopx_cli.py 自检用的协议替身
  requirements.txt         依赖锁定
```

## 3. 安装

### macOS

```bash
./install_macos.sh --check          # 只诊断，不改动
./install_macos.sh --dry-run        # 打印计划动作与 plist 全文（plutil -lint 已验证）
sudo ./install_macos.sh             # 安装到 /opt/popopx-bot-studio 并注册 LaunchDaemon
```

日常开发可直接用启动器（免 root，自动建 `.venv`、按需装依赖、生成随机令牌写入 `.env` 0600）：

```bash
./start_macos.sh                    # 127.0.0.1:8090
./start_macos.sh --check            # 配置/权限/依赖校验
./start_macos.sh --self-test        # 全量自检门禁
```

### Ubuntu 22.04

```bash
sudo ./install_ubuntu22.sh --mode native --check
sudo ./install_ubuntu22.sh --mode native --dry-run
sudo ./install_ubuntu22.sh --mode native
systemctl status popopx-bot-studio
```

`native` 模式创建 `popopx-studio` 专用系统用户、Python 3.11 venv 与
`/etc/systemd/system/popopx-bot-studio.service`（`Environment=STUDIO_HOST=127.0.0.1`）。
服务用户的主组一律取 `--group`（默认与 `--user` 同名）：`groupadd --system --force` 预建组，
`useradd --system --gid <group>` 建用户；用户已存在但主组不符时用 `usermod -g` 纠正，
一致时不动。这里不用 `useradd -U/--user-group`——它会另建一个与用户名同名的组做主组，
`--group` 被绕开后，单元的 `Group=` 与数据目录属组就成了该用户不属于的组，
而 systemd 只要组存在就不报错，错配完全是静默的。`--check` 会复核主组、`/etc/group`
里的组存在性以及 `STUDIO_DATA_DIR` 属组，并在不符时给出纠正命令。
`dev` 模式只做 venv + `.env`，非 root 可跑。两个安装器都支持：

| 旗标 | 作用 |
| --- | --- |
| `--dry-run` / `-n` | 打印全部计划动作，不写文件、不联网下载 |
| `--check` | 只诊断布局、python、依赖、`.env` 权限、CLI、监听地址、服务单元，以及服务用户主组与数据目录属组是否与 `--group` 一致 |
| `--uninstall` | 摘除服务（保留 `.env`、数据目录与 CLI） |
| `--no-node-download` | 不下载 `popopx-cli`；缺二进制时 Studio 离线降级运行 |
| `--lan`（macOS） | 显式绑定 `0.0.0.0` 并置 `STUDIO_ALLOW_LAN=1` |

按需下载逻辑：本机没有 `/usr/local/bin/popopx-cli` 且未传 `--no-node-download` 时，
探测 OS 与 CPU 架构，从 `popopx-chat/popopx-chat` 的 GitHub Releases 取最新资产，
校验 SHA-256 后安装到 `/usr/local/bin/popopx-cli` 并 `chmod 755`。

### Docker

```bash
cp .env.example .env && chmod 600 .env      # 填入 STUDIO_ADMIN_TOKEN
docker compose up -d
```

Compose 只在宿主机回环发布端口（`127.0.0.1:${STUDIO_HOST_PORT:-8090}:8090`），
Bot 控制端口不对外发布，源码卷只读挂载，状态存命名卷 `studio-data`。

## 4. Web 控制台与 API

控制台 `http://127.0.0.1:8090/`：Bot 工厂（创建/启停/冷备）、自动回复规则、消息路由、
插件配置、消息日志、Open API 文档页。管理令牌来自 `STUDIO_ADMIN_TOKEN`，
浏览器侧走 Cookie（`studio_token`）或 `X-Studio-Token` 头。

管理 API 前缀 `/api/admin`：`session` `overview` `bots` `bots/{id}`（含 `qrcode` `qr.png`
`send` `contacts` `groups` `rules` `routing` `start` `stop` `restart`）`rules/{id}`
`rules/preview` `routing/{id}` `routing/preview` `plugins` `plugins/{id}` `logs` `updates`
`backup/export` `backup/import` `backups` `config` `i18n/parity`。

开发者 API（Telegram 风格，前缀 `/api/v1`，裸路径与 `/bot<TOKEN>/` 两种挂载各一份）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/getMe` | Bot 身份、地址、在线状态 |
| POST | `/sendMessage` | 单聊/群聊发送，支持引用回复与幂等 `message_id` |
| POST | `/broadcastGroup` | 多群广播，带节流与失败清单 |
| POST | `/setWebhook` | 注册入站消息回调（仅 https 或回环 http） |
| GET | `/getUpdates` | 长轮询读取缓冲更新（`offset` `limit≤500` `timeout≤30s`） |

入站 Webhook 派发：`POST /api/v1/hooks/<bot_id>/<secret>`，由声明该 `secret` 的插件认领。

## 5. 内置插件

| plugin_id | 优先级 | 作用域 | 功能 |
| --- | --- | --- | --- |
| `webhook_relay` | 40 | message | 外部监控 `POST /api/v1/hooks/<bot>/<secret>` 告警推送到群/联系人；入站消息回调 Bot 的 `webhook_url` |
| `auto_reply` | 60 | message | 关键词与指令自动回复、多级指令菜单、定时公告群发（规则存插件 config，UI 可编辑） |
| `msg_router` | 65 | message | 跨会话/跨群路由：客户单聊按关键词建工单转群，群内以工单号回帖自动转回客户 |
| `llm_bridge` | 80 | message | OpenAI 兼容 `/chat/completions` 桥接，自定义 Base URL / Key / Model / System Prompt 与会话上下文记忆 |

插件总线纪律：一个模块一个目录（`studio/plugins/*.py`）暴露 `StudioPlugin` 子类；
每个生命周期调用与派发都被包裹、计数、记录，插件抛异常只累加 `errors` 并写一条
`status="error"` 日志，绝不让网关崩掉；按 `priority` 升序派发，第一个
`handled=True` 的结果终止链路；密钥字段（`password`）在读写两侧都以 `********` 掩码。

## 6. 国际化

- 18 个 iOS 对齐语种：`en, zh-Hans, zh-Hant, ja, bg, cs, de, es, fi, fr, hu, it, nl, pl, ru, th, tr, uk`，
  缺失词条一律回退 `en`。
- 零构建：结构化 JSON 目录在渲染时内联进页面（`__I18N_CATALOG_JSON__`），前端字典引擎
  结合 `localStorage` 与 `navigator.languages` 检测语种，顶部切换器免刷新换语言。
- 后端按 Bot 的 `default_locale` 填充默认欢迎语模板（FastAPI 渲染），
  占位符 `{bot_name}` 等在此展开。
- `--self-test` 的 `i18n` 分组断言每个语种与 `en` 的键集合 100% 对齐、占位符无漂移、
  无空词条，并提供 `/api/admin/i18n/parity` 在线自检。

## 7. 离线冷备

```bash
cd studio && ../.venv/bin/python ../official_tools/export_bot_bundle.py list
../.venv/bin/python ../official_tools/export_bot_bundle.py export --bot <id> --out /secure/backups
../.venv/bin/python ../official_tools/export_bot_bundle.py verify /secure/backups/<name>.botbundle
../.venv/bin/python ../official_tools/export_bot_bundle.py restore --bundle <包> --data-dir <新目录>
```

产物 `.botbundle`（gzip tar）+ 边车 `<name>.botbundle.json`；加 `--passphrase`（或
`--passphrase-stdin`）得到 AES-256-GCM 加密包（魔数 `PBSB`）。manifest 的逐成员
SHA-256 是自指的，只有边车的 `payload_sha256` 能锚定它，因此**缺少边车即校验失败**。
还原是幂等的：回复规则按 `(bot_id, trigger_type, pattern)` upsert，路由规则按内容签名去重，
同址 Bot 复用既有行；`--replace-rules` 表示“清掉目标多余规则”。还原后的 `cli-data`
文件一律收紧到 `0600`（`run-cli.sh` 保留可执行位）。

退出码：`0` 成功 / `1` 运行期错误 / `2` 用法错误 / `3` Bot 不存在 / `4` Bot 已删除 /
`5` 目标目录不可写 / `6` 包损坏或校验失败 / `7` 口令问题 / `8` 账本写入失败。

## 8. 自检

```bash
cd studio
../.venv/bin/python -m app.main --self-test                 # 全量
../.venv/bin/python -m app.main --self-test --group bundle  # 单组
../.venv/bin/python -m app.main --check                     # 只看配置/权限/依赖
```

| 分组 | 断言 | 覆盖 |
| --- | --- | --- |
| `config` | 62 | 环境解析、回环约束、权限告警 |
| `database` | 110 | 账本 CRUD、迁移、软删除、插件配置 |
| `ws_protocol` | 103 | 行协议帧、指令语法、探活命令与错误帧唤醒、异常与超时 |
| `supervisor` | 86 | 端口分配、隔离目录、包装脚本与首启名片、重连退避 |
| `provisioning` | 66 | 建 Bot、`/_address`、名称与头像保留、复启与冷备复活幂等 |
| `rules` | 60 | exact/prefix/regex/default 匹配与优先级 |
| `router` | 78 | 关键词路由、工单号、模板与冷却 |
| `gateway` | 94 | 入站管线、插件派发、更新缓冲 |
| `plugins` | 94 | 发现、生命周期、掩码、隔离与计数 |
| `open_api` | 119 | 五个方法、鉴权、幂等、长轮询、webhook |
| `web_admin` | 146 | 控制台路由、CSRF/Cookie、越权与审计 |
| `i18n` | 320 | 18 语种完整性、协商、欢迎语、页面注入 |
| `web_live` | 55 | 真实 ASGI 生命周期、WebSocket、冷备往返 |
| `bundle` | 250 | 冷备导出/校验/篡改/跨账本迁移/幂等 |
| `install` | 241 | 脚本语法与旗标、干跑、服务用户主组与 `--group` 一致性（含真跑 `create_service_user` 的无桩探针）、回环与零二进制捆绑、无桩残留 |

## 9. 运维与安全注意

- 控制台口令是唯一门槛，请始终只绑回环或用反代加 TLS；`--lan` 是可显式审计的决定。
- `.env` 必须 `0600`，`STUDIO_DATA_DIR` 必须 `0700`；`--check` 与启动时都会告警。
- 软删除的 Bot 仍占用其名称与控制端口，详情接口返回 `status:"deleted"` 而非 404。
- 备份目录请自行加密与限权；冷备包内含 Bot 身份材料。
- 严禁使用不存在的 `/address`、`/auto_accept` 指令；地址与接受隐身一律走
  `/_address 1`、`/_address_settings 1 {...}`，且 `acceptIncognito` 保持 `false`
  以保留 Bot 自身名称与头像。
- 名片归属只以 `/users` 列表裁定，不采信错误文案：`/user` 在无活动 profile 时可能回
  `noActiveUser` 错误帧，也可能回 `activeUser` 且 `user: null`，两种形态都必须退到
  `/users` + `/_user <id>` 复用既有名片。库里已有 profile 时绝不发 `/_create user`
  （`CreateActiveUser` 会回 `userExists`），改名也不会静默覆盖既有名片。
- 冷备还原后的 cli-data 带的是原 profile，Studio 重启（`boot()`）与 Web 端重启同一个 Bot
  都必须直接复用；`--user-display-name` 只在空库首启注入，常驻会让「改名」变成「CLI 起不来」。

## 10. 许可

AGPL-3.0-only，详见 `LICENSE`。本仓库不分发任何 `popopx-chat` 二进制。
