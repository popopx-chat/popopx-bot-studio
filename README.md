# POPOPX Bot Studio

自托管的 POPOPX Bot 工厂 + 零代码自动回复 + 消息路由 + 开发者 Open API + 插件网关。
一个进程管理任意多个 `popopx-cli` Bot 实例，全部通过本机回环 WebSocket 控制，
配套 Web 控制台（18 语种）与离线冷备工具。

从这一版起，每个 Bot 还能开一个 **24 小时全天候替身**：端侧小模型抽意图、大模型只写话术、
日历永远等主人点确认；两个替身之间走**只交换掩码时段**的端到端加密 A2A 协商，
外部访客则用一条零安装、零注册、不留邮箱的一次性网页链接约时间。

- 许可：代码 AGPL-3.0-only（见 `LICENSE`）；内置的 Needle 3 权重是第三方 Apache-2.0 资产，
  许可原文与署名见 `studio/assets/models/`（第 11 节）。
- 零二进制捆绑：本仓库不包含、不下载分发任何 `popopx-chat` 编译产物；运行期只通过
  `ws://127.0.0.1:<port>` 驱动外部 `popopx-cli` 进程，二进制由安装脚本按需拉取到
  `/usr/local/bin/popopx-cli`，或用 `--no-node-download` 完全跳过。
- 模型零下载：`needle3.cact`（33.7 MiB，<50 MB）随仓库内置，加载前做 SHA-256 完整性校验，
  部署启动后即刻可用；没有 C 运行时或 SDK 时自动退回本仓自带的确定性抽取器（第 5 节）。
- 自检门禁：`python3 -m app.main --self-test` → **24 组 / 7300 条真实断言 / 0 失败 / 约 19 秒 / 退出码 0**，
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
│  database.py    SQLite(WAL) 账本 + schema_migrations（当前 v5）                 │
│  bot_supervisor.py  每 Bot 独立数据目录 + 回环端口 + 包装脚本 + 重连退避          │
│  ws_protocol.py 与 popopx-cli 的行协议帧、/_address /_create /_send 等指令       │
│  gateway.py     入站事件 → 规则/路由/插件 → 出站发送，更新缓冲（≤500 条）         │
│  rule_engine.py 自动回复（exact / prefix / regex / default）                    │
│  router_engine.py 关键词路由与工单转接                                          │
│  plugin_manager.py 插件总线：发现、生命周期、隔离派发、脱敏配置                   │
│  open_api.py    Telegram 风格开发者 API（/getMe /sendMessage …）                │
│  i18n.py        18 语种词条、协商、欢迎语模板与完整性断言                        │
│ ── 替身机器人 ──────────────────────────────────────────────────────────────  │
│  agent_runtime.py   编排：意图→偏好过滤→提案→卡片→确认→回执，全程写审计         │
│  needle3_runtime.py 端侧小引擎（只抽取 5 个工具调用）+ 确定性回退抽取器          │
│  needle_assets.py   内置权重的发现与 SHA-256 门禁，运行期零下载                 │
│  agent_preferences.py 每 Bot 的偏好规则：工作时间/缓冲/屏蔽段/关键词/协商策略   │
│  agent_copy.py      12 类话术 × 18 语种目录 + 占位符/文字族完整性门禁           │
│  reasoner_bridge.py 大模型只写话术（Ollama / OpenAI 兼容，严格回环或 https）     │
│  mac_node_bridge.py 本机 Mac Node 桥：状态、忙闲读取、approve 落库              │
│  eco_cards.py       ::POPOPX_ECO:: 确认卡片与 ::CB:: 回执的编解码               │
│  a2a.py             通道 A：两个替身之间的掩码时段协商帧                        │
│  guest_portal.py    通道 B：HMAC 一次性链接、脱敏空档、.ics 领取                │
│  ics.py             RFC 5545 日历条目生成（转义、UTC 时刻、 METHOD/UID）        │
│  agent_admin.py     /api/agent 管理路由 + /book/<token> 访客页                  │
└───────┬───────────────────────┬─────────────────────────────────────┘
        │  ws://127.0.0.1:5230..5299（严禁监听 0.0.0.0）
   popopx-cli ×N   每个 Bot 一个进程，数据目录 <data_dir>/bots/<bot_id>/cli-data
        │
   smp1..8.popopx.im（二进制内置双栈集群，可用 BOT_SMP_SERVERS 覆写）
        ▲ 通道 A：::POPOPX_A2A:: 帧（对端会话密钥签名，只带掩码时段）
        │
   http://127.0.0.1:18920   Mac Node（通道本机侧）：X-PPX-Token、只此回环、非回环直接拒
   http(s)://<studio>/book/<one_time_token>   通道 B：访客页，无会话、无 Cookie、无外链
```

隔离契约（由 `supervisor` / `config` / `install` / `mac_node` / `guest_portal` / `a2a` 分组断言把关）：

| 项目 | 取值 |
| --- | --- |
| 控制台监听 | 默认 `127.0.0.1:8090`，`STUDIO_ALLOW_LAN=1` 或显式 `--lan` 才允许非回环 |
| Bot 控制端口 | `BOT_WS_PORT_BASE` 起（默认 5230，上限 5299），只绑回环 |
| Bot 数据目录 | `<STUDIO_DATA_DIR>/bots/<bot_id>/cli-data`，目录 `0700`、文件 `0600` |
| 替身偏好目录 | `<STUDIO_DATA_DIR>/bots/<bot_id>/agent/preferences.json`，同 `0700`/`0600`，每 Bot 一份互不可见 |
| Mac Node 桥 | 只允许 `http://127.0.0.1:18920` 或 `http://localhost:18920`，非回环在 `load_settings()` 阶段直接拒绝（防 SSRF），请求带 `X-PPX-Token` |
| 大模型话术端点 | 明文 `http` 只允许回环；远端必须 `https`；URL 里不许内嵌用户名/密码；密钥只从 `.env` 读并以 `********` 掩码回显 |
| 访客链接 | `<base>/book/<token>`，令牌是自校验 HMAC 签名（`{v,lid,iat,exp,mus,dur}`），服务端不建会话、不发 Cookie |
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
.env.example               26 个键的配置模板（含替身机器人、Mac Node、访客门户、大模型话术端点）
official_tools/
  export_bot_bundle.py     离线冷备：export / list / verify / restore / invite（明文与 AES-256-GCM 包）
  verify_needle_assets.py  内置 Needle 3 权重的 SHA-256 清单校验器（安装与 --check 都会跑）
studio/
  app/                     引擎源码（见上图模块分工）
  assets/models/           内置模型资产：needle3.cact + 清单 + config + 许可原文 + 说明
  plugins/                 五个内置插件
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

模型权重不参与下载：两个安装器都会用 `official_tools/verify_needle_assets.py` 复核仓库内置的
`studio/assets/models/needle3.*`（清单、字节数、逐文件 SHA-256、许可文本齐全）。`--check` 只报
问题不中断，正式安装时校验不过直接终止——手改清单或权重被截断，比没有端侧模型更糟。

### Docker

```bash
cp .env.example .env && chmod 600 .env      # 填入 STUDIO_ADMIN_TOKEN
docker compose up -d
```

Compose 只在宿主机回环发布端口（`127.0.0.1:${STUDIO_HOST_PORT:-8090}:8090`），
Bot 控制端口不对外发布，源码卷只读挂载，状态存命名卷 `studio-data`。

## 4. Web 控制台与 API

控制台 `http://127.0.0.1:8090/`：Bot 工厂（创建/启停/冷备）、自动回复规则、消息路由、
插件配置、消息日志、Open API 文档页，外加两块新面板——**替身机器人**（抽取引擎与端侧权重状态、
「试一句」抽取器、五个工具槽位、每 Bot 偏好规则编辑器、对端配对、待确认提案、协商启动、
全流程审计日志）与**访客链接**（一次性链接生成与列表、撤销、按需取回完整链接、访问/领取计数）。
管理令牌来自 `STUDIO_ADMIN_TOKEN`，
浏览器侧走 Cookie（`studio_token`）或 `X-Studio-Token` 头。

管理 API 前缀 `/api/admin`：`session` `overview` `bots` `bots/{id}`（含 `qrcode` `qr.png`
`send` `contacts` `groups` `rules` `routing` `start` `stop` `restart`）`rules/{id}`
`rules/preview` `routing/{id}` `routing/preview` `plugins` `plugins/{id}` `logs` `updates`
`backup/export` `backup/import` `backups` `config` `i18n/parity`。
`qrcode` 与 `qr.png` 默认返回 `https://popopx.chat/i/v1/<Base64URL密文>` 隐私封装邀请链接
（HKDF-SHA256 + ChaCha20-Poly1305，隐藏 `smpN.popopx.im` 节点域名；密钥参数
IKM/salt/info/AAD 与 `popopx-service-suite` 的 `opaque_invite_codec.py @ a6c1632`
逐字节一致，客户端只维护一套解密密钥），二维码面板底部的
折叠区与 `qr.png?raw=1` 才用于原始 `smp://` 地址的高级诊断。

替身机器人管理 API 前缀 `/api/agent`（同样要 `require_admin`）：
`summary` `engine`（GET 读状态 / POST 切换引擎）、`extract`（试一句）、
`prefs/{bot_id}`（GET/POST）与 `prefs/{bot_id}/reset`、`peers`（GET/POST）与 `peers/remove`、
`proposals` 与 `proposals/{id}/decision`、`negotiations` 与 `negotiate`、`audit`、
`guest/links`（GET/POST）、`guest/links/{id}/revoke`、`guest/links/{id}/url`（一次性取回完整链接，
带 nonce 防重放）、`node`（GET）与 `node/probe`（POST）。

访客通道（无需管理令牌，令牌自身即凭据）：`GET /book`、`GET /book/<token>`、
`POST /book/<token>`（提交时间偏好）、`GET /book/<token>/invite.ics`（主人确认后才发得出 .ics）。

开发者 API（Telegram 风格，前缀 `/api/v1`，裸路径与 `/bot<TOKEN>/` 两种挂载各一份）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/getMe` | Bot 身份、地址、在线状态 |
| POST | `/sendMessage` | 单聊/群聊发送，支持引用回复与幂等 `message_id` |
| POST | `/broadcastGroup` | 多群广播，带节流与失败清单 |
| POST | `/setWebhook` | 注册入站消息回调（仅 https 或回环 http） |
| GET | `/getUpdates` | 长轮询读取缓冲更新（`offset` `limit≤500` `timeout≤30s`） |

入站 Webhook 派发：`POST /api/v1/hooks/<bot_id>/<secret>`，由声明该 `secret` 的插件认领。

## 5. 替身机器人（24 小时全天候）

一条消息进来分成两半：**端侧小模型只抽意图，大模型只写话术**，日历改动一律等主人点确认。

### 5.1 抽取引擎与双引擎路由

- `needle3_runtime.py` 加载 `Cactus-Compute/needle3`（`needle3.cact`，33.7 MiB，1.21 亿参数，
  engine 3.1.0）在毫秒内产出五个工具调用之一：`calendar.get_availability`、
  `calendar.propose_create`、`calendar.propose_reschedule`、`calendar.propose_cancel`、
  `workspace.summarize_file`。五个工具函数全是**只读回声桩**（`TOOL_STUBS`）：只记参数，
  绝不写日历、绝不读文件正文。
- 权重经 `needle_assets.ensure_weights()` 做 SHA-256 门禁后从仓库内置路径加载，**运行期不下载任何模型**；
  清单与重抓步骤在 `studio/assets/models/needle3.manifest.json`，独立校验：
  `python3 official_tools/verify_needle_assets.py`（`--check` 与两个安装器都会跑，安装时不通过即终止）。
- 没有 C 运行时 / SDK 未装 / 校验失败 / 加载抛错，一律降级到本模块自带的**确定性抽取器**：
  中英双语的约会议、问空档、改期、取消、看纪要句式，加相对日期（明天、周四、next week）、
  钟点（下午三点、3pm、15:00）、时长（半小时、45 min）与时区提示，都解析成结构化参数；
  时钟通过 `hints={"now": …}` 注入，因此自检结果与运行当天无关。降级原因、引擎真身、抽取计数
  都在 `status()` 里，后台一眼能看出这台机器到底有没有在用端侧模型。抽取永不向调用方抛异常。
  本机口径（回退路径、2400 条混合句子连测）中位数 0.05 ms/条，即 `extract()` 返回的 `latency_ms`。
- `reasoner_bridge.py` 负责话术：Ollama 原生（`/api/generate`、`/api/chat`）与 OpenAI 兼容
  （`/v1/chat/completions`）两种方言按 URL 自动归一。系统提示词写死“不得新增、修改或猜测任何
  时间、日期、时区、时长、人名或地点；不得声称已经写入日历”。任何失败（开关未开、地址非法、
  超时、非 200、响应没有话术字段）都退回 `agent_copy` 模板并记下原因，非 200 同样计入 `errors`；
  外发的错误串一律过 `redact()`——键名形态（`Authorization: Bearer …`、`"api_key": "…"`、
  `REASONER_API_KEY='…'`、裸 `key=…`）与令牌本体形态（`sk-`/`ghp_`/`xoxb-` 等）都洗。
  明文 `http` 只允许回环，远端必须 `https`，URL 内嵌用户名/密码直接拒绝。
- 忙闲与落库结果来自 Mac Node；Node 不可用时读本地掩码缓存 `calendar_cache`，缓存只存时段，不存标题。

### 5.2 每 Bot 偏好规则引擎

规则存在 `<STUDIO_DATA_DIR>/bots/<bot_id>/agent/preferences.json`（目录 `0700`、文件 `0600`，
每 Bot 一份、互不可见），`version` 与代码不一致即拒绝并回退默认，回退会留一条恢复记录。
可编辑段落：`working_hours`（工作日与上下班，`end` 允许 `24:00`）、`buffers`（会前/会后缓冲，
缓冲只用于夹工作时间边界）、`blocked_periods`（固定屏蔽段，按候选时段本身判定）、
`keywords.boost/block` 与 `match_fields`、`meeting`（默认时长、最大时长、最小间隔）、
`negotiation`、`copy`。硬约束与上限：`require_owner_approval` 必须为 `true`——日程最终确认
只能由主人亲自点，规则改不了；关键词每侧最多 40 条，屏蔽段 id 最长 24 字符，时长与缓冲有上下界。
每条被筛掉的候选都带回可读理由（「周四不是工作日」「含缓冲后超出工作时间 09:00-18:00
（需 10:00-11:00±15/10 分钟）」「命中固定屏蔽时段「午休」」「时段已过去」「跨天的候选时段需要主人另行确认」），
理由进审计日志而不是被吞掉。

### 5.3 确认卡片与本机落库

移动/桌面端渲染 `::POPOPX_ECO::` 动态确认卡片（编码与回执规则见 `eco_cards.py`，
与 `::CB::` 上行帧同一套客户端约束）→ 主人点「确认」→ 编排层调用
`mac_node_bridge.MacNodeBridge.approve`（严格回环 `http://127.0.0.1:18920` 或
`http://localhost:18920`，携带 `X-PPX-Token`，非回环地址在 `load_settings()` 阶段就拒）→
提案转 `approved` 落库 → 双方各得一份 `ics.py` 生成的 RFC 5545 邀请。复启与冷备复活都是幂等的。

### 5.4 通道 A：双边加密 A2A 协商

帧格式 `::POPOPX_A2A::<base64url(json)>.<base64url(hmac-sha256)>`，签名用**对端会话密钥**
（SMP 通道本来就有），校验走 `hmac.compare_digest`，再叠版本号、时间窗与 nonce 重放防护。
「只交换掩码候选时段」不靠约定，靠三道独立的闸：`mask_slots` 白名单投影重建时段对象
（只可能留下 `start/end/tz/free/ref`，上游塞进来的 `title` 活不过这一行）；`encode_frame`
在签名之前递归检查帧体，命中 `FORBIDDEN_KEYS` 任何键名直接拒发；`intersect_slots` 收发都是
绝对 epoch，墙上时间只作为文本呈现，跨时区与夏令时因此不可能算错。状态机
`open → converged/rejected/expired/aborted` 落在 `a2a_negotiations`，每次迁移写一条审计，
detail 只允许出现 id、计数和原因码；`converged` 之后**只产出一条 `pending` 提案，日历一个字节都不写**，
改期是显式 `counter` 重开（旧提案置 `superseded`），`expired/rejected/aborted` 一律拒绝复活。

### 5.5 通道 B：零安装访客预约门户

主人铸造 `<base>/book/<one_time_token>`：令牌是自校验 HMAC 签名，内容只有
`{v,lid,iat,exp,mus,dur}`——主人身份与日历内容一个字节都不进令牌。访客打开时按
「签名 → 版本 → 过期 → 撤销 → 次数 → 领取」顺序校验，访问计数在 `threading.Lock` 内
一次性 check-and-set（否则两个并发协程会同时穿过预算判断）；预算取
`min(令牌 mus, 库里 max_uses)`，事后把库里的次数改大不能让已用完的单次令牌复活，管理员收紧立即生效。
访客写下时间偏好后，门户向注入的空档来源要**脱敏后的空闲时段**（拿不到就诚实说
「暂时无法确认空档」，绝不编造），收敛到唯一时段即写 `source="guest"` 的 `pending` 提案并把
`::POPOPX_ECO::` 卡片推给主人；主人确认之前，`GET /book/<token>/invite.ics` 拿不到 .ics。
`VEVENT` 只带会议房间链接或「POPOPX Chat 通话」说明，绝不含主人真实地址、真名、邮箱或完整日程。
页面是自包含 HTML：不建会话、不发 Cookie、无 `<script>`、无外链、表单 `action=""`、访客输入一律
HTML 转义，18 语种文案齐全且占位符完全一致。

### 5.6 新增配置键

| 键 | 默认 | 作用 |
| --- | --- | --- |
| `AGENT_ENABLED` | `1` | 替身机器人总开关（关闭后消息只走原有规则/路由/插件链） |
| `REASONER_ENABLED` | `0` | 是否让大模型写话术；关闭即全部走 `agent_copy` 模板 |
| `REASONER_BASE_URL` | 空 | 推理端点；明文 http 只允许回环，远端必须 https |
| `REASONER_MODEL` | 空 | 模型名（Ollama 方言取 `model`，OpenAI 方言同） |
| `REASONER_API_KEY` | 空 | 只进请求头，读写两侧掩码，绝不进日志与提示词 |
| `REASONER_TIMEOUT_SECONDS` | `20.0` | 单次话术请求超时 |
| `MAC_NODE_ENABLED` | `0` | 是否启用 Mac Node 桥（忙闲读取与确认落库） |
| `MAC_NODE_URL` | `http://127.0.0.1:18920` | 只接受 `127.0.0.1` / `localhost` 回环 |
| `MAC_NODE_TOKEN` | 空 | 以 `X-PPX-Token` 头携带 |
| `MAC_NODE_TIMEOUT_SECONDS` | `8.0` | 桥接超时 |
| `GUEST_ENABLED` | `1` | 访客门户开关 |
| `GUEST_SECRET` | 空 | 令牌 HMAC 密钥；缺失时无法铸造新链接 |
| `GUEST_PUBLIC_BASE_URL` | 空 | 对外可访问的基址（反代场景必填） |
| `GUEST_DEFAULT_TTL_HOURS` | `72` | 一次性链接默认有效期 |
| `AGENT_MEETING_BASE_URL` | 空 | 写进 .ics 的会议房间链接基址 |

## 6. 内置插件

| plugin_id | 优先级 | 作用域 | 功能 |
| --- | --- | --- | --- |
| `personal_agent` | 30 | message | 24 小时替身：把入站消息交给 Needle 3 抽取意图，按每 Bot 偏好规则筛时段，产提案与 `::POPOPX_ECO::` 确认卡片（详见第 5 节） |
| `webhook_relay` | 40 | message | 外部监控 `POST /api/v1/hooks/<bot>/<secret>` 告警推送到群/联系人；入站消息回调 Bot 的 `webhook_url` |
| `auto_reply` | 60 | message | 关键词与指令自动回复、多级指令菜单、定时公告群发（规则存插件 config，UI 可编辑） |
| `msg_router` | 65 | message | 跨会话/跨群路由：客户单聊按关键词建工单转群，群内以工单号回帖自动转回客户 |
| `llm_bridge` | 80 | message | OpenAI 兼容 `/chat/completions` 桥接，自定义 Base URL / Key / Model / System Prompt 与会话上下文记忆 |

插件总线纪律：一个模块一个目录（`studio/plugins/*.py`）暴露 `StudioPlugin` 子类；
每个生命周期调用与派发都被包裹、计数、记录，插件抛异常只累加 `errors` 并写一条
`status="error"` 日志，绝不让网关崩掉；按 `priority` 升序派发，第一个
`handled=True` 的结果终止链路；密钥字段（`password`）在读写两侧都以 `********` 掩码。

## 7. 国际化

- 18 个 iOS 对齐语种：`en, zh-Hans, zh-Hant, ja, bg, cs, de, es, fi, fr, hu, it, nl, pl, ru, th, tr, uk`，
  缺失词条一律回退 `en`。
- 零构建：结构化 JSON 目录在渲染时内联进页面（`__I18N_CATALOG_JSON__`），前端字典引擎
  结合 `localStorage` 与 `navigator.languages` 检测语种，顶部切换器免刷新换语言。
- 后端按 Bot 的 `default_locale` 填充默认欢迎语模板（FastAPI 渲染），
  占位符 `{bot_name}` 等在此展开。
- `--self-test` 的 `i18n` 分组断言每个语种与 `en` 的键集合 100% 对齐、占位符无漂移、
  无空词条，并提供 `/api/admin/i18n/parity` 在线自检。
- 替身机器人另有一套独立话术目录：`agent_copy.py` 的 12 类话术 × 18 语种，键集、占位符集合、
  数字（时间窗/天数/时长都来自事实而非译文）与文字族（拉丁句里蹦出汉字即判定串语种）四项
  全部由 `agent_copy.assert_catalog()` 把门；访客页文案同样要求 18 语种齐全且占位符完全一致。

## 8. 离线冷备

```bash
cd studio && ../.venv/bin/python ../official_tools/export_bot_bundle.py list
../.venv/bin/python ../official_tools/export_bot_bundle.py invite --bot <id> --qr /secure/invite.png
../.venv/bin/python ../official_tools/export_bot_bundle.py export --bot <id> --out /secure/backups
../.venv/bin/python ../official_tools/export_bot_bundle.py verify /secure/backups/<name>.botbundle
../.venv/bin/python ../official_tools/export_bot_bundle.py restore --bundle <包> --data-dir <新目录>
```

`list` 与 `invite` 默认只输出 `https://popopx.chat/i/v1/<Base64URL密文>` 隐私封装邀请链接，
另有 `--raw` / `--raw-links` 供管理员查看原始 `smp://` 地址与 SMP 节点列表。

产物 `.botbundle`（gzip tar）+ 边车 `<name>.botbundle.json`；加 `--passphrase`（或
`--passphrase-stdin`）得到 AES-256-GCM 加密包（魔数 `PBSB`）。manifest 的逐成员
SHA-256 是自指的，只有边车的 `payload_sha256` 能锚定它，因此**缺少边车即校验失败**。
还原是幂等的：回复规则按 `(bot_id, trigger_type, pattern)` upsert，路由规则按内容签名去重，
同址 Bot 复用既有行；`--replace-rules` 表示“清掉目标多余规则”。还原后的 `cli-data`
文件一律收紧到 `0600`（`run-cli.sh` 保留可执行位）。

退出码：`0` 成功 / `1` 运行期错误 / `2` 用法错误 / `3` Bot 不存在 / `4` Bot 已删除 /
`5` 目标目录不可写 / `6` 包损坏或校验失败 / `7` 口令问题 / `8` 账本写入失败。

## 9. 自检

```bash
cd studio
../.venv/bin/python -m app.main --self-test                 # 全量
../.venv/bin/python -m app.main --self-test --group bundle  # 单组
../.venv/bin/python -m app.main --check                     # 只看配置/权限/依赖
```

| 分组 | 断言 | 覆盖 |
| --- | --- | --- |
| `config` | 62 | 环境解析、回环约束、权限告警、Mac Node/话术端点非法值拒绝 |
| `database` | 110 | 账本 CRUD、v1..v5 迁移、软删除、插件配置、提案/协商/访客表 |
| `agent_ledger` | 139 | 提案与协商状态机持久化、审计写入、忙闲缓存、幂等 |
| `ws_protocol` | 103 | 行协议帧、指令语法、探活命令与错误帧唤醒、异常与超时 |
| `supervisor` | 86 | 端口分配、隔离目录、包装脚本与首启名片、重连退避 |
| `provisioning` | 74 | 建 Bot、`/_address`、名称与头像保留、复启与冷备复活幂等 |
| `rules` | 60 | exact/prefix/regex/default 匹配与优先级 |
| `router` | 78 | 关键词路由、工单号、模板与冷却 |
| `gateway` | 94 | 入站管线、插件派发、更新缓冲 |
| `plugins` | 104 | 发现、生命周期、掩码、隔离与计数（含 `personal_agent`） |
| `open_api` | 119 | 五个方法、鉴权、幂等、长轮询、webhook |
| `web_admin` | 146 | 控制台路由、CSRF/Cookie、越权与审计 |
| `i18n` | 320 | 18 语种完整性、协商、欢迎语、页面注入 |
| `web_live` | 60 | 真实 ASGI 生命周期、WebSocket、冷备往返、隐私二维码 |
| `invite_codec` | 101 | HKDF/ChaCha20 标准向量、service-suite 密钥与两条标准向量逐字节对齐、`/i/v1/` 路径主机校验、随机 nonce、明文不泄漏、篡改拒绝 |
| `bundle` | 281 | 冷备导出/校验/篡改/跨账本迁移/幂等、CLI `invite` 与 `--raw-links` |
| `eco_cards` | 89 | `::POPOPX_ECO::` 卡片与 `::CB::` 回执编解码、越界字段拒绝 |
| `ics` | 65 | RFC 5545 转义、UTC 时刻、UID/DUMPSTAMP、时长与跨天 |
| `install` | 276 | 脚本语法与旗标、干跑、服务用户主组与 `--group` 一致性（含真跑 `create_service_user` 的无桩探针）、回环与零二进制捆绑、内置权重清单校验、无桩残留 |
| `mac_node` | 201 | 严格回环与 SSRF 阻断、`X-PPX-Token`、状态/忙闲/approve、超时与降级 |
| `a2a` | 220 | 掩码投影、`FORBIDDEN_KEYS` 闸、HMAC 签名与重放、时区求交、状态机 |
| `guest_portal` | 571 | 令牌签发/验签/过期/撤销/次数预算、并发领取、脱敏空档、.ics 门槛、页面转义 |
| `agent_engine` | 3552 | Needle 3 抽取与确定性回退、权重 SHA-256 门禁、偏好规则、话术与推理桥降级、密钥卫生 |
| `agent_console` | 389 | `/api/agent/*` 与 `/book/*` 路由、鉴权、面板数据结构、18 语种词条 |
| 合计 | **7300** | 24/24 组 0 失败，退出码 0 |

## 10. 运维与安全注意

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
- 替身数据不在冷备包里：`export_bot_bundle.py` 只打包 `cli-data/` 与账本里的规则/路由，
  每 Bot 的 `agent/preferences.json` 要单独备份——它和 `cli-data` 一样是 `0700/0600`，
  但丢了只能重配。
- **访客链接本身就是凭据**：谁拿到 `/book/<token>` 谁就能占一次名额。只走私信或加密渠道分发，
  按需 `revoke`；轮换 `GUEST_SECRET` 会让全部已发出的链接立刻失效（这是预期行为，不是 bug）。
- 轮换 `MAC_NODE_TOKEN` 后必须同步 `.env`，否则 `approve` 全部失败；桥的失败只会退回模板话术
  并在审计里记 `approve_failed`，日历不会被悄悄改坏，但提案会停在 `pending`。
- A2A 不引入新的信任根：能在 SMP 队列里写出那帧的，本来就只有已配对的对方，因此签名密钥
  就是对端会话密钥。协商审计只写 id、计数和原因码，正文与标题不落审计。
- 想让替身彻底离线：`REASONER_ENABLED=0` 即可（话术全走 18 语种模板，链路不联网）；
  `MAC_NODE_ENABLED=0` 时确认落库与忙闲读取都退到本地掩码缓存，卡片流程仍然完整。

## 11. 许可

AGPL-3.0-only，详见 `LICENSE`。本仓库不分发任何 `popopx-chat` 二进制。

内置的第三方模型资产：`studio/assets/models/needle3.cact` 及其 `config-needle3.json`，来自
Cactus-Compute 的 Needle 3 权重，SHA-256 `c9d915eca282ed42d1a09b143b592adb4cc6744ffe2d294adf5cfc5548170c38`
（35,335,380 字节），许可为 **Apache-2.0**，原文 `studio/assets/models/LICENSE-needle3.txt`
（SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`）。署名沿用清单原文：
*Needle 3 weights (c) Cactus Compute, Apache License 2.0. Not authored or endorsed by the POPOPX project.*
本仓库随附该权重与清单、不下载分发；删掉 `studio/assets/models/needle3.cact` 后 Studio 仍能工作——
`needle_assets` 校验不过会退回内置的确定性抽取器（第 5.1 节），只是不再使用端侧模型。
