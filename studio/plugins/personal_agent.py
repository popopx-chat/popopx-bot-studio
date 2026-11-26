"""personal_agent — 24 小时替身机器人（prompt.md 任务 1–3 的插件侧入口）。

插件只做三件事：把入站消息交给 :class:`app.agent_runtime.AgentRuntime`、把定时收尾交给
它的 ``tick``、把权重卸载交给 ``on_unload``。抽取、查空档、A2A 协商、访客门户、写日历全部
在编排层，后台路由与自检复用同一个 :class:`AgentRuntime`，因此不存在「插件一套逻辑、
后台另一套逻辑」的分叉。

优先级 30 是内置插件里最低的：替身先看到消息，但只在 Needle 3 命中五个已知工具
（``calendar.get_availability`` / ``propose_create`` / ``propose_reschedule`` /
``propose_cancel`` / ``workspace.summarize_file``）且置信度过线时才接手，其余一律 ``pass``，
不会抢走关键词问答或路由规则的会话。

配置项只放行为开关。``STUDIO_ADMIN_TOKEN``、Mac Node 地址与令牌、A2A 密钥永远留在
``Settings``（即环境变量与 ``var/studio/`` 里 0600 的密钥文件），插件配置能被后台读写、
也会被脱敏回显，所以这里一个字都不放。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from app import agent_runtime as ar
from app.plugin_manager import PASS, PluginContext, PluginResult, StudioPlugin

log = logging.getLogger("popopx.studio.plugin.personal_agent")

PLUGIN_ID = ar.PLUGIN_ID


class PersonalAgentPlugin(StudioPlugin):
    """替身机器人插件：一条消息 → 五个工具之一 → 主人确认卡片 → 写日历并回邀请。"""

    plugin_id = PLUGIN_ID
    name = "替身机器人 / Personal stand-in"
    version = "1.0.0"
    description = (
        "Needle 3 毫秒级抽取日程意图，空档只取本机 Mac Node 或本地脱敏缓存，"
        "双边加密 A2A 协商与零安装访客门户共用同一套提案与确认卡片（数据全部留在本机）"
    )
    priority = 30
    scope = "message"

    config_fields = [
        {"key": "enabled", "type": "bool", "label": "启用替身机器人"},
        {"key": "owner_chat", "type": "text", "label": "主人会话（确认卡片发到这里，如 #12 或 @3）"},
        {"key": "min_confidence", "type": "number", "label": "接受的最低抽取置信度（0–1）"},
        {"key": "max_slots", "type": "number", "label": "一次最多给出的候选时段（1–8）"},
        {"key": "send_invite", "type": "bool", "label": "确认后自动发送 .ics 邀请"},
        {"key": "handle_a2a", "type": "bool", "label": "处理对端的 A2A 协商帧"},
    ]

    default_config = dict(ar.DEFAULT_CONFIG)

    # ``StudioPlugin.__init__`` 之外的状态放这里：插件实例由插件总线按模块创建一次，
    # 一个进程因此只有一个运行时，提案幂等与事件循环绑定才有意义。
    def __init__(self) -> None:
        super().__init__()
        self.agent: Optional[ar.AgentRuntime] = None
        self.last_tick: Dict[str, Any] = {}

    # ------------------------------------------------------------------ 装配
    def attach(self, runtime: ar.AgentRuntime) -> None:
        """由 ``main.build_stack`` 注入共享运行时（那里才有 ``Settings``）。"""
        self.agent = runtime
        log.info("[personal_agent] 已接管 Studio 运行时")

    def runtime(self, context: PluginContext) -> ar.AgentRuntime:
        """取共享运行时；独立装载（自检、第三方宿主）时就地建一个。

        ``PluginContext`` 故意不暴露 ``Settings``——它带着管理令牌——所以兜底路径只能用
        ``load_settings()`` 读本进程配置，绝不从插件配置里拼设置。
        """
        if self.agent is not None:
            return self.agent
        self.agent = ar.AgentRuntime(
            db=context.db,
            settings=ar.load_settings(),
            sender=ar.build_sender(context.services),
            clock=context.clock,
        )
        return self.agent

    # ---------------------------------------------------------------- 生命周期
    async def on_load(self, context: PluginContext) -> None:
        """装载阶段刻意不建运行时：``build_stack`` 在插件装载之后才 ``attach`` 共享实例。"""
        log.info("[personal_agent] 装载：等待 Studio 注入共享运行时")

    async def on_enable(self, context: PluginContext) -> None:
        runtime = self.runtime(context)
        runtime.bind_loop()
        cfg = dict(context.config or {})
        log.info(
            "[personal_agent] 启用：替身=%s 主人会话=%s 处理 A2A=%s",
            cfg.get("enabled"),
            cfg.get("owner_chat") or "（未配置）",
            cfg.get("handle_a2a"),
        )

    async def on_disable(self, context: PluginContext) -> None:
        log.info("[personal_agent] 停用：入站消息交回其它插件与规则")

    async def on_unload(self) -> None:
        if self.agent is not None:
            self.agent.close()

    # ------------------------------------------------------------------ 派发
    async def on_message(self, event: Any, context: PluginContext) -> PluginResult:
        text = str(getattr(event, "text", "") or "")
        if not text.strip():
            return PASS
        decision = await self.runtime(context).handle_message(
            str(getattr(event, "bot_id", "") or ""), event, context.config
        )
        if not decision:
            return PASS
        return PluginResult(**decision)

    async def on_tick(self, context: PluginContext) -> None:
        """卡片与协商会话的 TTL 收尾：总线只全局 tick，过期判断跨 Bot。"""
        self.last_tick = await self.runtime(context).tick(context)

    def health(self) -> Dict[str, Any]:
        base = super().health()
        if self.agent is not None:
            base["agent"] = self.agent.status()
            base["last_tick"] = dict(self.last_tick)
        return base

    # -------------------------------------------------------------- 后台入口
    def export_prompt(self, bot_id: str, *, locale: str = "") -> str:
        """把该 Bot 的偏好规则导成人类可读文本（后台「导出规则」按钮）。"""
        if self.agent is None:
            return ""
        row = self.agent.preferences.load(bot_id)
        return json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True)


__all__ = ["PersonalAgentPlugin", "PLUGIN_ID"]
