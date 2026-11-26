"""Plugin bus: discovery, lifecycle and isolated message dispatch.

A plugin is one module in ``studio/plugins/`` that exposes a subclass of
:class:`StudioPlugin`. The bus never lets a plugin break the gateway: every
lifecycle call and every dispatch is wrapped, counted and logged.
"""

from __future__ import annotations

import asyncio
import importlib.util
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

PLUGIN_METHODS = ("on_load", "on_enable", "on_disable", "on_unload", "on_message", "on_event", "on_hook", "on_tick")
CONFIG_FIELD_TYPES = ("text", "password", "textarea", "number", "bool", "select", "json")
MASKED_VALUE = "********"


class PluginError(RuntimeError):
    """Raised when a plugin module cannot be loaded or is malformed."""


@dataclass
class PluginResult:
    """What a plugin wants the bus to do after seeing one message."""

    handled: bool = False
    reply: str = ""
    reply_content: Optional[Dict[str, Any]] = None
    forwards: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "ok"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def should_reply(self) -> bool:
        return bool(self.reply or self.reply_content)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "handled": self.handled,
            "reply": self.reply,
            "forwards": self.forwards,
            "status": self.status,
            "metadata": self.metadata,
        }


PASS = PluginResult(status="pass")


class StudioServices(Protocol):
    """The narrow surface a plugin may use. Implemented by the Studio core."""

    async def send_text(
        self,
        bot_id: str,
        chat_type: str,
        chat_id: int,
        text: str,
        *,
        quoted_item_id: Optional[int] = None,
        plugin_id: str = "",
    ) -> Dict[str, Any]:
        ...

    async def send_content(
        self,
        bot_id: str,
        chat_type: str,
        chat_id: int,
        content: Dict[str, Any],
        *,
        plugin_id: str = "",
        file_path: str = "",
    ) -> Dict[str, Any]:
        ...

    def log_message(
        self,
        bot_id: str,
        direction: str,
        *,
        chat_type: str = "",
        chat_ref: str = "",
        sender: str = "",
        text: str = "",
        plugin_id: str = "",
        status: str = "ok",
        error: str = "",
        rule_id: Optional[int] = None,
    ) -> int:
        ...

    def clients(self) -> List[str]:
        ...


@dataclass
class PluginContext:
    """Everything a plugin is allowed to reach."""

    services: StudioServices
    db: Any
    config: Dict[str, Any] = field(default_factory=dict)
    clock: Callable[[], float] = time.time

    def config_value(self, key: str, default: Any = None) -> Any:
        value = self.config.get(key, default)
        return default if value in (None,) else value

    def require(self, *keys: str) -> Tuple[str, ...]:
        missing = [key for key in keys if not str(self.config.get(key) or "").strip()]
        if missing:
            raise PluginError(f"插件配置缺少必填项：{missing}")
        return tuple(str(self.config[key]) for key in keys)


class StudioPlugin:
    """Base class every bundled and third-party plugin extends."""

    plugin_id = ""
    name = ""
    version = "1.0.0"
    description = ""
    priority = 100
    scope = "message"  # message | transport
    config_fields: List[Dict[str, Any]] = []
    default_config: Dict[str, Any] = {}

    def __init__(self) -> None:
        if not self.plugin_id:
            raise PluginError(f"{type(self).__name__} 缺少 plugin_id")
        self.context: Optional[PluginContext] = None
        self.enabled = False
        self.loaded = False
        self.last_error = ""
        self.errors = 0
        self.processed = 0
        self.replied = 0
        self.loaded_at = 0.0
        self._tick_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------- lifecycle
    async def on_load(self, context: PluginContext) -> None:
        """Called once when the plugin module is imported."""

    async def on_enable(self, context: PluginContext) -> None:
        """Called when the plugin is switched on for at least one Bot."""

    async def on_disable(self, context: PluginContext) -> None:
        """Called when the plugin is switched off everywhere."""

    async def on_unload(self) -> None:
        """Called during gateway shutdown."""

    # ------------------------------------------------------------- dispatch
    async def on_message(self, event: Any, context: PluginContext) -> PluginResult:
        raise NotImplementedError

    async def on_event(self, frame: Any, context: PluginContext) -> None:
        """Raw CLI frame observer; used for non-message events."""

    async def on_hook(self, bot_id: str, secret: str, payload: Any, context: PluginContext) -> PluginResult:
        return PASS

    async def on_tick(self, context: PluginContext) -> None:
        """Periodic work, driven by the bus at ``tick_interval`` seconds."""

    # ------------------------------------------------------------------ util
    def merged_config(self, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        config = dict(self.default_config)
        config.update(override or {})
        return config

    def health(self) -> Dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name or self.plugin_id,
            "version": self.version,
            "description": self.description,
            "priority": self.priority,
            "scope": self.scope,
            "enabled": self.enabled,
            "loaded": self.loaded,
            "processed": self.processed,
            "replied": self.replied,
            "errors": self.errors,
            "last_error": self.last_error,
            "config_fields": self.config_fields,
        }


def _is_plugin_class(obj: Any) -> bool:
    return (
        isinstance(obj, type)
        and issubclass(obj, StudioPlugin)
        and obj is not StudioPlugin
        and bool(getattr(obj, "plugin_id", ""))
    )


def load_plugin_module(path: Path) -> List[StudioPlugin]:
    """Import *path* and instantiate every ``StudioPlugin`` subclass it exposes."""
    if not path.is_file():
        raise PluginError(f"插件文件不存在：{path}")
    spec = importlib.util.spec_from_file_location(f"popopx_plugin_{path.stem}", str(path))
    if spec is None or spec.loader is None:
        raise PluginError(f"无法加载插件模块 {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise PluginError(f"插件 {path.name} 导入失败：{type(exc).__name__}: {exc}") from exc
    instances: List[StudioPlugin] = []
    for attribute in vars(module).values():
        if _is_plugin_class(attribute):
            try:
                instances.append(attribute())
            except Exception as exc:
                raise PluginError(f"插件 {path.name}::{getattr(attribute, '__name__')} 实例化失败：{exc}") from exc
    if not instances:
        raise PluginError(f"插件 {path.name} 未定义任何 StudioPlugin 子类")
    return instances


class PluginManager:
    """Registry plus the serialized dispatch loop."""

    def __init__(
        self,
        db: Any,
        services: StudioServices,
        *,
        plugins_dir: Optional[Path] = None,
        tick_interval: float = 60.0,
    ):
        self.db = db
        self.services = services
        self.plugins_dir = Path(plugins_dir) if plugins_dir else Path(__file__).resolve().parents[1] / "plugins"
        self.tick_interval = max(5.0, float(tick_interval))
        self.plugins: Dict[str, StudioPlugin] = {}
        self.module_paths: Dict[str, Path] = {}
        self.failures: Dict[str, str] = {}
        self.dispatches = 0
        self._tick_task: Optional[asyncio.Task] = None
        self._stopping = False

    # --------------------------------------------------------------- loading
    def discover(self) -> List[Path]:
        if not self.plugins_dir.is_dir():
            return []
        return sorted(path for path in self.plugins_dir.glob("*.py") if not path.name.startswith("_"))

    def load(self) -> Dict[str, str]:
        """Import every discovered plugin; failures are recorded, never raised."""
        self.failures.clear()
        for path in self.discover():
            try:
                for plugin in load_plugin_module(path):
                    if plugin.plugin_id in self.plugins:
                        self.failures[plugin.plugin_id] = f"重复的 plugin_id（{path.name}）"
                        continue
                    self.plugins[plugin.plugin_id] = plugin
                    self.module_paths[plugin.plugin_id] = path
            except PluginError as exc:
                self.failures[path.stem] = str(exc)
        return {plugin_id: "loaded" for plugin_id in self.plugins}

    async def load_async(self) -> Dict[str, str]:
        result = self.load()
        for plugin_id, plugin in self.plugins.items():
            try:
                await plugin.on_load(self._context(plugin, ""))
                plugin.loaded = True
                plugin.loaded_at = time.time()
                result[plugin_id] = "ready"
            except Exception as exc:
                plugin.last_error = f"on_load 失败：{exc}"
                plugin.errors += 1
                result[plugin_id] = "error"
        return result

    def get(self, plugin_id: str) -> Optional[StudioPlugin]:
        return self.plugins.get(plugin_id)

    def ids(self) -> List[str]:
        return sorted(self.plugins)

    # -------------------------------------------------------------- config
    def _context(self, plugin: StudioPlugin, bot_id: str) -> PluginContext:
        _, merged = self.db.effective_plugin_config(plugin.plugin_id, bot_id)
        return PluginContext(services=self.services, db=self.db, config=plugin.merged_config(merged))

    async def set_enabled(self, plugin_id: str, enabled: bool, *, bot_id: str = "") -> Dict[str, Any]:
        plugin = self.plugins.get(plugin_id)
        if plugin is None:
            raise PluginError(f"未知插件 {plugin_id!r}")
        stored = self._strip_secrets(plugin, self._current_config(plugin_id, bot_id))
        self.db.set_plugin_config(plugin_id, stored, bot_id=bot_id, enabled=enabled)
        await self.set_state(plugin, enabled)
        return self.health(plugin_id)

    async def set_state(self, plugin: StudioPlugin, should_enable: bool) -> None:
        """Run the enable/disable hook only when the effective state changes."""
        if should_enable == plugin.enabled:
            plugin.enabled = should_enable
            return
        plugin.enabled = should_enable
        hook = plugin.on_enable if should_enable else plugin.on_disable
        try:
            await hook(self._context(plugin, ""))
        except Exception as exc:
            plugin.last_error = f"{'on_enable' if should_enable else 'on_disable'} 失败：{exc}"
            plugin.errors += 1

    async def update_config(
        self,
        plugin_id: str,
        config: Dict[str, Any],
        *,
        bot_id: str = "",
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        plugin = self.plugins.get(plugin_id)
        if plugin is None:
            raise PluginError(f"未知插件 {plugin_id!r}")
        if not isinstance(config, dict):
            raise PluginError("插件配置必须是对象")
        stored = dict(self._current_config(plugin_id, bot_id))
        stored.update({key: value for key, value in config.items() if value is not None})
        self.db.set_plugin_config(plugin_id, self._strip_secrets(plugin, stored), bot_id=bot_id, enabled=enabled)
        if enabled is not None:
            await self.set_state(plugin, bool(enabled))
        return self.health(plugin_id)

    def _current_config(self, plugin_id: str, bot_id: str) -> Dict[str, Any]:
        row = self.db.get_plugin_config(plugin_id, bot_id=bot_id)
        return dict(row["config"]) if row else {}

    def _strip_secrets(self, plugin: StudioPlugin, config: Dict[str, Any]) -> Dict[str, Any]:
        """Drop a secret field when the UI sent the masked placeholder back."""
        cleaned = dict(config)
        for candidate in (plugin_id_field(field) for field in plugin.config_fields):
            if candidate and cleaned.get(candidate) in ("", MASKED_VALUE):
                cleaned.pop(candidate, None)
        return cleaned

    # ------------------------------------------------------------- dispatch
    def ordered(self, bot_id: str = "") -> List[StudioPlugin]:
        return sorted(
            (plugin for plugin in self.plugins.values() if plugin.enabled),
            key=lambda plugin: (plugin.priority, plugin.plugin_id),
        )

    async def handle_message(self, event: Any, *, bot_id: str) -> List[Tuple[str, PluginResult]]:
        """Run every enabled plugin for one message until one handles it."""
        self.dispatches += 1
        outcomes: List[Tuple[str, PluginResult]] = []
        for plugin in self.ordered(bot_id):
            try:
                result = await plugin.on_message(event, self._context(plugin, bot_id))
            except Exception as exc:
                plugin.errors += 1
                plugin.last_error = f"{type(exc).__name__}: {exc}"
                self.db.log_message(
                    bot_id, "out", plugin_id=plugin.plugin_id, status="error",
                    text="", error=plugin.last_error, sender=getattr(event, "sender", ""),
                )
                outcomes.append((plugin.plugin_id, PASS))
                continue
            result = result if isinstance(result, PluginResult) else PASS
            plugin.processed += int(result.status != "pass")
            if result.should_reply:
                plugin.replied += 1
            outcomes.append((plugin.plugin_id, result))
            if result.handled:
                break
        return outcomes

    async def handle_event(self, frame: Any, *, bot_id: str) -> None:
        for plugin in self.ordered(bot_id):
            try:
                await plugin.on_event(frame, self._context(plugin, bot_id))
            except Exception as exc:
                plugin.errors += 1
                plugin.last_error = f"on_event: {type(exc).__name__}: {exc}"

    async def handle_hook(self, bot_id: str, secret: str, payload: Any) -> Dict[str, Any]:
        """Deliver one inbound webhook to whichever plugin claims the secret."""
        for plugin in self.ordered(bot_id):
            if "on_hook" not in type(plugin).__dict__ and not hasattr(plugin, "on_hook"):
                continue
            try:
                result = await plugin.on_hook(bot_id, secret, payload, self._context(plugin, bot_id))
            except Exception as exc:
                plugin.errors += 1
                plugin.last_error = f"on_hook: {type(exc).__name__}: {exc}"
                continue
            if result.handled or result.status != "pass":
                return {"plugin_id": plugin.plugin_id, **result.as_dict()}
        return {"plugin_id": "", "handled": False, "status": "no_plugin", "reply": "", "forwards": [], "metadata": {}}

    # ------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        self._stopping = False
        rows = self.db.list_plugin_configs()
        for plugin in self.plugins.values():
            enabled = any(row["plugin_id"] == plugin.plugin_id and bool(row["enabled"]) for row in rows)
            await self.set_state(plugin, enabled)
        if any("on_tick" in type(plugin).__dict__ for plugin in self.plugins.values()):
            self._tick_task = asyncio.create_task(self._tick_loop(), name="plugin-tick")

    async def _tick_loop(self) -> None:
        while not self._stopping:
            try:
                await asyncio.sleep(self.tick_interval)
            except asyncio.CancelledError:
                return
            for plugin in self.plugins.values():
                if not plugin.enabled or "on_tick" not in type(plugin).__dict__:
                    continue
                try:
                    await plugin.on_tick(self._context(plugin, ""))
                except Exception as exc:
                    plugin.errors += 1
                    plugin.last_error = f"on_tick: {type(exc).__name__}: {exc}"

    async def stop(self) -> None:
        self._stopping = True
        if self._tick_task is not None:
            self._tick_task.cancel()
            self._tick_task = None
        for plugin in self.plugins.values():
            try:
                await plugin.on_unload()
            except Exception as exc:
                plugin.errors += 1
                plugin.last_error = f"on_unload: {type(exc).__name__}: {exc}"
            plugin.loaded = False
            plugin.enabled = False

    # ------------------------------------------------------------- reporting
    def health(self, plugin_id: Optional[str] = None) -> Any:
        if plugin_id is not None:
            plugin = self.plugins.get(plugin_id)
            if plugin is None:
                raise PluginError(f"未知插件 {plugin_id!r}")
            return {**plugin.health(), "config": self._masked_config(plugin)}
        return {
            "plugins": [
                {**plugin.health(), "config": self._masked_config(plugin)}
                for plugin in sorted(self.plugins.values(), key=lambda item: (item.priority, item.plugin_id))
            ],
            "failures": dict(self.failures),
            "dispatches": self.dispatches,
        }

    def _masked_config(self, plugin: StudioPlugin) -> Dict[str, Any]:
        row = self.db.get_plugin_config(plugin.plugin_id, bot_id="")
        stored = dict(row["config"]) if row else {}
        for candidate in (plugin_id_field(field) for field in plugin.config_fields):
            if candidate and stored.get(candidate):
                stored[candidate] = MASKED_VALUE
        return stored


def plugin_id_field(config_field: Any) -> str:
    """Extract the storage key from either a dict or a plain string field spec."""
    if isinstance(config_field, dict):
        return str(config_field.get("key") or config_field.get("name") or "")
    return str(config_field or "")
