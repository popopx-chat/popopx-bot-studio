#!/usr/bin/env python3
"""POPOPX Bot Studio — 离线 Bot 冷备导出、完整性校验与迁移恢复工具。

本工具复用 Studio 自身的实现（``app.main.build_stack`` +
``app.bot_supervisor.BotSupervisor.export_bundle/import_bundle``），产出的备份包与
Web 管理后台「一键冷备」完全一致：gzip tar + Studio manifest，可选 ``PBSB``
（scrypt + AES-256-GCM）加密，并附带 ``.json`` 清单边车文件。

严格离线：不启动 Web 服务、不 fork ``popopx-cli``、不监听也不探测任何 socket。

用法示例::

    python3 official_tools/export_bot_bundle.py list --json
    python3 official_tools/export_bot_bundle.py invite --bot opsbot --qr /srv/opsbot-invite.png
    python3 official_tools/export_bot_bundle.py export --bot opsbot --dest /srv/backups
    python3 official_tools/export_bot_bundle.py export --bot bot_alpha_102f2e99 \\
        --dest /srv/backups --passphrase-env BOT_BACKUP_PASSPHRASE
    python3 official_tools/export_bot_bundle.py verify /srv/backups/bot_alpha_xxx.botbundleenc \\
        --passphrase-stdin
    python3 official_tools/export_bot_bundle.py restore /srv/backups/bot_alpha_xxx.botbundle \\
        --data-dir /srv/new-studio --into opsbot

安全约定：口令只能通过 ``--passphrase-env <环境变量名>`` 或 ``--passphrase-stdin``
交互输入取得，绝不接受命令行明文口令（那会泄漏进 ``ps`` 与 shell 历史），且口令
内容永不打印。Bot Token 等敏感字段也不会出现在任何输出里。
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROG = "export_bot_bundle.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
STUDIO_DIR = REPO_ROOT / "studio"
if str(STUDIO_DIR) not in sys.path:  # 允许从仓库根目录直接运行本文件
    sys.path.insert(0, str(STUDIO_DIR))

from app.bot_supervisor import (  # noqa: E402  (sys.path 必须先就绪)
    BUNDLE_MAGIC,
    BUNDLE_VERSION,
    BotSupervisor,
    BotSupervisorError,
    decrypt_bundle,
    sha256_bytes,
    unique_bot_name,
)
from app.config import (  # noqa: E402
    SECURE_DIR_MODE,
    SECURE_FILE_MODE,
    Settings,
    load_settings,
    mode_of,
)
from app.database import Database, LedgerError  # noqa: E402
from app.main import APP_NAME, APP_VERSION, StudioStack, build_stack  # noqa: E402
from app.security.opaque_invite_codec import OpaqueInviteError, encode_invite_link  # noqa: E402

BUNDLE_FORMAT = "popopx-bot-studio-bundle"
PLAIN_SUFFIX = ".botbundle"
ENC_SUFFIX = ".botbundleenc"
SIDECAR_SUFFIX = ".json"
GZIP_MAGIC = b"\x1f\x8b"

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_BOT_MISSING = 3
EXIT_BOT_DELETED = 4
EXIT_DEST_UNWRITABLE = 5
EXIT_BUNDLE_BAD = 6
EXIT_PASSPHRASE = 7
EXIT_LEDGER = 8

__all__ = [
    "main",
    "build_parser",
    "export",
    "export_with_stack",
    "verify_bundle",
    "restore",
    "restore_with_stack",
    "list_bots",
    "invite",
    "resolve_bot",
    "find_reuse_row",
    "ToolError",
    "BUNDLE_FORMAT",
    "EXIT_OK",
    "EXIT_USAGE",
    "EXIT_BOT_MISSING",
    "EXIT_BOT_DELETED",
    "EXIT_DEST_UNWRITABLE",
    "EXIT_BUNDLE_BAD",
    "EXIT_PASSPHRASE",
]


class ToolError(RuntimeError):
    """面向操作者的中文错误，携带明确退出码。"""

    def __init__(self, message: str, *, code: int = EXIT_RUNTIME):
        super().__init__(message)
        self.message = message
        self.code = int(code)


# --------------------------------------------------------------------- plumbing
def _utf8_streams() -> None:
    """中文输出不能因为 LC_ALL=C 崩成 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - 极少见
            pass


def sha256_file(path: Path) -> str:
    """流式 SHA-256：不把大备份包整体读进内存。"""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mode_text(path: Path) -> str:
    mode = mode_of(path)
    return "" if mode is None else f"0{mode:o}"


def mode_findings(payload: Dict[str, Any]) -> List[Tuple[str, str]]:
    """导出/校验结果里所有文件权限位，用于 0600 安全告警。"""
    found: List[Tuple[str, str]] = []
    file_info = payload.get("file")
    if isinstance(file_info, dict) and file_info.get("mode"):
        found.append((str(file_info.get("path") or "备份包"), str(file_info["mode"])))
    sidecar = payload.get("sidecar")
    if isinstance(sidecar, dict) and sidecar.get("mode"):
        found.append((str(sidecar.get("path") or "边车清单"), str(sidecar["mode"])))
    if payload.get("mode"):
        found.append((str(payload.get("path") or "备份包"), str(payload["mode"])))
    return found


def permission_warnings(messages: Sequence[str]) -> List[str]:
    """只保留权限相关告警：离线工具不需要 admin token，也不会拉起 CLI。"""
    return [text for text in messages if "权限" in text]


def apply_env_overrides(data_dir: Optional[str], env_file: Optional[str]) -> None:
    """把 ``--data-dir`` / ``--env-file`` 写回环境变量，再交给 ``load_settings``。"""
    if data_dir:
        os.environ["STUDIO_DATA_DIR"] = str(Path(data_dir).expanduser())
    if env_file:
        os.environ["STUDIO_ENV_FILE"] = str(Path(env_file).expanduser())


def make_settings(data_dir: Optional[str] = None, env_file: Optional[str] = None) -> Settings:
    """按仓库既有约定加载 Settings（.env 与环境变量，环境变量优先）。"""
    apply_env_overrides(data_dir, env_file)
    return load_settings()


def prepare_dest(dest: Optional[Any], fallback: Path) -> Path:
    """确认导出目录存在且可写，否则给出中文错误（退出码 5）。"""
    raw = str(dest).strip() if dest else ""
    target = Path(raw).expanduser() if raw else Path(fallback).expanduser()
    if raw and target.is_file():
        raise ToolError(f"导出目标 {target} 是文件，不是目录", code=EXIT_DEST_UNWRITABLE)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ToolError(
            f"无法创建导出目录 {target}：{type(exc).__name__}: {exc}", code=EXIT_DEST_UNWRITABLE
        ) from exc
    if not target.is_dir():
        raise ToolError(f"导出目录 {target} 不是目录", code=EXIT_DEST_UNWRITABLE)
    if not os.access(target, os.W_OK | os.X_OK):
        raise ToolError(
            f"导出目录 {target} 不可写：请换目录，或用可写账号执行 chmod/chown",
            code=EXIT_DEST_UNWRITABLE,
        )
    current = mode_of(target)
    if current is not None and current & ~SECURE_DIR_MODE:
        # 帮助文档承诺「导出目录会被强制设为 0700」：冷包里是 Bot 身份与密钥库。
        try:
            os.chmod(target, SECURE_DIR_MODE)
        except OSError:
            pass
    return target.resolve()


def read_passphrase(env_var: str = "", from_stdin: bool = False) -> str:
    """按「环境变量名 → 标准输入」顺序取口令；命令行永远不含口令。"""
    if env_var:
        name = env_var.strip()
        if name not in os.environ:
            raise ToolError(f"环境变量 {name} 未设置，无法取得冷备口令", code=EXIT_PASSPHRASE)
        value = os.environ[name] or ""
        if not value:
            raise ToolError(f"环境变量 {name} 为空，无法取得冷备口令", code=EXIT_PASSPHRASE)
        return value
    if not from_stdin:
        return ""
    if sys.stdin.isatty():
        first = getpass.getpass("冷备口令（已关闭回显）: ")
        second = getpass.getpass("再次输入冷备口令: ")
        if first != second:
            raise ToolError("两次输入的冷备口令不一致", code=EXIT_PASSPHRASE)
        if not first:
            raise ToolError("冷备口令不能为空", code=EXIT_PASSPHRASE)
        return first
    line = sys.stdin.readline()
    if not line:
        raise ToolError("标准输入为空，无法读取冷备口令", code=EXIT_PASSPHRASE)
    value = line.rstrip("\r\n")
    if not value:
        raise ToolError("标准输入中的冷备口令为空", code=EXIT_PASSPHRASE)
    return value


def resolve_bot(db: Database, ref: str) -> Dict[str, Any]:
    """把 ``--bot`` 解释串（id / 名称 / 端口）解析成账本行。"""
    needle = (ref or "").strip()
    if not needle:
        raise ToolError("缺少 --bot：请提供 Bot id、Bot 名称或控制端口", code=EXIT_USAGE)
    bot = db.get_bot(needle)
    if bot is None:
        bot = db.get_bot_by_name(needle.lower())
    if bot is None and needle.isdigit():
        bot = db.get_bot_by_port(int(needle))
    if bot is None:
        deleted = db.get_bot(needle, include_deleted=True)
        if deleted is not None and str(deleted.get("status")) == "deleted":
            raise ToolError(
                f"Bot {needle} 已被删除（status=deleted）：账本已不接管它，"
                "请直接在备份目录里使用它上次导出的冷备包",
                code=EXIT_BOT_DELETED,
            )
        known = ", ".join(str(row["name"]) for row in db.list_bots()[:12]) or "（账本为空）"
        raise ToolError(
            f"账本中不存在 Bot {needle!r}；可用 --list 查看，当前 Bot 名称：{known}",
            code=EXIT_BOT_MISSING,
        )
    return bot


def bot_view(bot: Dict[str, Any], *, raw: bool = False) -> Dict[str, Any]:
    """对外 Bot 视图：永不携带 ``bot_token`` 等敏感字段。

    默认只给隐私封装后的 ``invite_link``；``smp://`` 原始地址与 SMP 节点列表
    会把集群拓扑暴露给拿到输出的人，只有 ``raw=True``（命令行的 ``--raw`` /
    ``--raw-links``）才附带。
    """
    raw_link = str(bot.get("permanent_link") or bot.get("contact_address") or "")
    try:
        invite = encode_invite_link(raw_link) if raw_link else ""
    except OpaqueInviteError:
        invite = ""
    view = {
        "bot_id": str(bot.get("id") or ""),
        "name": str(bot.get("name") or ""),
        "display_name": str(bot.get("display_name") or ""),
        "port": int(bot.get("port") or 0),
        "status": str(bot.get("status") or ""),
        "invite_link": invite,
    }
    if raw:
        view["permanent_link"] = raw_link
        view["smp_servers"] = str(bot.get("smp_servers") or "")
    return view


def sidecar_path(bundle: Path) -> Path:
    return bundle.with_name(bundle.name + SIDECAR_SUFFIX)


def load_sidecar(bundle: Path) -> Tuple[Path, Optional[Dict[str, Any]]]:
    sidecar = sidecar_path(bundle)
    if not sidecar.is_file():
        return sidecar, None
    try:
        return sidecar, json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ToolError(
            f"边车清单 {sidecar} 无法解析：{type(exc).__name__}: {exc}", code=EXIT_BUNDLE_BAD
        ) from exc


def open_bundle(bundle: Any, passphrase: str = "") -> Tuple[bytes, bytes, bool]:
    """返回 (磁盘字节, 解压前 payload, 是否加密)；复用 Studio 的 PBSB 解密。"""
    source = Path(bundle).expanduser()
    if not source.is_file():
        raise ToolError(f"备份包不存在：{source}", code=EXIT_BUNDLE_BAD)
    blob = source.read_bytes()
    if blob[:4] == BUNDLE_MAGIC:
        if not passphrase:
            raise ToolError(
                f"备份包 {source.name} 已加密，请用 --passphrase-env/--passphrase-stdin 提供口令",
                code=EXIT_PASSPHRASE,
            )
        try:
            payload = decrypt_bundle(blob, passphrase)
        except BotSupervisorError as exc:
            text = str(exc)
            code = EXIT_PASSPHRASE if "解密失败" in text else EXIT_BUNDLE_BAD
            raise ToolError(f"无法解密备份包 {source.name}：{text}", code=code) from exc
        return blob, payload, True
    if blob.startswith(GZIP_MAGIC):
        return blob, blob, False
    raise ToolError(
        f"备份包 {source} 格式无法识别（既无 PBSB 魔数，也不是 gzip 数据）", code=EXIT_BUNDLE_BAD
    )


def unpack_payload(payload: bytes, source: Path) -> Tuple[Dict[str, Any], Dict[str, Tuple[bytes, int]], List[str]]:
    """复用 Studio 的安全解包器，并把损坏包翻译成分级错误（退出码 6）。"""
    try:
        return BotSupervisor._unpack_tar(payload)  # noqa: SLF001 - 与 import_bundle 同一实现
    except BotSupervisorError as exc:
        raise ToolError(f"备份包 {source.name} 无法解包：{exc}", code=EXIT_BUNDLE_BAD) from exc


# ----------------------------------------------------------------------- export
async def export_with_stack(
    stack: StudioStack,
    bot_ref: str,
    *,
    passphrase: str = "",
    dest: Optional[Any] = None,
    verify: bool = True,
) -> Dict[str, Any]:
    """调用现有 ``BotSupervisor.export_bundle`` 产出一个冷备包。

    从未启动过的 Bot 只有账本行、没有隔离数据目录，而 ``export_bundle`` 要求目录
    存在；这里先用 ``BotPaths.create()`` 按标准布局补建空目录，保证离线导出可用。
    """
    warnings: List[str] = list(permission_warnings(stack.settings.startup_warnings))
    bot = resolve_bot(stack.db, bot_ref)
    bot_id = str(bot["id"])
    paths = stack.supervisor.paths_for(bot_id)
    created_dirs = False
    if not paths.cli_data.is_dir():
        paths.create()
        created_dirs = True
        warnings.append(
            f"Bot {bot_id} 尚无隔离数据目录（从未启动过），已按标准布局补建空目录：{paths.cli_data}"
        )
    out_dir = prepare_dest(dest, stack.settings.backups_dir)
    meta = await stack.supervisor.export_bundle(bot_id, passphrase=passphrase, dest=out_dir)
    result = build_export_result(
        meta,
        bot=bot,
        created_dirs=created_dirs,
        warnings=warnings,
        data_dir=str(stack.settings.data_dir),
    )
    if verify:
        report = verify_bundle(Path(meta["bundle"]), passphrase=passphrase, sidecar=meta)
        result["verify"] = report
        if not report["ok"]:
            raise ToolError(f"冷备包完整性校验未通过：{report['errors']}", code=EXIT_BUNDLE_BAD)
    return result


def build_export_result(
    meta: Dict[str, Any],
    *,
    bot: Optional[Dict[str, Any]] = None,
    created_dirs: bool = False,
    warnings: Sequence[str] = (),
    data_dir: str = "",
) -> Dict[str, Any]:
    path = Path(meta["bundle"])
    sidecar = sidecar_path(path)
    return {
        "ok": True,
        "action": "export",
        "format": BUNDLE_FORMAT,
        "data_dir": data_dir,
        "bot": bot_view(bot or {"id": meta.get("bot_id")}),
        "file": {
            "path": str(path),
            "name": path.name,
            "bytes": int(meta.get("bytes") or path.stat().st_size),
            "sha256": str(meta.get("sha256") or ""),
            "file_sha256": sha256_file(path),
            "encrypted": bool(meta.get("encrypted")),
            "suffix": ENC_SUFFIX if meta.get("encrypted") else PLAIN_SUFFIX,
            "magic": "PBSB" if meta.get("encrypted") else "gzip",
            "mode": mode_text(path),
            "bundle_version": BUNDLE_VERSION,
        },
        "sidecar": {
            "path": str(sidecar),
            "exists": sidecar.is_file(),
            "mode": mode_text(sidecar),
        },
        "files": int(meta.get("files") or 0),
        "created_dirs": bool(created_dirs),
        "created_at": float(meta.get("created_at") or time.time()),
        "bundle_meta": dict(meta),
        "verify": None,
        "warnings": list(warnings),
    }


def export(
    bot_ref: str,
    *,
    passphrase: str = "",
    dest: Optional[Any] = None,
    data_dir: Optional[Any] = None,
    env_file: Optional[Any] = None,
    verify: bool = True,
) -> Dict[str, Any]:
    """一次性离线导出：自建 Settings/账本/supervisor，不起服务也不拉 CLI。"""
    settings = make_settings(
        str(data_dir) if data_dir else None, str(env_file) if env_file else None
    )
    stack = build_stack(settings)
    try:
        return asyncio.run(
            export_with_stack(stack, bot_ref, passphrase=passphrase, dest=dest, verify=verify)
        )
    finally:
        stack.db.close()


# ----------------------------------------------------------------------- verify
def verify_bundle(
    bundle: Any, *, passphrase: str = "", sidecar: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """非破坏式完整性校验：魔数、manifest 格式、逐成员 SHA-256、边车一致性。"""
    source = Path(bundle).expanduser()
    blob, payload, encrypted = open_bundle(source, passphrase)
    manifest, restored, skipped = unpack_payload(payload, source)
    errors: List[str] = []
    if str(manifest.get("format") or "") != BUNDLE_FORMAT:
        errors.append(f"manifest.format={manifest.get('format')!r}，期望 {BUNDLE_FORMAT!r}")

    mismatched: List[str] = []
    checked = 0
    for record in manifest.get("files") or []:
        name = str(record.get("name") or "")
        entry = restored.get(name)
        if entry is None or entry[0] is None:
            mismatched.append(name)
            continue
        if sha256_bytes(entry[0]) != str(record.get("sha256") or ""):
            mismatched.append(name)
            continue
        checked += 1
    if mismatched:
        errors.append("以下成员缺失或 SHA-256 不匹配：" + ", ".join(sorted(mismatched)[:8]))

    payload_sha = sha256_bytes(payload)
    sidecar_file = sidecar_path(source)
    sidecar_report: Dict[str, Any] = {
        "path": str(sidecar_file),
        "exists": sidecar_file.is_file(),
        "mode": mode_text(sidecar_file),
        "matches": False,
        "errors": [],
        "warnings": [],
        "meta": {},
    }
    if sidecar is None:
        sidecar_file, disk_sidecar = load_sidecar(source)
        if disk_sidecar is None:
            # manifest 里的逐成员 SHA-256 是自指的：只有边车的 payload 哈希能锚定它。
            # 边车一旦被删，校验就退化成「能解开就算通过」，必须报错而不是静默放行。
            message = f"缺少边车清单：{sidecar_file}，无法锚定 payload SHA-256"
            sidecar_report["errors"].append(message)
            errors.append(message)
        else:
            sidecar = disk_sidecar
    if sidecar:
        sidecar_report["meta"] = dict(sidecar)
        pairs = {
            "bytes": (_sidecar_int(sidecar.get("bytes")), len(blob)),
            "sha256": (str(sidecar.get("sha256") or ""), payload_sha),
            "encrypted": (bool(sidecar.get("encrypted")), encrypted),
            "bot_id": (str(sidecar.get("bot_id") or ""), str(manifest.get("bot_id") or "")),
            "files": (_sidecar_int(sidecar.get("files")), _count_cli_data_files(manifest)),
        }
        for key, (got, want) in pairs.items():
            if got != want:
                sidecar_report["errors"].append(f"边车 {key} 与实际内容不一致：{got} != {want}")
        # 文件名只做提示：改过名字的备份包配同名边车仍然完整，完整性由 payload sha256 把关。
        saved_name = Path(str(sidecar.get("bundle") or "")).name
        if saved_name and saved_name != source.name:
            sidecar_report["warnings"].append(
                f"边车记录的文件名 {saved_name} 与当前 {source.name} 不同（应已改名）"
            )
        sidecar_report["matches"] = not sidecar_report["errors"]
        errors.extend(sidecar_report["errors"])
    sidecar_report["exists"] = sidecar_file.is_file()

    return {
        "ok": not errors,
        "action": "verify",
        "path": str(source),
        "bytes": len(blob),
        "mode": mode_text(source),
        "encrypted": encrypted,
        "magic": "PBSB" if encrypted else "gzip",
        "format": BUNDLE_FORMAT,
        "bundle_format": str(manifest.get("format") or ""),
        "version": int(manifest.get("version") or 0),
        "bundle_bot_id": str(manifest.get("bot_id") or ""),
        "created_at": float(manifest.get("created_at") or 0.0),
        "file_sha256": sha256_file(source),
        "payload_sha256": payload_sha,
        "manifest_files": len(manifest.get("files") or []),
        "cli_data_files": _count_cli_data_files(manifest),
        "checked": checked,
        "mismatched": sorted(mismatched),
        "skipped": list(skipped),
        "sidecar": sidecar_report,
        "bot": bot_view(manifest.get("bot") or {}) if manifest.get("bot") else None,
        "rules": {
            "reply": len(manifest.get("reply_rules") or []),
            "routing": len(manifest.get("routing_rules") or []),
            "plugin_configs": len(manifest.get("plugin_configs") or []),
        },
        "errors": errors,
    }


def _count_cli_data_files(manifest: Dict[str, Any]) -> int:
    return len(
        [
            record
            for record in (manifest.get("files") or [])
            if str(record.get("name") or "").startswith("cli-data/")
        ]
    )


def _sidecar_int(value: Any) -> int:
    """边车里的数字字段：合法的 0 不能被当成「缺失」。

    从未启动过的 Bot 打包时 ``files`` 就是 0，用 ``int(v or -1)`` 会把它读成 -1，
    于是自己的导出校验永远报「边车 files 与实际内容不一致」。
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return -1
    return int(value)


def find_reuse_row(db: Database, saved_bot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """目标账本里代表「同一个 Bot」的行（永久链接优先，其次名称），没有则 None。

    软删除的行不参与：删除已经烧掉了它的名称与端口，还原应当得到新的一行。
    """
    link = str(saved_bot.get("permanent_link") or "")
    name = str(saved_bot.get("name") or "")
    for row in db.list_bots():
        if link and str(row.get("permanent_link") or "") == link:
            return row
        if not link and name and str(row.get("name") or "") == name:
            return row
    return None


# ---------------------------------------------------------------------- restore
async def restore_with_stack(
    stack: StudioStack,
    bundle: Any,
    *,
    passphrase: str = "",
    into: str = "",
    new_name: str = "",
    verify_first: bool = True,
    replace_rules: bool = False,
) -> Dict[str, Any]:
    """调用现有 ``BotSupervisor.import_bundle`` 把冷备包还原进目标账本。

    还原后的 Bot 一律停在 ``stopped``：本工具既不启动 ``popopx-cli``，也不探测端口
    （新账本行的端口由 ``Database.next_free_port`` 纯 SQL 分配）。
    """
    warnings: List[str] = list(permission_warnings(stack.settings.startup_warnings))
    source = Path(bundle).expanduser()
    report = verify_bundle(source, passphrase=passphrase) if verify_first else None
    if report is not None and not report["ok"]:
        raise ToolError(f"冷备包完整性校验未通过，已拒绝还原：{report['errors']}", code=EXIT_BUNDLE_BAD)

    manifest = unpack_payload(open_bundle(source, passphrase)[1], source)[0]
    saved_bot = manifest.get("bot") or {}
    manifest_bot_id = str(manifest.get("bot_id") or "")

    target_id = ""
    created_row: Optional[Dict[str, Any]] = None
    if into:
        target_id = str(resolve_bot(stack.db, into)["id"])
    elif manifest_bot_id and stack.db.get_bot(manifest_bot_id, include_deleted=True) is not None:
        target_id = manifest_bot_id
    else:
        reuse = find_reuse_row(stack.db, saved_bot)
        if reuse is not None:
            # 同一个 Bot 的永久地址在账本里只能有一行；按包内 bot_id 找不到时（换机
            # 还原后 id 已经是新建的），同址/同名行就是它的上一份还原结果。
            target_id = str(reuse["id"])
            warnings.append(
                f"目标账本已有同址 Bot {target_id}（{reuse['name']}），冷备还原进该行"
            )
        else:
            base = new_name or str(saved_bot.get("name") or "") or manifest_bot_id or "restored"
            name = unique_bot_name(base, stack.db)
            port = stack.db.next_free_port(stack.settings.ws_port_base, stack.settings.ws_port_max)
            created_row = stack.db.create_bot(
                name,
                port,
                display_name=str(saved_bot.get("display_name") or "") or name,
                smp_servers=str(saved_bot.get("smp_servers") or ""),
            )
            target_id = str(created_row["id"])
            warnings.append(
                f"目标账本没有 Bot {manifest_bot_id or '（包内 id）'}，已新建行 {target_id}（端口 {port}）"
            )

    removed = {"reply": 0, "routing": 0}
    if replace_rules:
        # 还原本身是幂等的（自动回复按 (bot, trigger, pattern) upsert，路由按内容指纹跳过），
        # --replace-rules 是另一件事：目标 Bot 上那些「包里已经没有」的旧规则要先清掉。
        for rule in stack.db.list_reply_rules(target_id):
            removed["reply"] += int(bool(stack.db.delete_reply_rule(int(rule["id"]))))
        for rule in stack.db.list_routing_rules(target_id):
            removed["routing"] += int(bool(stack.db.delete_routing_rule(int(rule["id"]))))
        warnings.append(
            f"--replace-rules：已删除目标 Bot {target_id} 原有的 "
            f"{removed['reply']} 条自动回复规则与 {removed['routing']} 条路由规则"
        )

    try:
        info = await stack.supervisor.import_bundle(
            source, passphrase=passphrase, bot_id=target_id, start=False
        )
    except LedgerError as exc:
        raise ToolError(f"还原写入账本失败：{exc}", code=EXIT_LEDGER) from exc
    row = stack.db.get_bot(target_id, include_deleted=True) or {}
    paths = stack.supervisor.paths_for(target_id)
    written = len([item for item in paths.cli_data.rglob("*") if item.is_file()])
    expected = report["cli_data_files"] if report else None
    if expected is not None and written != expected:
        raise ToolError(
            f"还原后 cli-data 有 {written} 个文件，与备份包声明的 {expected} 个不一致",
            code=EXIT_BUNDLE_BAD,
        )
    return {
        "ok": True,
        "action": "restore",
        "format": BUNDLE_FORMAT,
        "source": str(source),
        "data_dir": str(stack.settings.data_dir),
        "bot": bot_view(row),
        "created_row": bot_view(created_row) if created_row else None,
        "import": dict(info),
        "replaced_rules": removed,
        "restored_files": written,
        "expected_files": expected,
        "verify": report,
        "started": False,
        "warnings": warnings,
    }


def restore(
    bundle: Any,
    *,
    passphrase: str = "",
    into: str = "",
    new_name: str = "",
    data_dir: Optional[Any] = None,
    env_file: Optional[Any] = None,
    verify_first: bool = True,
    replace_rules: bool = False,
) -> Dict[str, Any]:
    """一次性离线还原（供脚本与自检直接调用）。"""
    settings = make_settings(
        str(data_dir) if data_dir else None, str(env_file) if env_file else None
    )
    stack = build_stack(settings)
    try:
        return asyncio.run(
            restore_with_stack(
                stack,
                bundle,
                passphrase=passphrase,
                into=into,
                new_name=new_name,
                verify_first=verify_first,
                replace_rules=replace_rules,
            )
        )
    finally:
        stack.db.close()


# ------------------------------------------------------------------------- list
def list_bots(
    *,
    data_dir: Optional[Any] = None,
    env_file: Optional[Any] = None,
    include_deleted: bool = False,
    raw_links: bool = False,
) -> Dict[str, Any]:
    """读取账本，返回 Bot 列表（含端口与隔离目录状态）与备份包概览。"""
    settings = make_settings(
        str(data_dir) if data_dir else None, str(env_file) if env_file else None
    )
    stack = build_stack(settings)
    items: List[Dict[str, Any]] = []
    try:
        rows = all_rows(stack.db) if include_deleted else stack.db.list_bots()
        for row in rows:
            bot_id = str(row["id"])
            paths = stack.supervisor.paths_for(bot_id)
            bundles = (
                sorted(
                    path.name
                    for pattern in (f"{bot_id}*{PLAIN_SUFFIX}", f"{bot_id}*{ENC_SUFFIX}")
                    for path in settings.backups_dir.glob(pattern)
                )
                if settings.backups_dir.is_dir()
                else []
            )
            exists = paths.cli_data.is_dir()
            items.append(
                {
                    **bot_view(row, raw=raw_links),
                    "cli_data": str(paths.cli_data),
                    "cli_data_exists": exists,
                    "cli_data_files": (
                        len([item for item in paths.cli_data.rglob("*") if item.is_file()])
                        if exists
                        else 0
                    ),
                    "bundles": bundles,
                }
            )
    finally:
        stack.db.close()
    return {
        "ok": True,
        "action": "list",
        "data_dir": str(settings.data_dir),
        "db_file": str(settings.db_file),
        "backups_dir": str(settings.backups_dir),
        "ws_port_range": [settings.ws_port_base, settings.ws_port_max],
        "cli_bin_path": str(settings.cli_bin_path),
        "cli_present": settings.cli_bin_path.exists(),
        "count": len(items),
        "bots": items,
        "warnings": permission_warnings(settings.startup_warnings),
    }


def all_rows(db: Database) -> List[Dict[str, Any]]:
    """含软删除行的账本视图（``list --all`` 用）；只做一次只读查询。"""
    with db._lock:  # noqa: SLF001 - 复用同一连接，避免另开 WAL 读者
        cursor = db.conn.execute("SELECT * FROM bots ORDER BY port")
        return [dict(row) for row in cursor.fetchall()]


# ---------------------------------------------------------------------- invite
def invite(
    bot_ref: str,
    *,
    raw: bool = False,
    qr_path: Optional[Any] = None,
    box_size: int = 8,
    data_dir: Optional[Any] = None,
    env_file: Optional[Any] = None,
) -> Dict[str, Any]:
    """生成 Bot 邀请链接与可选二维码；默认隐私封装，``raw=True`` 才暴露原始地址。"""
    settings = make_settings(
        str(data_dir) if data_dir else None, str(env_file) if env_file else None
    )
    stack = build_stack(settings)
    try:
        bot = resolve_bot(stack.db, bot_ref)
        raw_link = str(bot.get("permanent_link") or bot.get("contact_address") or "")
        if not raw_link:
            raise ToolError(
                f"Bot {bot_ref} 还没有永久联系地址，请先启动并完成初始化", code=EXIT_RUNTIME
            )
        if raw:
            link = raw_link
        else:
            try:
                link = encode_invite_link(raw_link)
            except OpaqueInviteError as exc:
                raise ToolError(f"邀请链接隐私封装失败：{exc}", code=EXIT_RUNTIME) from exc
        qr_report: Optional[Dict[str, Any]] = None
        if qr_path:
            target = Path(str(qr_path)).expanduser()
            try:
                payload = stack.supervisor.qr_png(link, box_size=int(box_size))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                os.chmod(target, SECURE_FILE_MODE)
            except (OSError, ValueError) as exc:
                raise ToolError(
                    f"无法写出二维码 {target}：{type(exc).__name__}: {exc}", code=EXIT_DEST_UNWRITABLE
                ) from exc
            qr_report = {
                "path": str(target.resolve()),
                "bytes": len(payload),
                "sha256": sha256_bytes(payload),
                "mode": mode_text(target),
                "box": int(box_size),
            }
        return {
            "ok": True,
            "action": "invite",
            "data_dir": str(settings.data_dir),
            "bot": bot_view(bot, raw=raw),
            "link": link,
            "opaque": not raw,
            "qr": qr_report,
            "warnings": permission_warnings(settings.startup_warnings),
        }
    finally:
        stack.db.close()


# ----------------------------------------------------------------------- render
def render_export(payload: Dict[str, Any]) -> str:
    file_info = payload["file"]
    lines = [
        f"冷备包已写出：{file_info['path']}",
        f"  大小 {file_info['bytes']} 字节，权限 {file_info['mode']}，"
        + ("已加密（PBSB）" if file_info["encrypted"] else "未加密（gzip）"),
        f"  payload SHA-256 {file_info['sha256']}",
        f"  文件   SHA-256 {file_info['file_sha256']}",
        f"  cli-data 文件数 {payload['files']}，边车清单 {payload['sidecar']['path']}",
    ]
    report = payload.get("verify")
    if report:
        lines.append(
            f"  完整性校验{'通过' if report['ok'] else '失败'}："
            f"manifest {report['manifest_files']} 项，已核对 {report['checked']} 项，"
            f"跳过 {len(report['skipped'])} 项"
        )
    return "\n".join(lines)


def render_verify(payload: Dict[str, Any]) -> str:
    text = (
        f"备份包 {payload['path']}\n"
        f"  魔数 {payload['magic']}，{payload['bytes']} 字节，权限 {payload['mode']}，"
        f"format={payload['bundle_format']} version={payload['version']}\n"
        f"  源 Bot {payload['bundle_bot_id'] or '（未知）'}，manifest 成员 "
        f"{payload['manifest_files']} 项（cli-data {payload['cli_data_files']} 项），"
        f"已核对 {payload['checked']} 项\n"
        f"  规则：自动回复 {payload['rules']['reply']}，路由 {payload['rules']['routing']}，"
        f"插件配置 {payload['rules']['plugin_configs']}\n"
        f"  边车清单 {payload['sidecar']['path']}："
        + ("匹配" if payload["sidecar"]["matches"] else "不匹配")
    )
    if payload["skipped"]:
        text += f"\n  已跳过不安全成员 {len(payload['skipped'])} 项"
    if payload["errors"]:
        text += "\n  错误：" + "；".join(payload["errors"])
    else:
        text += "\n  完整性校验通过"
    return text


def render_restore(payload: Dict[str, Any]) -> str:
    bot = payload["bot"]
    replaced = payload.get("replaced_rules") or {"reply": 0, "routing": 0}
    lines = [
        f"冷备包已还原进账本：{payload['data_dir']}",
        f"  目标 Bot {bot['bot_id']}（名称 {bot['name']}，端口 {bot['port']}，状态 {bot['status']}）",
        f"  写入 cli-data 文件 {payload['restored_files']} 个；未启动 popopx-cli",
    ]
    if replaced["reply"] or replaced["routing"]:
        lines.append(
            f"  --replace-rules 已清除旧规则：自动回复 {replaced['reply']} 条，"
            f"路由 {replaced['routing']} 条"
        )
    return "\n".join(lines)


def render_invite(payload: Dict[str, Any]) -> str:
    bot = payload["bot"]
    lines = [
        f"Bot {bot['bot_id']}（{bot['name']}）邀请链接：",
        f"  {payload['link']}",
        f"  形式：{'原始 smp:// 地址（高级诊断，含节点域名）' if not payload['opaque'] else '隐私封装，可安全分享'}",
    ]
    qr = payload.get("qr")
    if qr:
        lines.append(f"  二维码：{qr['path']}（{qr['bytes']} 字节，权限 {qr['mode']}，box={qr['box']}）")
        lines.append(f"  二维码 SHA-256 {qr['sha256']}")
    return "\n".join(lines)


def render_list(payload: Dict[str, Any]) -> str:
    lines = [
        f"数据目录 {payload['data_dir']}",
        f"控制端口区间 {payload['ws_port_range'][0]}-{payload['ws_port_range'][1]}；"
        f"CLI 二进制 {payload['cli_bin_path']}"
        + ("" if payload["cli_present"] else "（未安装：生命周期操作将降级为离线）"),
    ]
    if not payload["bots"]:
        lines.append("账本为空：还没有创建任何 Bot")
        return "\n".join(lines)
    lines.append(f"{'BOT_ID':<26} {'NAME':<16} {'PORT':<6} {'STATUS':<9} FILES  BUNDLES")
    for row in payload["bots"]:
        lines.append(
            f"{row['bot_id']:<26} {row['name']:<16} {row['port']:<6} "
            f"{row['status']:<9} {row['cli_data_files']:<6} {len(row['bundles'])}"
        )
    return "\n".join(lines)


RENDERERS = {
    "export": render_export,
    "verify": render_verify,
    "restore": render_restore,
    "list": render_list,
    "invite": render_invite,
}


# ----------------------------------------------------------------------- parser
def _add_common(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "--data-dir", default="", metavar="PATH", help="覆盖 STUDIO_DATA_DIR：Studio 数据根目录"
    )
    sub.add_argument("--env-file", default="", metavar="PATH", help="指定 .env 路径（等价 STUDIO_ENV_FILE）")
    sub.add_argument("--json", action="store_true", help="把结果作为单个 JSON 对象打印到标准输出")


def _add_passphrase(sub: argparse.ArgumentParser) -> None:
    group = sub.add_mutually_exclusive_group()
    group.add_argument(
        "--passphrase-env",
        default="",
        metavar="ENV_VAR",
        help="从该环境变量的取值读取冷备口令；export 时给出即启用 PBSB 加密（命令行不接受明文口令）",
    )
    group.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="从标准输入读取口令：TTY 关闭回显并二次确认，管道则取首行",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "POPOPX Bot Studio 离线冷备工具：导出 / 校验 / 迁移恢复 / 邀请链接生成单个 Bot 的冷备包。\n"
            "复用 app.main.build_stack 与 BotSupervisor.export_bundle/import_bundle，"
            "产物与管理后台「一键冷备」完全一致。\n"
            "invite 与 list 默认只输出 https://popopx.chat/i/v1/<密文> 隐私封装邀请链接；"
            "--raw / --raw-links 才输出原始 smp:// 地址。\n"
            "全程离线：不启动 Web 服务、不拉起 popopx-cli、不监听任何端口。"
        ),
        epilog=(
            "注意：\n"
            "  1) 导出运行中的 Bot 会先停止它（reason=backup）再打包，打包完成后自动恢复其原状态；\n"
            "     从未启动过的 Bot 同样可以导出，工具会先按标准布局补建隔离数据目录。\n"
            "  2) 口令只能来自 --passphrase-env <环境变量名> 或 --passphrase-stdin，"
            "命令行明文口令会泄漏进 ps 与 shell 历史，因此被禁止；口令内容永不打印。\n"
            "  3) --dest 指向的目录会被强制设为 0700，备份包与 .json 边车清单为 0600。\n"
            "  4) restore 只写账本与 cli-data，还原后 Bot 状态为 stopped，不会自动启动；"
            "如需拉起进程请到 Web 管理后台或 app.main。\n"
            "  5) 还原是幂等的：同一冷备包反复 --into 同一个 Bot 只会得到同一套规则"
            "（自动回复按 (bot, trigger, pattern) upsert，路由按内容指纹跳过已有行）。"
            "--replace-rules 用于相反的需求：清掉目标 Bot 上「包里已经没有」的旧规则。\n"
            "退出码：0 成功 / 1 运行错误 / 2 用法错误 / 3 Bot 不存在 / 4 Bot 已删除 / "
            "5 输出目录不可写 / 6 备份包损坏或校验失败 / 7 口令缺失或错误 / 8 账本错误"
        ),
    )
    parser.add_argument("--list", action="store_true", help="列出账本中的 Bot 及端口（等价于 list 子命令）")
    parser.add_argument("--version", action="store_true", help="打印版本后退出")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_export = sub.add_parser("export", help="导出一个 Bot 的冷备包", formatter_class=argparse.RawDescriptionHelpFormatter)
    p_export.add_argument(
        "--bot", required=True, metavar="ID|NAME|PORT", help="Bot id、Bot 名称或控制端口（三者之一）"
    )
    p_export.add_argument(
        "--dest", default="", metavar="DIR", help="输出目录，默认 <数据目录>/backups；目录会被 chmod 0700"
    )
    _add_passphrase(p_export)
    p_export.add_argument(
        "--no-verify",
        dest="verify",
        action="store_false",
        help="导出后跳过完整性校验（默认执行逐成员 SHA-256 校验）",
    )
    p_export.set_defaults(verify=True)
    _add_common(p_export)

    p_list = sub.add_parser("list", help="列出账本中的 Bot、端口与既有备份包")
    p_list.add_argument("--all", action="store_true", help="同时列出 status=deleted 的 Bot")
    p_list.add_argument(
        "--raw-links",
        dest="raw_links",
        action="store_true",
        help="额外输出原始 smp:// 永久地址与 SMP 节点列表（高级诊断；默认只给隐私封装邀请链接）",
    )
    _add_common(p_list)

    p_invite = sub.add_parser(
        "invite", help="生成 Bot 隐私封装邀请链接与可选二维码", formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p_invite.add_argument(
        "--bot", required=True, metavar="ID|NAME|PORT", help="Bot id、Bot 名称或控制端口（三者之一）"
    )
    p_invite.add_argument(
        "--raw",
        action="store_true",
        help="输出原始 smp:// 协议地址（高级诊断；会暴露 SMP 节点域名与集群拓扑）",
    )
    p_invite.add_argument("--qr", default="", metavar="PATH", help="同时把二维码写成 PNG（文件权限 0600）")
    p_invite.add_argument("--box", type=int, default=8, metavar="N", help="二维码像素倍率，默认 8")
    _add_common(p_invite)

    p_verify = sub.add_parser("verify", help="非破坏式校验既有冷备包的完整性")
    p_verify.add_argument("bundle", metavar="BUNDLE", help=f"冷备包路径（{PLAIN_SUFFIX} 或 {ENC_SUFFIX}）")
    _add_passphrase(p_verify)
    _add_common(p_verify)

    p_restore = sub.add_parser("restore", help="把冷备包还原（迁移）进目标数据目录的账本")
    p_restore.add_argument("bundle", metavar="BUNDLE", help="冷备包路径")
    p_restore.add_argument(
        "--into",
        default="",
        metavar="ID|NAME|PORT",
        help="还原到目标账本中已存在的 Bot；缺省时沿用包内 bot_id，不存在则新建一行",
    )
    p_restore.add_argument(
        "--new-name", default="", metavar="NAME", help="新建 Bot 时使用的基础名称（自动净化为 [a-z0-9_-]）"
    )
    _add_passphrase(p_restore)
    p_restore.add_argument(
        "--allow-unverified",
        dest="verify_first",
        action="store_false",
        help="跳过还原前的完整性校验（不推荐；默认先校验再落盘）",
    )
    p_restore.set_defaults(verify_first=True)
    p_restore.add_argument(
        "--replace-rules",
        dest="replace_rules",
        action="store_true",
        help="还原到已有 Bot 时，先删除该 Bot 现有的全部自动回复/路由规则再写入包内规则；"
        "用于让目标规则集与备份包完全一致（幂等还原不需要它），默认关闭",
    )
    _add_common(p_restore)
    return parser


COMMANDS = ("export", "list", "verify", "restore", "invite")


def normalize_argv(argv: Sequence[str]) -> List[str]:
    """把 ``--list`` 糖块翻译成 ``list`` 子命令，其余原样交给 argparse。"""
    tokens = [str(item) for item in argv]
    if "--list" not in tokens:
        return tokens
    rest = [token for token in tokens if token != "--list"]
    present = [token for token in rest if token in COMMANDS]
    if present and present[0] != "list":
        raise ToolError(f"--list 与 {present[0]} 子命令不能同时使用", code=EXIT_USAGE)
    if not present:
        rest.insert(0, "list")
    return rest


def emit_error(as_json: bool, message: str, code: int) -> None:
    """错误：人读走 stderr；``--json`` 时 stdout 也只有一个 JSON 对象。"""
    if as_json:
        print(json.dumps({"ok": False, "error": message, "exit_code": code}, ensure_ascii=False))
    print(f"错误：{message}", file=sys.stderr)


# ------------------------------------------------------------------------- main
def main(argv: Optional[Sequence[str]] = None) -> int:
    _utf8_streams()
    parser = build_parser()
    tokens = list(sys.argv[1:] if argv is None else argv)
    try:
        tokens = normalize_argv(tokens)
    except ToolError as exc:
        print(f"错误：{exc.message}", file=sys.stderr)
        return exc.code
    if not tokens:
        parser.print_help()
        return EXIT_OK
    args = parser.parse_args(tokens)
    if getattr(args, "version", False):
        print(f"{APP_NAME} {APP_VERSION} · {PROG}")
        return EXIT_OK
    command = getattr(args, "command", None)
    if command not in COMMANDS:
        parser.print_help(sys.stderr)
        print("错误：缺少子命令（export / list / verify / restore / invite）", file=sys.stderr)
        return EXIT_USAGE

    as_json = bool(args.json)
    try:
        passphrase = read_passphrase(
            str(getattr(args, "passphrase_env", "") or ""),
            bool(getattr(args, "passphrase_stdin", False)),
        )
        if command == "export":
            payload = export(
                args.bot,
                passphrase=passphrase,
                dest=args.dest or None,
                data_dir=args.data_dir or None,
                env_file=args.env_file or None,
                verify=bool(args.verify),
            )
        elif command == "list":
            payload = list_bots(
                data_dir=args.data_dir or None,
                env_file=args.env_file or None,
                include_deleted=bool(args.all),
                raw_links=bool(getattr(args, "raw_links", False)),
            )
        elif command == "invite":
            payload = invite(
                args.bot,
                raw=bool(args.raw),
                qr_path=args.qr or None,
                box_size=int(args.box),
                data_dir=args.data_dir or None,
                env_file=args.env_file or None,
            )
        elif command == "verify":
            payload = verify_bundle(Path(args.bundle).expanduser(), passphrase=passphrase)
            payload["warnings"] = list(payload["sidecar"].get("warnings") or [])
        else:
            payload = restore(
                args.bundle,
                passphrase=passphrase,
                into=args.into,
                new_name=args.new_name,
                data_dir=args.data_dir or None,
                env_file=args.env_file or None,
                verify_first=bool(args.verify_first),
                replace_rules=bool(args.replace_rules),
            )
    except ToolError as exc:
        emit_error(as_json, exc.message, exc.code)
        return exc.code
    except (BotSupervisorError, asyncio.TimeoutError) as exc:
        text = f"{type(exc).__name__}: {exc}"
        code = EXIT_BUNDLE_BAD if "备份包" in text else EXIT_RUNTIME
        emit_error(as_json, text, code)
        return code
    except LedgerError as exc:
        emit_error(as_json, f"账本操作失败 {type(exc).__name__}: {exc}", EXIT_LEDGER)
        return EXIT_LEDGER
    except OSError as exc:
        emit_error(as_json, f"文件系统操作失败 {type(exc).__name__}: {exc}", EXIT_RUNTIME)
        return EXIT_RUNTIME

    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        print(RENDERERS[payload["action"]](payload))
    for warning in payload.get("warnings") or []:
        print(f"警告：{warning}", file=sys.stderr)
    for label, mode in mode_findings(payload):
        if mode and int(mode, 8) & ~SECURE_FILE_MODE:
            print(f"警告：{label} 权限为 {mode}，应为 0{SECURE_FILE_MODE:o}", file=sys.stderr)
    if command == "verify" and not payload.get("ok"):
        # 校验失败必须以退出码表达，否则 `set -e` 的备份巡检会把坏包当成好包。
        return EXIT_BUNDLE_BAD
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
