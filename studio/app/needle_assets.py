"""Needle 3 端侧权重的本地固定资产路径、清单 pin 与 SHA-256 完整性校验。

Bot Studio 把 ``needle3.cact`` 随仓库内置在 ``studio/assets/models/``，运行期**绝不**
从任何外网地址下载权重。加载前必须先用同目录的 ``needle3.manifest.json`` 做 SHA-256
与字节数校验：清单是唯一的权威来源，``official_tools/verify_needle_assets.py`` 与本模块
共用同一份代码，因此「装完就能跑」与「CI 里能复核」看到的是同一套判定。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

ASSET_DIRNAME = "models"
MANIFEST_NAME = "needle3.manifest.json"
WEIGHT_FILE = "needle3.cact"
REQUIRED_FILES = (WEIGHT_FILE, "LICENSE-needle3.txt")
ASSET_DIR_ENV = "NEEDLE_ASSET_DIR"
MAX_WEIGHT_BYTES = 50 * 1024 * 1024  # 裁定：内置权重必须 <50MB
_CHUNK = 1024 * 1024

_MANIFEST_FIELDS = ("asset", "source", "license", "model", "files")


class NeedleAssetError(RuntimeError):
    """权重缺失、字节数或 SHA-256 与清单不符时抛出，调用方据此回退。"""


@dataclass(frozen=True)
class NeedleAsset:
    """清单里的一条文件记录。"""

    name: str
    bytes: int
    sha256: str
    path: Path
    required: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "path": str(self.path),
            "required": self.required,
        }


@dataclass(frozen=True)
class NeedleManifest:
    """``needle3.manifest.json`` 的内存表示。"""

    path: Path
    asset: str
    purpose: str
    source: Dict[str, Any]
    license: Dict[str, Any]
    model: Dict[str, Any]
    files: Dict[str, NeedleAsset]

    @property
    def weights(self) -> NeedleAsset:
        try:
            return self.files[WEIGHT_FILE]
        except KeyError as exc:  # pragma: no cover - validate_manifest 已拦截
            raise NeedleAssetError(f"清单缺少 {WEIGHT_FILE} 记录") from exc

    def attribution(self) -> str:
        return str(self.license.get("attribution") or "").strip()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "manifest": str(self.path),
            "asset": self.asset,
            "purpose": self.purpose,
            "source": dict(self.source),
            "license": dict(self.license),
            "model": dict(self.model),
            "files": {name: asset.as_dict() for name, asset in sorted(self.files.items())},
        }


def default_asset_root() -> Path:
    """内置权重目录（``studio/assets/models``），可用 ``NEEDLE_ASSET_DIR`` 覆盖。"""

    override = str(os.environ.get(ASSET_DIR_ENV) or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "assets" / ASSET_DIRNAME


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_manifest(raw: Dict[str, Any], *, origin: str) -> NeedleManifest:
    missing = [key for key in _MANIFEST_FIELDS if key not in raw]
    if missing:
        raise NeedleAssetError(f"{origin} 清单缺少字段：{missing}")
    files_raw = raw.get("files")
    if not isinstance(files_raw, dict) or not files_raw:
        raise NeedleAssetError(f"{origin} 清单 files 必须是非空对象")
    root = Path(origin).parent if origin.endswith(".json") else default_asset_root()
    assets: Dict[str, NeedleAsset] = {}
    for name, record in files_raw.items():
        clean = str(name or "").strip()
        if not clean or "/" in clean or "\\" in clean or clean.startswith("."):
            raise NeedleAssetError(f"{origin} 清单文件名非法：{name!r}")
        if not isinstance(record, dict):
            raise NeedleAssetError(f"{origin} 清单 {clean} 记录必须是对象")
        size = record.get("bytes")
        digest = str(record.get("sha256") or "").strip().lower()
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise NeedleAssetError(f"{origin} 清单 {clean} 的 bytes 无效")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise NeedleAssetError(f"{origin} 清单 {clean} 的 sha256 无效")
        assets[clean] = NeedleAsset(
            name=clean, bytes=int(size), sha256=digest, path=root / clean,
            required=clean in REQUIRED_FILES,
        )
    if WEIGHT_FILE not in assets:
        raise NeedleAssetError(f"{origin} 清单未收录 {WEIGHT_FILE}")
    asset_name = str(raw.get("asset") or "").strip()
    if asset_name != WEIGHT_FILE:
        raise NeedleAssetError(f"{origin} 清单 asset={asset_name!r}，应为 {WEIGHT_FILE!r}")
    if assets[WEIGHT_FILE].bytes > MAX_WEIGHT_BYTES:
        raise NeedleAssetError(
            f"{origin} 权重 {assets[WEIGHT_FILE].bytes} 字节超过内置上限 {MAX_WEIGHT_BYTES}"
        )
    license_raw = raw.get("license")
    if not isinstance(license_raw, dict) or not str(license_raw.get("spdx") or "").strip():
        raise NeedleAssetError(f"{origin} 清单缺少 license.spdx")
    return NeedleManifest(
        path=Path(origin),
        asset=asset_name,
        purpose=str(raw.get("purpose") or "").strip(),
        source=dict(raw.get("source") or {}),
        license=dict(license_raw),
        model=dict(raw.get("model") or {}),
        files=assets,
    )


def load_manifest(root: Optional[Path] = None) -> NeedleManifest:
    base = Path(root) if root is not None else default_asset_root()
    path = base / MANIFEST_NAME
    if not path.is_file():
        raise NeedleAssetError(f"权重清单不存在：{path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NeedleAssetError(f"权重清单无法解析：{path.name}: {exc}") from exc
    if not isinstance(raw, dict):
        raise NeedleAssetError(f"权重清单必须是对象：{path.name}")
    return validate_manifest(raw, origin=str(path))


def check_asset(asset: NeedleAsset) -> Tuple[bool, str, Dict[str, Any]]:
    """校验单条文件记录，返回 ``(ok, detail, 实测值)``。"""

    measured: Dict[str, Any] = {
        "name": asset.name,
        "expected_bytes": asset.bytes,
        "expected_sha256": asset.sha256,
        "bytes": 0,
        "sha256": "",
    }
    if not asset.path.is_file():
        return False, f"文件缺失：{asset.path}", measured
    try:
        size = asset.path.stat().st_size
    except OSError as exc:
        return False, f"无法读取 {asset.name}: {exc}", measured
    measured["bytes"] = int(size)
    if size != asset.bytes:
        return False, f"{asset.name} 字节数 {size} != 清单 {asset.bytes}", measured
    try:
        digest = sha256_file(asset.path)
    except OSError as exc:
        return False, f"{asset.name} 摘要失败: {exc}", measured
    measured["sha256"] = digest
    if digest != asset.sha256:
        return False, f"{asset.name} SHA-256 不符：{digest[:12]}… != {asset.sha256[:12]}…", measured
    return True, "ok", measured


def verify_assets(root: Optional[Path] = None, *, optional: bool = True) -> Dict[str, Any]:
    """复核整个内置权重目录，返回结构化报告（不抛异常，供 API/CLI 共用）。"""

    base = Path(root) if root is not None else default_asset_root()
    report: Dict[str, Any] = {
        "ok": False,
        "root": str(base),
        "manifest": str(base / MANIFEST_NAME),
        "weight": "",
        "weight_bytes": 0,
        "attribution": "",
        "checked": [],
        "errors": [],
    }
    try:
        manifest = load_manifest(base)
    except NeedleAssetError as exc:
        report["errors"].append(str(exc))
        return report
    report["attribution"] = manifest.attribution()
    report["weight"] = str(manifest.weights.path)
    report["weight_bytes"] = manifest.weights.bytes
    for name, asset in sorted(manifest.files.items()):
        if not asset.required and not optional:
            continue
        ok, detail, measured = check_asset(asset)
        report["checked"].append({**measured, "ok": ok, "required": asset.required, "detail": detail})
        if not ok and asset.required:
            report["errors"].append(detail)
    report["ok"] = not report["errors"]
    return report


def ensure_weights(root: Optional[Path] = None) -> Path:
    """加载前门禁：权重存在且摘要匹配才返回路径，否则抛 :class:`NeedleAssetError`。"""

    base = Path(root) if root is not None else default_asset_root()
    manifest = load_manifest(base)
    asset = manifest.weights
    ok, detail, _ = check_asset(asset)
    if not ok:
        raise NeedleAssetError(detail)
    return asset.path


__all__ = [
    "ASSET_DIR_ENV",
    "MANIFEST_NAME",
    "MAX_WEIGHT_BYTES",
    "REQUIRED_FILES",
    "WEIGHT_FILE",
    "NeedleAsset",
    "NeedleAssetError",
    "NeedleManifest",
    "check_asset",
    "default_asset_root",
    "ensure_weights",
    "load_manifest",
    "sha256_file",
    "validate_manifest",
    "verify_assets",
]
