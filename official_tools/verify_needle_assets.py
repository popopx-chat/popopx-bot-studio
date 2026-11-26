#!/usr/bin/env python3
"""POPOPX Bot Studio — 内置 Needle 3 权重完整性校验器。

按 ``studio/assets/models/needle3.manifest.json`` 逐条复核文件名、字节数与 SHA-256，
只读本地文件，绝不联网、绝不下载、绝不写盘。运行时 ``app.needle_assets`` 与
``app.needle3_runtime`` 用的是同一份判定逻辑，所以本工具的结论即等于加载门禁的结论。

用法示例::

    python3 official_tools/verify_needle_assets.py
    python3 official_tools/verify_needle_assets.py --dir /srv/studio/assets/models
    python3 official_tools/verify_needle_assets.py --json
    python3 official_tools/verify_needle_assets.py --quiet        # 只输出结论行

退出码：0=全部通过，1=清单缺失/非法，2=必需文件缺失或摘要不符，3=用法错误。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Sequence

PROG = "verify_needle_assets.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
STUDIO_DIR = REPO_ROOT / "studio"
if str(STUDIO_DIR) not in sys.path:  # 允许从仓库根目录直接运行本文件
    sys.path.insert(0, str(STUDIO_DIR))

from app.needle_assets import (  # noqa: E402  (sys.path 必须先就绪)
    ASSET_DIR_ENV,
    NeedleAssetError,
    default_asset_root,
    load_manifest,
    verify_assets,
)

EXIT_OK = 0
EXIT_BAD_MANIFEST = 1
EXIT_BAD_ASSETS = 2
EXIT_USAGE = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="校验内置 Needle 3 权重与随附文件的 SHA-256/字节数（离线、只读）。",
        epilog=f"权重目录亦可用环境变量 {ASSET_DIR_ENV} 指定。",
    )
    parser.add_argument("--dir", dest="asset_dir", default="", help="权重目录，默认 studio/assets/models")
    parser.add_argument("--json", action="store_true", help="输出机器可读的 JSON 报告")
    parser.add_argument("--quiet", "-q", action="store_true", help="只输出最后一行结论")
    parser.add_argument("--list", action="store_true", help="仅打印清单内容后退出")
    return parser


def _emit(payload: dict, *, as_json: bool, quiet: bool) -> List[str]:
    lines: List[str] = []
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return lines
    lines.append(f"清单：{payload['manifest']}")
    lines.append(f"目录：{payload['root']}")
    for record in payload["checked"]:
        mark = "OK  " if record["ok"] else "FAIL"
        lines.append(
            f"[{mark}] {record['name']:<24} {record['bytes']:>10} B  "
            f"sha256={record['sha256'][:16] or '—'}"
            + ("" if record["ok"] else f"  <- {record['detail']}")
        )
    for error in payload["errors"]:
        lines.append(f"[FAIL] {error}")
    if quiet:
        return lines[-1:]
    if payload["attribution"]:
        lines.append(f"许可：{payload['attribution']}")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    root = Path(args.asset_dir).expanduser() if args.asset_dir else default_asset_root()
    if args.list:
        try:
            manifest = load_manifest(root)
        except NeedleAssetError as exc:
            print(f"清单不可用：{exc}", file=sys.stderr)
            return EXIT_BAD_MANIFEST
        if args.json:
            print(json.dumps(manifest.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print(f"清单：{manifest.path}")
            print(f"用途：{manifest.purpose}")
            print(f"来源：{manifest.source.get('org')}/{manifest.source.get('repository')}"
                  f" @ {manifest.source.get('revision')}")
            print(f"许可：{manifest.license.get('spdx')}（{manifest.license.get('text_file')}）")
            for name, asset in sorted(manifest.files.items()):
                print(f"  {name:<24} {asset.bytes:>10} B  {asset.sha256}")
        return EXIT_OK

    report = verify_assets(root)
    for line in _emit(report, as_json=args.json, quiet=args.quiet):
        print(line)
    if args.json:
        return EXIT_OK if report["ok"] else EXIT_BAD_ASSETS
    print("结论：内置权重完整，部署后可即刻加载。" if report["ok"] else "结论：权重校验未通过，请重新内置文件。")
    if report["ok"]:
        return EXIT_OK
    return EXIT_BAD_MANIFEST if not report["checked"] else EXIT_BAD_ASSETS


if __name__ == "__main__":
    raise SystemExit(main())
