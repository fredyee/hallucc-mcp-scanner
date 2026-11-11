"""命令行入口：hallucc-mcp-scan <config> / hallucc-mcp-scan --compliance <文本文件>。

示例：
    hallucc-mcp-scan ~/.config/claude/claude_desktop_config.json
    hallucc-mcp-scan mcp.json --save-baseline        # 首次扫描落基线
    hallucc-mcp-scan mcp.json                        # 复扫自动 diff 基线（rug pull）
    hallucc-mcp-scan --compliance 稿件.txt            # 广告法违禁词扫描
    加 --json 输出机器可读结果。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .compliance import scan as compliance_scan, ai_label_check
from .scanner import scan_file, save_baseline, extract_parts

_SEV_ICON = {"high": "🔴", "medium": "🟡", "low": "⚪"}


def _print_report(report) -> None:
    s = report.summary
    print(f"风险级别: {s['risk_level'].upper()}  |  "
          f"发现 {s['total']} 项（高 {s['by_severity']['high']} / "
          f"中 {s['by_severity']['medium']} / 低 {s['by_severity']['low']}）  |  "
          f"server {s['server_count']} 个 / 工具 {s['tool_count']} 个  |  "
          f"明文密钥 {s['plaintext_secrets']} 处")
    for f in report.findings:
        icon = _SEV_ICON.get(f.severity, "⚪")
        print(f"  {icon} [{f.category}] {f.server}: {f.detail}")
        if f.raw:
            print(f"      raw: {f.raw[:120]}")
    if report.inventory:
        print("\n权限清单（这个 server 能干什么）：")
        for inv in report.inventory:
            caps = "、".join(c["label"] for c in inv["capabilities"]) or "（未检出敏感能力）"
            print(f"  · {inv['server']}: {caps}")
    if report.has_baseline and not report.baseline_changes:
        print("\n基线 diff: 无变化 ✓")
    elif not report.has_baseline:
        print("\n（无基线：--save-baseline 落基线后，复扫可检出工具描述/启动命令被换的 rug pull）")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hallucc-mcp-scan",
        description="MCP 配置安全扫描 / 中文广告法违禁词检测（纯规则，零 LLM）")
    ap.add_argument("config", nargs="?", help="MCP 配置文件（mcp.json / claude_desktop_config.json，支持 JSON/YAML）")
    ap.add_argument("--compliance", metavar="TEXT_FILE",
                    help="改为广告法违禁词扫描：传入待检文本文件路径")
    ap.add_argument("--baseline", metavar="PATH", default=None,
                    help="基线文件路径（默认 <config>.baseline.json）")
    ap.add_argument("--save-baseline", action="store_true", help="扫描后保存/更新基线")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if args.compliance:
        text = Path(args.compliance).read_text(encoding="utf-8")
        result = compliance_scan(text)
        result["ai_label"] = ai_label_check(text)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"违禁词命中 {result['total']} 处")
            for h in result["hits"]:
                print(f"  [{h['severity']}] {h['word']}（{h['category_label']}）"
                      f" ×{h['count']}  依据: {h['law']}")
                print(f"      建议: {h['advice']}")
            ai = result["ai_label_check"]
            print(f"\nAI 生成显式声明: {'已找到「' + ai['matched'] + '」' if ai['has_declaration'] else '未找到'}")
            for tip in ai["tips"]:
                print(f"  · {tip}")
        return 0 if result["total"] == 0 else 1

    if not args.config:
        ap.error("需要 MCP 配置文件路径，或用 --compliance 扫描文本")

    cfg_path = Path(args.config)
    baseline_path = Path(args.baseline) if args.baseline else cfg_path.with_suffix(cfg_path.suffix + ".baseline.json")
    report = scan_file(cfg_path, baseline_path=baseline_path if baseline_path.exists() else None)

    if args.save_baseline:
        parts = extract_parts(cfg_path.read_text(encoding="utf-8"))
        if parts:
            h = save_baseline(baseline_path, parts[0], parts[1])
            if not args.json:
                print(f"基线已保存: {baseline_path} (hash={h})")

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        _print_report(report)
    return 1 if report.summary.get("by_severity", {}).get("high", 0) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
