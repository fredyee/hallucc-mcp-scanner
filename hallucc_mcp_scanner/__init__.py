"""hallucc-mcp-scanner: MCP 配置安全扫描 + 中文广告法合规词库（纯规则，零 LLM）。

HallucC（https://aihcc.cloud）开源的规则层。核心检测管线、判定器与
智能体冰墙为闭源，本包只含可独立使用的纯规则模块：

- scanner:    MCP 配置/工具描述静态安全扫描（tool poisoning / 权限过大 /
              rug pull 基线 diff / 供应链 / 明文密钥 + 权限清单盘点）
- inject_patterns: 中英双语 prompt injection 模式库（屏幕/文档/工具描述文本）
- compliance: 中文广告法违禁词/极限词检测（绝对化用语/医疗功效/虚假承诺/
              金融违规/权威冒用 + GB 45438 AI 标识显式声明检查）
"""

from .inject_patterns import (
    InjectPattern, InjectMatch, InjectionReport, PATTERNS, scan_screen_text,
)
from .scanner import (
    Finding, ScanReport, scan_config, scan_file, build_baseline, save_baseline,
    MALICIOUS_SERVERS,
)
from .compliance import (
    check_compliance, summarize, rule_count, scan as compliance_scan,
    ai_label_check,
)

__version__ = "0.1.0"

__all__ = [
    "InjectPattern", "InjectMatch", "InjectionReport", "PATTERNS", "scan_screen_text",
    "Finding", "ScanReport", "scan_config", "scan_file", "build_baseline",
    "save_baseline", "MALICIOUS_SERVERS",
    "check_compliance", "summarize", "rule_count", "compliance_scan", "ai_label_check",
    "__version__",
]
