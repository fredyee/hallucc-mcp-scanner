"""MCP server 静态安全扫描。

竞品对标：Invariant Labs MCP-scan（2025 年被 Snyk 收购）。

检测四类（纯规则、0 LLM）：
1. tool_poisoning  — tool description 内嵌指令模式（模式库见 inject_patterns.py）
2. over_permission — tool 含 shell/exec/write 能力但无 scope 限制声明；
   server 启动参数把整个根目录/家目录授出（broad_scope）也算过权，高危
3. rug_pull        — 首次扫描落基线，复扫 diff 告警（工具名/描述/schema hash 变化）
4. supply_chain    — server 包名/命令命中已知恶意清单；npx/uvx 未钉 semver 版本
   （@latest 等可变 tag 也算未固定）是 rug pull 入口，中危
5. plaintext_secret — env/args 里的明文密钥（占位符不报，真凭据才报；
   连接串内嵌密码 scheme://user:password@host 也算，DATABASE_URL 跑不掉）

并输出 per-server 权限清单（inventory）：把「这个 server 能干什么」翻成人话——
shell 执行 / 文件读写 / 网络外发 / 持有凭据 / 触及敏感路径 / 数据库访问。清单是报告主体，
findings 是需要修的问题；零命中时清单依然展示（零命中 ≠ 零权限）。

MCP 配置格式兼容 mcp.json / claude_desktop_config.json：
    {"mcpServers": {"name": {"command": "...", "args": [...], "env": {...}}}}
也支持直接传工具列表：
    {"tools": [{"name": "...", "description": "...", "inputSchema": {...}}]}
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .inject_patterns import scan_screen_text

# ---------- 数据结构 ----------


@dataclass
class Finding:
    """单条扫描发现。"""
    server: str          # server 名或 tool 名
    severity: str        # "high" / "medium" / "low"
    category: str        # 检测器类别
    detail: str          # 人类可读说明
    raw: str = ""        # 原始内容片段（截断到 300 字符）


@dataclass
class ScanReport:
    """扫描结果。"""
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    config_hash: str = ""     # 当前配置的指纹（下次 diff 的参照物；非基线文件 hash）
    has_baseline: bool = False  # 是否找到已有基线
    baseline_changes: list[str] = field(default_factory=list)
    # 由 scan_config/scan_file 在扫描时填入（_recompute_summary 拿不到原始配置）
    tool_count: int = 0      # 本次配置中提取到的工具总数
    server_count: int = 0    # 本次配置中提取到的 server 总数
    # B1 权限清单： [{server, capabilities: [{id, label, evidence}]}]
    inventory: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.summary:
            self._recompute_summary()

    def add(self, f: Finding) -> None:
        self.findings.append(f)
        self._recompute_summary()

    def _recompute_summary(self) -> None:
        by_sev = {"high": 0, "medium": 0, "low": 0}
        by_cat: dict[str, int] = {}
        poisoned: set[str] = set()
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
            if f.category == "tool_poisoning":
                poisoned.add(f.server)
        if by_sev["high"] > 0:
            risk = "high"
        elif by_sev["medium"] > 0:
            risk = "medium"
        else:
            risk = "low"
        self.summary = {
            "total": len(self.findings),
            "by_severity": by_sev,
            "by_category": by_cat,
            "risk_level": risk,
            # 语义修正（2026-10-04）：tool_count/poisoned_tools 原来数的是 finding 条数，
            # 与字段名承诺的「工具数」不符（一个工具可命中多条 finding）。现在
            # tool_count=实际扫描工具数，poisoned_tools=去重后的中毒工具数。
            "tool_count": self.tool_count,
            "server_count": self.server_count,
            "poisoned_tools": len(poisoned),
            "rug_pull_changes": len(self.baseline_changes),
            # B1：明文密钥命中数单列（最易懂、最能驱动转化的一项）
            "plaintext_secrets": by_cat.get("plaintext_secret", 0),
        }

    def to_dict(self) -> dict:
        return {
            "findings": [{"server": f.server, "severity": f.severity,
                          "category": f.category, "detail": f.detail, "raw": f.raw}
                         for f in self.findings],
            "summary": self.summary,
            "config_hash": self.config_hash,
            "has_baseline": self.has_baseline,
            "baseline_changes": self.baseline_changes,
            "inventory": self.inventory,
        }


# ---------- 已知恶意 MCP server 清单 ----------

# 小清单 + 可追加。匹配 server 名或 command。
MALICIOUS_SERVERS: dict[str, str] = {
    "evil-mcp-server": "已知恶意：尝试窃取环境变量",
    "data-exfil-mcp": "已知恶意：数据外泄工具",
    "backdoor-mcp": "已知恶意：后门工具",
    "credential-stealer": "已知恶意：凭据窃取器",
    "malicious-mcp": "已知恶意：通用恶意标记",
}

# command/args 中常见危险模式
_DANGEROUS_COMMAND_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(curl|wget)\b.*\|\s*(bash|sh|python)"), "命令管道执行远程脚本"),
    (re.compile(r"\brm\s+-[rf]"), "命令含递归强制删除"),
    (re.compile(r"\b(sudo|su)\b"), "命令含提权"),
    (re.compile(r"mkfs|dd\s+of=/dev/"), "命令含格式化/写设备"),
]

# 授权范围过大的路径参数：把整个根目录/家目录交给 MCP server（最经典的过权配置）。
# 只做「独立 token / --flag=value」精确匹配，不匹配子串——否则 https://…、
# /usr/bin/python 之类正常参数全被误伤。
_BROAD_PATH_EXACT = {"/", "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%",
                     "/root", "/home", "/Users"}
_DRIVE_ROOT_RE = re.compile(r"(?i)^[A-Z]:[\\/]?$")


def _broad_path_args(args: list) -> list[str]:
    """返回 args 里授权范围过大的路径参数（原样保留，用于报告）。"""
    hits: list[str] = []
    for a in args:
        s = str(a).strip()
        val = s.split("=", 1)[1].strip() if s.startswith("--") and "=" in s else s
        if val in _BROAD_PATH_EXACT or _DRIVE_ROOT_RE.match(val):
            hits.append(s)
    return hits


# npx/uvx/bunx 启动器：包名无 @版本（或 @latest 等可变 tag）= 每次启动重新解析
# registry 最新包——rug pull 最经典的入口（包易主/投毒后无需改配置即命中）。
# 只有 semver 钉版（@1.4.2）才算固定。docker 镜像 tag 同理，待后续覆盖。
_PKG_RUNNERS = {"npx", "uvx", "bunx"}
_PKG_NAME_RE = re.compile(
    r"^(@[a-zA-Z0-9._~-]+/)?[a-zA-Z0-9._~-]+(@(?P<ver>[a-zA-Z0-9._~+-]+))?$")
_SEMVER_PIN_RE = re.compile(r"^\d+(\.\d+){0,2}([-+][a-zA-Z0-9.-]+)?$")


def _unpinned_package(command: str, args: list) -> str | None:
    """npx/uvx 启动且首个包参数未钉 semver 版本时返回该包名，否则 None。

    只判定首个非选项参数（npx 解析的对象）：本地路径/URL 等非 registry 包不算；
    其后参数是传给 server 自身的，与版本固定无关。
    """
    cmd_base = command.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    for suffix in (".cmd", ".exe", ".bat"):
        if cmd_base.endswith(suffix):
            cmd_base = cmd_base[: -len(suffix)]
    if cmd_base not in _PKG_RUNNERS:
        return None
    for a in args:
        s = str(a).strip()
        if not s or s.startswith("-"):
            continue
        m = _PKG_NAME_RE.match(s)
        if not m:
            return None  # 首个非选项参数不是 registry 包（本地路径/URL/脚本）
        ver = m.group("ver")
        return None if (ver and _SEMVER_PIN_RE.match(ver)) else s
    return None


# ---------- 权限过大检测 ----------

# 危险能力关键词：tool 能做这些事时需要 scope 限制声明。
# 刻意不含 file/path/directory/folder 等中性词（搜索文件 ≠ 写文件）。
_DANGEROUS_CAPABILITY_KEYWORDS = [
    "execute", "exec", "shell", "command", "run", "spawn", "subprocess",
    "write", "delete", "remove", "create", "modify", "edit",
    "install", "upgrade", "update", "configure", "setup",
    "password", "credential", "token", "secret", "key",
    "network", "http", "api", "request", "fetch",
    "system", "os", "process",
    "chmod", "chown", "sudo", "curl", "wget",
]

# scope 限制声明关键词：tool 描述含这些词时视为已声明权限边界
_SCOPE_LIMIT_KEYWORDS = [
    "readonly", "read-only", "read only", "limited", "restricted",
    "scoped", "sandbox", "sandboxed", "isolated", "safe",
    "whitelist", "allowlist", "blocked", "denied",
    "confirmation", "confirm", "approval", "approve",
    "user", "explicit", "manual",
]


# ---------- 明文密钥检测（B1） ----------

# 已知密钥形态前缀（无论 key 名叫什么都报）。宁严勿宽：这些是各厂商固定格式，
# 误报率极低；通用「key 名+可疑值」通道单独走 _SECRET_KEY_RE + 占位符排除。
_SECRET_VALUE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"), "OpenAI 项目密钥（sk-proj-…）"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI/DeepSeek 兼容密钥（sk-…）"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key（AKIA…）"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "AWS 临时凭据（ASIA…）"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "GitHub Token（gh*_…）"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GitHub PAT（github_pat_…）"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API Key（AIza…）"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack Token（xox*-…）"),
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "HuggingFace Token（hf_…）"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "内联私钥（PEM 块）"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
     "内联 JWT（三段式 token）"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "SendGrid Key（SG.…）"),
]

# key 名像凭据（env 变量名/args 选项名）
_SECRET_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|credential|private[_-]?key|access[_-]?key)")

# 占位符：key 名像凭据但值明显是占位时不报（控制误报——MCP 配置里占位符很常见）
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(\s*|\$\{[^}]*\}|\$\([^)]*\)|<[^>]*>|x+|\*+|your[_-].+|change[_-]?me|"
    r"todo|none|null|placeholder|example|sample|test|redacted|env:.*|"
    r"\.\.\.|…)$")

# 连接串内嵌密码（scheme://user:password@host）：key 名不含 password/secret 也跑不掉
# （DATABASE_URL/REDIS_URL 之类是凭据泄露最经典的形态）。密码段单设捕获组——
# 是占位符（${VAR}/<...>/xxx）时不报；无密码段（postgres://user@host）也不报。
_URI_CRED_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,31}://[^:/@\s]*:(?P<pw>[^@\s]+)@")


def _uri_cred_hit(value: str) -> re.Match | None:
    """值含连接串内嵌明文密码则返回 match；密码段是占位符不算。"""
    m = _URI_CRED_RE.search(value)
    if m and not _PLACEHOLDER_RE.match(m.group("pw").strip()):
        return m
    return None


def _mask_uri_cred(m: re.Match) -> str:
    """连接串脱敏：只掩密码段（scheme://user:***@），密码一个字符都不回显。"""
    return m.group(0)[: m.start("pw") - m.start(0)] + "***" + m.group(0)[m.end("pw") - m.start(0):]


def _mask_secret(value: str) -> str:
    """密钥脱敏：只留头 4 尾 2。报告会进截图/分享，绝不回显完整凭据。"""
    v = value.strip()
    if len(v) <= 8:
        return "***"
    return f"{v[:4]}…{v[-2:]}"


def _looks_like_secret(key_name: str, value: str) -> str | None:
    """判断 env/args 里的值是否是真凭据。返回命中原因，不是则 None。

    双通道：① 值命中已知密钥前缀（不看 key 名）；② key 名像凭据 + 值够长
    且非占位符（通用兜底）。占位符排除优先于通道②——宁可漏报不乱报。
    """
    v = value.strip()
    if not v or _PLACEHOLDER_RE.match(v):
        return None
    for pat, desc in _SECRET_VALUE_PATTERNS:
        if pat.search(v):
            return desc
    if _uri_cred_hit(v):
        return "连接串内嵌明文密码（scheme://user:password@host）"
    if _SECRET_KEY_RE.search(key_name) and len(v) >= 8 and not v.startswith("/"):
        return "凭据类变量含明文值"
    return None


def _scan_plaintext_secrets(servers: dict[str, Any], report: ScanReport) -> None:
    """第 5 类检测：server env 块与 args 里的明文密钥。"""
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        env = cfg.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                if not isinstance(v, str):
                    continue
                why = _looks_like_secret(str(k), v)
                if why:
                    report.add(Finding(
                        server=name, severity="high", category="plaintext_secret",
                        detail=f"环境变量 {k} 疑似明文密钥：{why}。MCP 配置常以明文落盘，"
                               "建议改用密钥管理服务或系统 keychain 引用",
                        raw=f"{k}={_mask_secret(v)}"))
        # args 里内联的 --token sk-... / 命令行拼接凭据 / 连接串密码
        args_text = " ".join(str(a) for a in cfg.get("args", []) if isinstance(a, (str, int)))
        for pat, desc in _SECRET_VALUE_PATTERNS:
            m = pat.search(args_text)
            if m:
                report.add(Finding(
                    server=name, severity="high", category="plaintext_secret",
                    detail=f"启动参数内联密钥：{desc}。命令行参数对同机进程可见"
                           "（ps 可读），建议挪到受保护的凭据存储",
                    raw=_mask_secret(m.group(0))))
        m_uri = _uri_cred_hit(args_text)
        if m_uri:
            report.add(Finding(
                server=name, severity="high", category="plaintext_secret",
                detail="启动参数内嵌连接串密码（scheme://user:password@host）。"
                       "命令行参数对同机进程可见（ps 可读），建议挪到受保护的凭据存储",
                raw=_mask_uri_cred(m_uri)))


# ---------- 权限清单盘点（B1） ----------

# 能力 id → (人话标签, 命中证据关键词)。从 command/args/env/工具描述四个来源推断。
_CAPABILITY_KEYWORDS: dict[str, tuple[str, list[str]]] = {
    "shell_exec": ("可执行任意命令", ["execute", "exec", "shell", "subprocess", "run command",
                                  "terminal", "bash", "sh -c", "执行命令", "终端"]),
    "file_write": ("可写/删文件", ["write", "delete", "remove", "create", "modify", "edit",
                               "save", "写文件", "删除", "创建文件", "修改"]),
    "file_read": ("可读文件", ["read file", "read_file", "load file", "open file", "读取文件",
                           "查看文件"]),
    "network": ("可联网外发", ["http", "https", "fetch", "request", "api", "url", "webhook",
                           "download", "upload", "curl", "wget", "联网", "请求"]),
    "credentials": ("持有凭据", []),   # 由 env key 名/连接串内嵌密码推断，不走关键词
    "sensitive_path": ("触及敏感目录", []),  # 由 args 路径推断
    "database": ("可访问数据库", []),   # 由启动包名推断，不走关键词
}

# 已知包名 → 能力映射：官方/常见 MCP server 的能力从包名即可确认，不依赖
# 工具描述关键词（filesystem server 挂根目录不该显示「未检出敏感能力」）。
_PACKAGE_CAPS: list[tuple[str, list[str]]] = [
    ("filesystem", ["file_read", "file_write"]),
    ("postgres", ["database"]),
    ("mysql", ["database"]),
    ("sqlite", ["database"]),
    ("mongo", ["database"]),
    ("redis", ["database"]),
]

_INTERPRETER_COMMANDS = {"sh", "bash", "zsh", "python", "python3", "node", "deno", "ruby"}
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(~/\.ssh|~/\.aws|~/\.config|/etc/|/root|\$HOME/\.|%USERPROFILE%)")


def _build_inventory(servers: dict[str, Any], all_tools: list[dict]) -> list[dict]:
    """生成 per-server 权限清单。证据从四个来源归并：启动命令 / 启动参数 /
    env 块 / 该 server 名下工具的描述。"""
    # 工具按 server 归组（extract_parts 已给内嵌工具打了 server 字段）
    tools_by_server: dict[str, list[dict]] = {}
    for t in all_tools:
        tools_by_server.setdefault(str(t.get("server", "")), []).append(t)

    inventory: list[dict] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", ""))
        args = " ".join(str(a) for a in cfg.get("args", []))
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        tool_text = " ".join(str(t.get("name", "")) + " " + str(t.get("description", ""))
                             for t in tools_by_server.get(name, []))
        haystack = f"{cmd} {args} {tool_text}".lower()

        caps: list[dict] = []
        cmd_base = cmd.rsplit("/", 1)[-1].lower()
        if cmd_base in _INTERPRETER_COMMANDS or any(
                kw in haystack for kw in _CAPABILITY_KEYWORDS["shell_exec"][1]):
            caps.append({"id": "shell_exec", "label": "可执行任意命令",
                         "evidence": f"启动命令 {cmd_base or cmd}" if cmd_base in _INTERPRETER_COMMANDS
                                     else "工具描述含命令执行能力"})
        if any(kw in haystack for kw in _CAPABILITY_KEYWORDS["file_write"][1]):
            caps.append({"id": "file_write", "label": "可写/删文件", "evidence": "工具描述含写/删能力"})
        if any(kw in haystack for kw in _CAPABILITY_KEYWORDS["file_read"][1]):
            caps.append({"id": "file_read", "label": "可读文件", "evidence": "工具描述含读取能力"})
        if any(kw in haystack for kw in _CAPABILITY_KEYWORDS["network"][1]) or "http" in args.lower():
            caps.append({"id": "network", "label": "可联网外发",
                         "evidence": "启动参数或工具描述含网络访问"})
        # 已知包名 → 能力（filesystem/postgres 等官方包不需要工具描述即可确认）
        have = {c["id"] for c in caps}
        pkg_text = args.lower()
        for key, cap_ids in _PACKAGE_CAPS:
            if key in pkg_text:
                for cid in cap_ids:
                    if cid not in have:
                        caps.append({"id": cid, "label": _CAPABILITY_KEYWORDS[cid][0],
                                     "evidence": f"启动包名含 {key}"})
                        have.add(cid)
        cred_keys = [str(k) for k in env if _SECRET_KEY_RE.search(str(k))]
        cred_keys += [str(k) for k, v in env.items()
                      if str(k) not in cred_keys and isinstance(v, str) and _uri_cred_hit(v)]
        if cred_keys:
            caps.append({"id": "credentials", "label": "持有凭据",
                         "evidence": f"环境变量含 {', '.join(cred_keys[:5])}"})
        if _SENSITIVE_PATH_RE.search(args):
            caps.append({"id": "sensitive_path", "label": "触及敏感目录",
                         "evidence": "启动参数引用 ~/.ssh、~/.aws 等敏感路径"})
        elif _broad_path_args(cfg.get("args", [])):
            caps.append({"id": "sensitive_path", "label": "触及敏感目录",
                         "evidence": "启动参数授权根目录/家目录"})
        inventory.append({"server": name, "capabilities": caps})
    return inventory


# ---------- 基线管理 ----------

def _compute_config_hash(servers: dict[str, Any], tools: list[dict]) -> str:
    """计算配置的指纹（server 命令/args + tool 名/描述/schema）。"""
    parts = []
    for name, cfg in sorted(servers.items()):
        cmd = cfg.get("command", "")
        args = json.dumps(sorted(cfg.get("args", [])), ensure_ascii=False)
        parts.append(f"server:{name}:{cmd}:{args}")
    for tool in sorted(tools, key=lambda t: t.get("name", "")):
        name = tool.get("name", "")
        desc = tool.get("description", "")
        schema = json.dumps(tool.get("inputSchema", {}), sort_keys=True, ensure_ascii=False)
        parts.append(f"tool:{name}:{desc}:{hashlib.sha256(schema.encode()).hexdigest()[:16]}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _tool_fingerprint(tool: dict) -> dict:
    """单个 tool 的指纹（用于 diff）。"""
    name = tool.get("name", "")
    desc = tool.get("description", "")
    schema = tool.get("inputSchema", {})
    return {
        "name": name,
        "description_hash": hashlib.sha256(desc.encode()).hexdigest()[:16],
        "schema_hash": hashlib.sha256(
            json.dumps(schema, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()[:16],
    }


def _diff_baseline(current_tools: list[dict], current_servers: dict[str, Any],
                   baseline_data: dict) -> list[dict]:
    """与基线 diff，返回变化列表 [{desc, severity}]。

    工具维度（描述/Schema/增删）severity=medium；
    server 启动命令/参数被换是典型 rug pull 手法（钉版本号投毒），severity=high。
    """
    changes: list[dict] = []
    baseline_tools = baseline_data.get("tools", [])
    baseline_map = {t["name"]: t for t in baseline_tools if "name" in t}
    current_map = {t["name"]: t for t in current_tools if "name" in t}

    # 新增工具
    for name in current_map:
        if name not in baseline_map:
            changes.append({"desc": f"新增工具: {name}", "severity": "medium"})
    # 删除工具
    for name in baseline_map:
        if name not in current_map:
            changes.append({"desc": f"移除工具: {name}", "severity": "medium"})
    # 描述/Schema 变化
    for name in current_map:
        if name in baseline_map:
            if current_map[name]["description_hash"] != baseline_map[name]["description_hash"]:
                changes.append({"desc": f"工具描述变化: {name}", "severity": "medium"})
            if current_map[name]["schema_hash"] != baseline_map[name]["schema_hash"]:
                changes.append({"desc": f"工具 Schema 变化: {name}", "severity": "medium"})

    # server 维度：基线里存了 command/args，必须参与 diff（之前只存不比，版本号
    # 替换类 rug pull 完全检不出）。
    baseline_servers = baseline_data.get("servers", {})
    for name in current_servers:
        if name not in baseline_servers:
            changes.append({"desc": f"新增 Server: {name}", "severity": "medium"})
    for name in baseline_servers:
        if name not in current_servers:
            changes.append({"desc": f"移除 Server: {name}", "severity": "medium"})
    for name, cfg in current_servers.items():
        if name not in baseline_servers or not isinstance(cfg, dict):
            continue
        base = baseline_servers[name]
        cur_cmd = cfg.get("command", "")
        cur_args = [str(a) for a in cfg.get("args", [])]
        base_args = [str(a) for a in base.get("args", [])]
        if cur_cmd != base.get("command", ""):
            changes.append({"desc": f"Server 启动命令变化: {name}"
                                    f"（{base.get('command', '')} → {cur_cmd}）",
                            "severity": "high"})
        elif sorted(cur_args) != sorted(base_args):
            old = " ".join(base_args)[:80]
            new = " ".join(cur_args)[:80]
            changes.append({"desc": f"Server 启动参数变化: {name}（{old} → {new}）",
                            "severity": "high"})
    return changes


def _load_baseline_file(baseline_path: Path) -> dict | None:
    """从文件读基线数据。文件不存在/解析失败返回 None。"""
    if not baseline_path.exists():
        return None
    try:
        return json.loads(baseline_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def build_baseline(servers: dict[str, Any], tools: list[dict]) -> dict:
    """构建基线数据（不落盘）。服务端按用户存基线时直接用。"""
    return {
        "hash": _compute_config_hash(servers, tools),
        "tools": [_tool_fingerprint(t) for t in tools],
        "servers": {name: {"command": cfg.get("command", ""),
                           "args": cfg.get("args", [])}
                    for name, cfg in servers.items()},
    }


def save_baseline(config_path: Path, servers: dict[str, Any], tools: list[dict]) -> str:
    """首次扫描后保存基线到文件。返回 baseline hash。"""
    baseline = build_baseline(servers, tools)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(baseline, indent=2, ensure_ascii=False), encoding="utf-8")
    return baseline["hash"]


# ---------- 核心扫描 ----------


def _parse_config_text(text: str) -> Any:
    """解析配置文本：先 JSON，失败再 YAML（前端 accept 已声明支持 .yaml/.yml）。
    两者都失败返回 None。"""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:  # noqa: BLE001 —— yaml 未装/解析失败都按无法识别处理
        return None


def extract_parts(config: dict | str) -> tuple[dict[str, Any], list[dict]] | None:
    """从 MCP 配置提取 (servers, tools)。解析失败返回 None。

    兼容三种输入形态：
    - {"mcpServers": {name: {command, args, env, tools?}}}   —— mcp.json / claude_desktop_config.json
    - {"tools": [...]}                                      —— 直接给工具清单
    - [{...}, {...}] 或 {"command": ...}                    —— 纯 server 列表 / 单个 server

    CLI 的 --save-baseline 也需要这一拆，故独立成公开函数。
    """
    if isinstance(config, str):
        config = _parse_config_text(config)
        if config is None:
            return None

    servers: dict[str, Any] = {}
    if isinstance(config, dict):
        servers = config.get("mcpServers", {}) or {}
    if not servers and not (isinstance(config, dict) and "tools" in config):
        if isinstance(config, list):
            servers = {str(i): item for i, item in enumerate(config) if isinstance(item, dict)}
        elif isinstance(config, dict) and "command" in config:
            servers = {"unnamed": config}

    all_tools: list[dict] = []
    if isinstance(config, dict) and isinstance(config.get("tools"), list):
        all_tools.extend(t for t in config["tools"] if isinstance(t, dict))
    for name, cfg in servers.items():
        if isinstance(cfg, dict) and isinstance(cfg.get("tools"), list):
            for t in cfg["tools"]:
                if isinstance(t, dict):
                    t = dict(t)
                    t.setdefault("server", name)
                    all_tools.append(t)

    return servers, all_tools


def scan_config(config: dict | str, baseline_path: Path | None = None,
                baseline_data: dict | None = None) -> ScanReport:
    """扫描 MCP 配置。config 可为 dict 或 JSON 字符串。

    基线二选一：baseline_path（文件，CLI 用）或 baseline_data（已加载的 dict，
    服务端按用户存储用）。都为 None 则跳过 rug pull 检测。
    """
    parts = extract_parts(config)
    if parts is None:
        report = ScanReport()
        report.add(Finding(server="(config)", severity="high", category="parse_error",
                           detail="配置解析失败：不是合法的 JSON 或 YAML"))
        return report

    servers, all_tools = parts

    report = ScanReport()
    report.tool_count = len(all_tools)
    report.server_count = len(servers)

    # 1. supply_chain: server 包名/命令恶意检测
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = cfg.get("command", "")
        args = " ".join(str(a) for a in cfg.get("args", []))
        full = f"{cmd} {args}"

        # 已知恶意清单
        for evil, desc in MALICIOUS_SERVERS.items():
            if evil.lower() in name.lower() or evil.lower() in full.lower():
                report.add(Finding(server=name, severity="high", category="supply_chain",
                                   detail=desc, raw=full[:300]))

        # 危险命令模式
        for pat, desc in _DANGEROUS_COMMAND_PATTERNS:
            if pat.search(full):
                report.add(Finding(server=name, severity="high", category="supply_chain",
                                   detail=desc, raw=full[:300]))

        # 未固定版本的包启动器（rug pull 窗口：每次启动解析 registry 最新包）
        pkg = _unpinned_package(str(cmd), cfg.get("args", []))
        if pkg:
            report.add(Finding(
                server=name, severity="medium", category="supply_chain",
                detail=f"包启动器未固定版本：{pkg} 每次启动都会解析 registry 最新包，"
                       "包被易主/投毒后无需改动配置即命中。建议钉死 semver 版本"
                       "（pkg@x.y.z），并配合基线 diff 复扫启动参数",
                raw=full[:300]))

    # 1.5 broad_scope: 启动参数把整个根目录/家目录授予 server（over_permission 高危形态）
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        broad = _broad_path_args(cfg.get("args", []))
        if broad:
            report.add(Finding(
                server=name, severity="high", category="over_permission",
                detail=f"启动参数将整个根目录/家目录（{broad[0]}）授予 server：其工具可读写"
                       "该范围内所有文件（含 ~/.ssh、~/.aws 等凭据目录），"
                       "建议收窄到具体工作目录",
                raw=" ".join(str(a) for a in cfg.get("args", []))[:300]))

    # 2. tool_poisoning: tool description 内嵌注入指令
    for tool in all_tools:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")
        if not desc:
            continue
        inj_report = scan_screen_text(desc)
        if inj_report.verdict == "injection":
            for m in inj_report.matches:
                report.add(Finding(
                    server=name, severity="high", category="tool_poisoning",
                    detail=f"工具描述含注入指令: {m.desc} [{m.pattern_id}]",
                    raw=desc[:300]))
        elif inj_report.verdict == "suspicious":
            for m in inj_report.matches:
                report.add(Finding(
                    server=name, severity="medium", category="tool_poisoning",
                    detail=f"工具描述含可疑指令: {m.desc} [{m.pattern_id}]",
                    raw=desc[:300]))

    # 3. over_permission: 能力声明无 scope 限制
    for tool in all_tools:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "").lower()
        if not desc:
            continue
        has_dangerous = any(kw in desc for kw in _DANGEROUS_CAPABILITY_KEYWORDS)
        has_scope_limit = any(kw in desc for kw in _SCOPE_LIMIT_KEYWORDS)
        if has_dangerous and not has_scope_limit:
            report.add(Finding(
                server=name, severity="medium", category="over_permission",
                detail="工具描述含敏感能力但无权限限制声明",
                raw=desc[:300]))

    # 4.5 plaintext_secret: env/args 明文密钥（B1）
    _scan_plaintext_secrets(servers, report)

    # 4.6 权限清单（B1）：零命中也输出——「它能干什么」与「检出什么问题」是两件事
    report.inventory = _build_inventory(servers, all_tools)

    # 5. rug_pull: 基线 diff（工具 + server 命令/args 两个维度）
    if baseline_data is None and baseline_path is not None:
        baseline_data = _load_baseline_file(baseline_path)
    if baseline_data is not None:
        current_fps = [_tool_fingerprint(t) for t in all_tools]
        changes = _diff_baseline(current_fps, servers, baseline_data)
        # 基线里有实质内容（工具或 server）才算「有基线」
        report.has_baseline = bool(baseline_data.get("tools") or baseline_data.get("servers"))
        if changes:
            report.baseline_changes = [c["desc"] for c in changes]
            for c in changes:
                report.add(Finding(
                    server="(baseline)", severity=c["severity"], category="rug_pull",
                    detail=f"基线变化: {c['desc']}"))
    else:
        report.has_baseline = False

    # 本次配置的指纹（作为下次 diff 的参照物落基线）
    report.config_hash = _compute_config_hash(servers, all_tools)
    report._recompute_summary()

    return report


def scan_file(path: str | Path, baseline_path: Path | None = None) -> ScanReport:
    """从文件扫描 MCP 配置。"""
    p = Path(path)
    if not p.exists():
        report = ScanReport()
        report.add(Finding(server="(file)", severity="high", category="parse_error",
                           detail=f"文件不存在: {path}"))
        return report
    try:
        config = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # 前端/CLI 声明支持 .yaml/.yml，YAML 兜底解析
        config = _parse_config_text(p.read_text(encoding="utf-8"))
        if config is None:
            report = ScanReport()
            report.add(Finding(server=str(path), severity="high", category="parse_error",
                               detail=f"配置解析失败（非合法 JSON/YAML）: {path}"))
            return report
    return scan_config(config, baseline_path)
