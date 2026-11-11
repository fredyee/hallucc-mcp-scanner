"""Prompt Injection 模式检测层（纯规则、零 LLM）。

攻击模型：网页/邮件/文档/工具描述中的文本进入 agent 上下文，其中藏匿的指令
被 LLM 当作用户指令执行。本模块是前置模式层：中英双语 regex 模式库 +
零宽字符/Base64 负载检测，在任何 LLM 调用之前完成过滤。

误报控制（对齐 CLAUDE.md）：单条低危模式命中只报 suspicious，不直接 injection；
critical 模式（指令覆盖/伪造确认）或 ≥2 条命中才判 injection。
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InjectPattern:
    id: str
    category: str
    severity: str            # "critical" | "high" | "low"
    regex: str
    desc: str


# ---------- 模式库（中英双语；severity 决定单条命中是否直接判 injection） ----------

PATTERNS: list[InjectPattern] = [
    # 1. 指令覆盖 —— critical：直接劫持 agent 任务
    InjectPattern("override_ignore_prev_en", "instruction_override", "critical",
                  r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(\w+\s+){0,2}(instructions?|prompts?|directions?|rules?)", "忽略先前指令"),
    InjectPattern("override_ignore_prev_zh", "instruction_override", "critical",
                  r"忽略(之前|以上|上述|先前)(的)?(所有|全部|任何)?(指令|指示|命令|任务)", "忽略先前指令(中)"),
    InjectPattern("override_disregard", "instruction_override", "critical",
                  r"(?i)disregard\s+(all\s+)?(previous|prior|your)\s+(\w+\s+){0,2}(instructions?|rules?|guidelines?|task)", "废弃先前规则"),
    InjectPattern("override_new_task", "instruction_override", "critical",
                  r"(?i)(your\s+)?(new|real|actual)\s+(task|instructions?|mission)\s*[:：是]|(new|real|actual)\s+task\s+is\b|新任务[:：]|(真实|真正)的?任务(是|[:：])", "替换任务目标"),
    InjectPattern("override_stop_task", "instruction_override", "critical",
                  r"(?i)stop\s+(working\s+on|following)\s+(your\s+)?(previous\s+)?task|停止(当前|之前|原先)的任务", "中止原任务"),

    # 2. 伪造确认/授权 —— critical：绕过 L2 人工确认
    InjectPattern("confirm_user_said_yes", "fake_confirmation", "critical",
                  r"(?i)(the\s+)?user\s+(has\s+)?(already\s+)?(confirmed|approved|agreed|said\s+yes)", "伪造用户确认"),
    InjectPattern("confirm_zh", "fake_confirmation", "critical",
                  r"用户已(经)?(确认|同意|授权)|已获得(用户)?授权|已确认无误[，,]?\s*请直接执行", "伪造用户确认(中)"),
    InjectPattern("confirm_skip", "fake_confirmation", "high",
                  r"(?i)no\s+need\s+to\s+(ask|confirm|verify)|do\s+not\s+ask\s+(the\s+)?user|无需(再次)?(确认|询问)", "诱导跳过确认"),

    # 3. 伪造系统消息 —— high
    InjectPattern("system_tag_en", "fake_system", "high",
                  r"(?i)^\s*(\[system\]|system\s*[:：]|###\s*system|<\|im_start\|>\s*system)", "伪造系统标签"),
    InjectPattern("system_zh", "fake_system", "high",
                  r"系统(消息|提示|通知)[:：].{0,30}(指令|执行|必须)", "伪造系统消息(中)"),

    # 4. 越狱/权限伪装 —— high
    InjectPattern("jailbreak_dev_mode", "jailbreak", "high",
                  r"(?i)(developer|admin|debug|god)\s+mode\s+(enabled|activated|on)|开发者模式已(开启|启用)|进入调试模式", "伪造模式切换"),
    InjectPattern("jailbreak_role", "jailbreak", "low",
                  r"(?i)you\s+are\s+now\s+(a|an)\s+|你现在是(一个|一名)", "角色重定义"),

    # 5. 数据外泄指令 —— high
    InjectPattern("exfil_send_en", "exfiltration", "high",
                  r"(?i)(send|email|upload|post|paste)\s+(the\s+)?(contents?|data|file|credentials?|api[\s_-]?keys?|passwords?)\s+.{0,40}\b(?:in)?to\b", "指令外发数据"),
    InjectPattern("exfil_send_zh", "exfiltration", "high",
                  r"(把|将).{0,20}(文件|内容|数据|密码|密钥|通讯录).{0,10}(发送|上传|发|传)(给|到)", "指令外发数据(中)"),
    InjectPattern("exfil_read_sensitive", "exfiltration", "high",
                  r"(?i)(read|open|cat|type)\s+.{0,30}(\.ssh|\.aws|id_rsa|credentials|\.env)\b|读取.{0,10}(\.ssh|密钥文件|凭证)", "指令读取敏感文件"),

    # 6. 紧迫性社工 —— low（单独命中不定罪）
    InjectPattern("urgency", "social_engineering", "low",
                  r"(?i)(immediately|urgently|right\s+now|within\s+\d+\s+minutes).{0,40}(transfer|send|pay|delete)|立即(转账|付款|删除|发送)", "紧迫性催促"),

    # 7. 间接注入载体 —— low
    InjectPattern("carrier_base64", "hidden_payload", "low",
                  r"\b[A-Za-z0-9+/]{80,}={0,2}\b", "疑似 Base64 负载"),
]

# 零宽字符（截图不可见但进上下文）：单独命中即 suspicious
_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}


@dataclass
class InjectMatch:
    pattern_id: str
    category: str
    severity: str
    desc: str
    span: tuple[int, int]


@dataclass
class InjectionReport:
    verdict: str                      # "clean" | "suspicious" | "injection"
    matches: list[InjectMatch] = field(default_factory=list)
    zero_width_count: int = 0

    @property
    def summary(self) -> str:
        if not self.matches:
            return "clean"
        return "; ".join(f"{m.desc}[{m.pattern_id}]" for m in self.matches)


def scan_screen_text(text: str, extra_patterns: list[InjectPattern] | None = None) -> InjectionReport:
    """模式层扫描屏幕文本。判定规则：
    - 有 critical 命中 → injection
    - ≥2 条命中，或 1 条 high + 零宽字符 → injection
    - 有命中 → suspicious
    """
    matches: list[InjectMatch] = []
    for p in list(PATTERNS) + list(extra_patterns or []):
        for m in re.finditer(p.regex, text, re.MULTILINE):
            matches.append(InjectMatch(p.id, p.category, p.severity, p.desc, m.span()))

    zw = sum(1 for ch in text if ch in _ZERO_WIDTH or unicodedata.category(ch) == "Cf")

    verdict = "clean"
    if matches or zw:
        verdict = "suspicious"
    if any(m.severity == "critical" for m in matches):
        verdict = "injection"
    elif len(matches) >= 2 or (any(m.severity == "high" for m in matches) and zw):
        verdict = "injection"
    return InjectionReport(verdict=verdict, matches=matches, zero_width_count=zw)


