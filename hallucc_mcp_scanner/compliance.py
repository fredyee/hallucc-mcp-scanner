"""中文广告法违禁词/极限词合规检测（发布前体检场景）。

设计约束：
- 纯正则、0 LLM、单次检测 <1ms（规则在 import 时预编译）
- 词库来源：《广告法》条文明确列举 + 市场监管执法实践公开认定的极限词清单
- 五类：absolute 绝对化用语 / medical_claim 医疗功效宣称 / false_promise 虚假承诺 /
  finance_violation 金融违规承诺 / authority_abuse 权威冒用；
  另附 ai_label_check（GB 45438 AI 标识显式声明检查，第三张清单）
- 词库聚焦「高危 + 低误伤」（多用双字以上搭配，不收单字泛词），不追求大而全
  （避免陷入词库价格战）；命中即提示、由创作者定夺——只标记，不删除、不改写

本模块不判定幻觉（没有真假概念），只判定「这句话写在广告/宣传文案里
本身是否违规」。

误报哲学：中文无词边界，「第一」可能是「第一次」。因此规则分两级：
- high：条文明确列举或执法实践中基本无争议的复合词（国家级、最高级、根治…）
- medium：需要语境确认的词（独家、领先、100%…），前端展示时应与 high 分组

API 两个层次：
- check_compliance()/summarize()：结构化命中（rule_id/severity/上下文窗口），
  供三清单页分组展示与审计引用
- scan()/ai_label_check()：字典契约（word/category_label/law/advice +
  has_declaration/tips），供前端直接渲染
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ComplianceRule:
    rule_id: str          # 稳定 ID，报告/审计引用用
    category: str         # absolute | medical_claim | false_promise | finance_violation | authority_abuse
    severity: str         # "high" | "medium"
    pattern: str          # 正则（import 时编译）
    desc: str             # 命中说明
    legal_basis: str      # 法条依据
    suggestion: str       # 给创作者的可操作建议


# ──────────────────────────── 规则库 ────────────────────────────
# 绝对化用语：《广告法》第九条第(三)项禁止「国家级、最高级、最佳等用语」。
# 「等」字外延由市场监管执法实践补充，以下复合词均为公开处罚案例中高频认定词。
_ABSOLUTE_HIGH = [
    # 条文明确列举
    (r"国家级", "「国家级」为《广告法》第九条明文禁止用语"),
    (r"最高级", "「最高级」为《广告法》第九条明文禁止用语"),
    (r"最佳", "「最佳」为《广告法》第九条明文禁止用语"),
    # 执法实践高频认定（复合形态，误报率低）
    (r"(全国|全球|全世界|世界|亚洲|中国|全网|全行业|行业|销量|口碑|全网销量)(第[一1]|之首)",
     "排名类绝对化用语，处罚案例高发"),
    (r"第[一1]品牌|品牌第[一1]", "「第一品牌」类绝对化用语"),
    (r"全球领先|国际领先|全球首创|世界首创", "全球/国际范围领先地位的绝对化表述"),
    (r"顶级", "「顶级」属绝对化用语（执法实践认定）"),
    (r"顶尖", "「顶尖」属绝对化用语"),
    (r"极致", "「极致」属绝对化用语"),
    (r"极品", "「极品」属绝对化用语"),
    (r"绝佳", "「绝佳」属绝对化用语"),
    (r"绝无仅有|空前绝后|独一无二", "绝对化排他表述"),
    (r"(全国|全球|世界|中国|行业|全网)首家", "「首家」类绝对化用语"),
    (r"(全国|全球|世界|中国|行业|全网)唯一|唯一一[家款个]", "「唯一」类绝对化用语"),
    (r"(全网|史上|历史|全网历史)最(低|高)(价|性价比)", "「最低价」类价格绝对化表述"),
    (r"驰名商标", "《广告法》第十四条：不得将「驰名商标」字样用于广告宣传"),
    (r"万能", "「万能」属绝对化功效表述"),
    (r"永久(?:有效|使用|免费|不变)", "「永久」类绝对化承诺"),
]

_ABSOLUTE_MEDIUM = [
    # 需要语境确认的词，单独命中不一定违规，但高频出现在处罚决定书中
    (r"最先进|最新技术|最专业", "「最先进/最新技术/最专业」属绝对化倾向表述"),
    (r"最(好|优|强|受欢迎|牛|全面)", "「最X」类绝对化倾向表述（需语境确认）"),
    (r"独家(?![播出版权]剧|播)", "「独家」在授权语境外属绝对化倾向表述"),
    (r"一流", "「一流」属绝对化倾向表述（需语境确认）"),
    (r"领先(?!(于)?(对手|同行))", "「领先」类表述需可证明，否则有风险"),
    (r"首选(品牌|产品|商家)", "「首选」类绝对化倾向表述"),
    (r"王牌|旗舰级|标杆", "品牌定位绝对化倾向表述"),
    (r"领导者|领军|领航", "行业地位绝对化倾向表述"),
    (r"100\s*%|百分之百", "百分比绝对化表述（医疗功效语境下升级为高危）"),
    (r"No\.?\s*1|TOP\s*1", "英文/榜单形态的第一表述"),
]

# 医疗功效宣称：《广告法》第十六条（医疗/药品/医疗器械广告不得含有的内容）、
# 第十七条（非医疗广告不得涉及疾病治疗功能）、第十八条（保健食品）。
_MEDICAL_HIGH = [
    (r"(治愈|根治|痊愈)(率)?\s*(达|为|高达)?\s*\d+(\.\d+)?\s*%|治愈率|有效率",
     "宣称治愈率/有效率（第十六条第一款禁止）"),
    (r"根治|治愈(?!系)|药到病除|包治百病|彻底(根治|治愈|消除)|断根",
     "功效断言/保证（第十六条第一款禁止）"),
    (r"无效退款|无效全额退款|不好(用)?退款", "变相功效保证"),
    (r"(无任何|零|完全无|绝无)副作用|无副作用|绝对安全|安全无毒",
     "安全性断言/保证（第十六条第一款禁止）"),
    (r"特效|神效|奇效|奇效良方", "夸大疗效表述"),
    (r"(专家|医生|医师|患者|名医|教授|院士)(实名)?(推荐|证明|代言|力荐|亲测)",
     "利用专业身份/患者名义作推荐证明（第十六条第四款禁止）"),
    (r"替代(药物|药品|药物治疗)|代替(药物|药品)|可以停药|停用(药物|胰岛素)",
     "保健食品/非药品宣称替代药物（第十八条禁止）"),
    (r"(防癌|抗癌|抗肿瘤|预防癌症|治疗糖尿病|降血压|降血糖|降血脂|治疗高血压)",
     "非医疗广告宣称疾病预防/治疗功能（第十七条禁止）"),
    (r"祖传秘方|宫廷秘方|秘制配方", "无法验证的秘方宣称（功效保证类）"),
    (r"(提高免疫力|增强免疫)(?!力相关)|抗病毒|杀(灭)?菌率\s*\d+",
     "食品/日用品宣称医疗级功效（需语境复核）"),
]

_MEDICAL_MEDIUM = [
    (r"调理(身体|体质|肠胃)|排毒|清宿便|祛湿寒", "保健功效暗示表述"),
    (r"养生(功效|疗效)|延年益寿", "保健功效暗示表述"),
    (r"临床(验证|证明|证实)", "「临床验证」宣称需有真实临床试验支撑"),
    (r"医用级|医疗级|医美级", "非医疗器械宣称医疗级别"),
]

# 虚假承诺：《广告法》第四条/第二十八条（不得含有虚假或引人误解的内容）。
_FALSE_PROMISE_HIGH = [
    (r"包过|保过|包治|包瘦|包赚|稳赚不赔|一夜暴富|躺赚|永不反弹",
     "结果承诺型表述，无法证实即构成虚假宣传"),
    (r"(七天|三天|一周|当天|立刻|立即)(瘦|见效|美白|祛斑|提分)",
     "时限+效果承诺需临床/检测数据支撑，否则构成虚假宣传"),
]
_FALSE_PROMISE_MEDIUM = [
    (r"假一赔十|不满意全退|无效退全款", "承诺类表述须有真实履约能力并留存履约凭证"),
]

# 金融违规承诺：《广告法》第二十五条（招商投资类广告不得对未来收益作保证性承诺）。
_FINANCE_HIGH = [
    (r"保本保息|保本|刚兑|无风险|零风险|稳赚|高收益无风险",
     "金融产品不得承诺保本保收益（第二十五条明令禁止）"),
    (r"内部消息|内幕信息|原始股|稳涨|必涨|荐股包赚",
     "涉嫌非法荐股/内幕交易暗示（广告法第二十五条 + 证券法）"),
]

# 权威冒用：《广告法》第九条第(二)项（不得使用国家机关名义）。
_AUTHORITY_HIGH = [
    (r"国家认证|央视推荐|央视同款|政府指定|官方指定|特供|专供|人民大会堂|国宴用酒|免检产品",
     "不得借国家机关/权威媒体名义作宣传"),
]


_RULES: list[ComplianceRule] = []


def _add(prefix: str, category: str, severity: str,
         entries: list[tuple[str, str]], legal_basis: str, suggestion: str) -> None:
    for pat, desc in entries:
        _RULES.append(ComplianceRule(
            rule_id=f"{prefix}{len(_RULES):03d}", category=category, severity=severity,
            pattern=pat, desc=desc, legal_basis=legal_basis, suggestion=suggestion,
        ))


_add("ABS-H", "absolute", "high", _ABSOLUTE_HIGH,
     "《广告法》第九条第(三)项（第十四条：驰名商标）",
     "删除或改为可举证的具体表述（如「2025 年某平台销量第 X，数据来源：XX」）")
_add("ABS-M", "absolute", "medium", _ABSOLUTE_MEDIUM,
     "《广告法》第九条第(三)项（执法实践扩展认定，需语境确认）",
     "确认是否有可举证的依据；无依据建议删除")
_add("MED-H", "medical_claim", "high", _MEDICAL_HIGH,
     "《广告法》第十六/十七/十八条",
     "医疗/药品广告中删除；非医疗广告出现疾病治疗宣称本身即违规")
_add("MED-M", "medical_claim", "medium", _MEDICAL_MEDIUM,
     "《广告法》第十六/十七条（需语境确认）",
     "确认产品资质与宣称是否匹配；食品不得宣称保健/治疗功能")
_add("FP-H", "false_promise", "high", _FALSE_PROMISE_HIGH,
     "《广告法》第四条/第二十八条（虚假或引人误解的商业宣传）",
     "结果承诺无法证实即虚假宣传，删除或改为可验证表述")
_add("FP-M", "false_promise", "medium", _FALSE_PROMISE_MEDIUM,
     "《广告法》第二十八条（需真实履约能力支撑）",
     "保留须备履约凭证，否则删除")
_add("FIN-H", "finance_violation", "high", _FINANCE_HIGH,
     "《广告法》第二十五条（+《证券法》荐股相关条款）",
     "改为风险提示语（如「历史业绩不代表未来，投资须谨慎」）；荐股暗示必须删除")
_add("AUTH-H", "authority_abuse", "high", _AUTHORITY_HIGH,
     "《广告法》第九条第(二)项",
     "不得借国家机关/权威媒体名义宣传，删除")

# import 时预编译：单次检测 <1ms 的前提
_COMPILED: list[tuple[ComplianceRule, re.Pattern]] = [
    (r, re.compile(r.pattern)) for r in _RULES
]

_CATEGORY_NAMES = {
    "absolute": "绝对化用语",
    "medical_claim": "医疗功效宣称",
    "false_promise": "虚假承诺",
    "finance_violation": "金融违规承诺",
    "authority_abuse": "权威冒用",
}
_CONTEXT_CHARS = 15  # 命中点前后截取的上下文长度

# AI 生成内容显式声明（GB 45438-2025 /《人工智能生成合成内容标识办法》简化检查）
_AI_DECLARATION = re.compile(
    r"(AI\s*生成|AI\s*创作|AI\s*辅助|人工智能生成|由\s*AI|本内容由\s*AI|AIGC|AI\s*合成|数字人|虚拟主播|AI\s*制作)",
    re.IGNORECASE,
)


@dataclass
class ComplianceHit:
    rule_id: str
    category: str
    category_name: str
    severity: str
    matched: str        # 命中的原文片段
    start: int
    end: int
    context: str        # 前后文窗口，便于人工复核
    desc: str
    legal_basis: str
    suggestion: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "category": self.category,
            "category_name": self.category_name, "severity": self.severity,
            "matched": self.matched, "start": self.start, "end": self.end,
            "context": self.context, "desc": self.desc,
            "legal_basis": self.legal_basis, "suggestion": self.suggestion,
        }


def check_compliance(text: str, categories: list[str] | None = None) -> list[ComplianceHit]:
    """检测文本中的违禁词/极限词命中。categories=None 表示全类别。

    同一规则多次命中全部上报（每处都要改）；不同规则命中同一位置属正常
    （如「100% 治愈」同时命中绝对化和功效宣称），不去重——前端按位置聚合展示。
    """
    if not text:
        return []
    allow = set(categories) if categories else None
    hits: list[ComplianceHit] = []
    for rule, rx in _COMPILED:
        if allow is not None and rule.category not in allow:
            continue
        for m in rx.finditer(text):
            s, e = m.start(), m.end()
            ctx = text[max(0, s - _CONTEXT_CHARS):s] + "【" + text[s:e] + "】" + text[e:e + _CONTEXT_CHARS]
            hits.append(ComplianceHit(
                rule_id=rule.rule_id, category=rule.category,
                category_name=_CATEGORY_NAMES[rule.category], severity=rule.severity,
                matched=text[s:e], start=s, end=e, context=ctx,
                desc=rule.desc, legal_basis=rule.legal_basis, suggestion=rule.suggestion,
            ))
    hits.sort(key=lambda h: (h.start, h.rule_id))
    return hits


def summarize(hits: list[ComplianceHit]) -> dict:
    """汇总计数，供 API 响应/三清单页头部展示。"""
    by_cat: dict[str, dict[str, int]] = {}
    for h in hits:
        c = by_cat.setdefault(h.category, {"high": 0, "medium": 0, "total": 0})
        c[h.severity] += 1
        c["total"] += 1
    return {
        "total": len(hits),
        "high": sum(1 for h in hits if h.severity == "high"),
        "medium": sum(1 for h in hits if h.severity == "medium"),
        "by_category": {
            k: {"name": _CATEGORY_NAMES[k], **v} for k, v in by_cat.items()
        },
    }


def rule_count() -> dict[str, int]:
    """规则库规模（监控/测试用，防止规则被误删）。"""
    out: dict[str, int] = {}
    for r in _RULES:
        out[r.category] = out.get(r.category, 0) + 1
    return out


# ─────────────────── API 端点与前端消费的字典契约 ───────────────────

def scan(text: str) -> dict:
    """违禁词扫描：返回 {hits, total, by_category}（API 端点与前端消费的契约）。

    hits 按文中出现顺序排列；同一 (word, category) 只报首次出现位置 + 累计次数。
    每条 hit 的 word/category_label/law/advice 是前端直接渲染的字段，
    severity/rule_id/suggestion 为审计与三清单页分组保留。
    """
    seen: dict[tuple[str, str], dict] = {}
    order: list[dict] = []
    for h in check_compliance(text):
        key = (h.matched, h.category)
        if key in seen:
            seen[key]["count"] += 1
            continue
        hit = {
            "word": h.matched,
            "category": h.category,
            "category_label": h.category_name,
            "severity": h.severity,
            "rule_id": h.rule_id,
            "law": h.legal_basis,
            "advice": h.suggestion,
            "desc": h.desc,
            "index": h.start,
            "count": 1,
        }
        seen[key] = hit
        order.append(hit)
    order.sort(key=lambda h: h["index"])
    by_category: dict[str, int] = {}
    for h in order:
        by_category[h["category_label"]] = by_category.get(h["category_label"], 0) + h["count"]
    return {"hits": order, "total": sum(h["count"] for h in order), "by_category": by_category}


def ai_label_check(text: str) -> dict:
    """AI 标识显式声明检查（GB 45438 简化版：只查显式文字声明，不判「AI 味」）。

    诚实边界：本函数不判断内容是否由 AI 生成（那是 AI 率检测，不可靠且非我们强项），
    只回答「稿件里有没有合规的 AI 生成声明文字」。元数据隐式标识检查留待 12 月。
    """
    m = _AI_DECLARATION.search(text)
    tips = [
        "若稿件由 AI 生成或含 AI 生成部分：《人工智能生成合成内容标识办法》（2025-09-01 施行）要求添加显式标识（如「本文由 AI 辅助生成」），平台未标识内容可被限流/处置",
        "显式标识应置于内容显著位置（开头/结尾均可），普通读者能直接看到",
        "视频/图片类内容还需检查文件元数据隐式标识（本检查暂不覆盖，12 月上线）",
    ]
    if m:
        return {"has_declaration": True, "matched": m.group(0), "tips": tips[:1]}
    return {"has_declaration": False, "matched": None, "tips": tips}
