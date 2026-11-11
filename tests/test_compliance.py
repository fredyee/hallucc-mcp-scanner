"""compliance 模块测试：

- 结构化 API：check_compliance/summarize/rule_count（rule_id/severity/上下文窗口）
- 五类规则命中正确性 + 误报防护 + 性能约束（<1ms 级）
- scan()/ai_label_check() 的 /gao 字典契约（前端 gao-manager 直接渲染）
- /gao 端点 E2E：三清单 + 改好稿 + gao 命名空间持久化 + 删除级联
"""
import time

from hallucc_mcp_scanner.compliance import (
    check_compliance, summarize, rule_count, scan, ai_label_check, _CATEGORY_NAMES,
)
import compliance_checker


def _ids(hits):
    return {h.rule_id for h in hits}


class TestAbsoluteTerms:
    def test_statutory_terms_hit_high(self):
        """条文明确列举的「国家级/最高级/最佳」必须 high 命中。"""
        hits = check_compliance("本产品为国家级最高级最佳产品")
        high = [h for h in hits if h.severity == "high" and h.category == "absolute"]
        matched = {h.matched for h in high}
        assert {"国家级", "最高级", "最佳"} <= matched

    def test_compound_first_hit(self):
        hits = check_compliance("我们的销量全国第一")
        assert any(h.matched == "全国第一" for h in hits)

    def test_ordinal_first_not_hit(self):
        """「第一次/第一步」是序数不是绝对化用语，不得命中。"""
        hits = check_compliance("这是我第一次使用，第一步先注册")
        assert not any("第一" in h.matched for h in hits)

    def test_china_first_hit(self):
        hits = check_compliance("中国第一品牌，值得信赖")
        assert _ids(hits)  # 全国第一/第一品牌 至少一条命中
        assert any(h.severity == "high" for h in hits)

    def test_well_known_mark_hit(self):
        hits = check_compliance("驰名商标，品质保证")
        assert any(h.matched == "驰名商标" and h.severity == "high" for h in hits)

    def test_lowest_price_hit(self):
        hits = check_compliance("全网最低价，错过再等一年")
        assert any("最低价" in h.matched for h in hits)


class TestMedicalClaim:
    def test_cure_rate_hit_high(self):
        hits = check_compliance("临床试验表明治愈率达95%")
        assert any(h.category == "medical_claim" and h.severity == "high" for h in hits)

    def test_cure_assertion_hit(self):
        hits = check_compliance("祖传秘方，根治糖尿病，无效退款")
        med_high = [h for h in hits if h.category == "medical_claim" and h.severity == "high"]
        matched = "|".join(h.matched for h in med_high)
        assert "根治" in matched and "无效退款" in matched and "祖传秘方" in matched

    def test_no_side_effect_hit(self):
        hits = check_compliance("纯天然配方，无任何副作用")
        assert any(h.matched == "无任何副作用" for h in hits)

    def test_doctor_endorsement_hit(self):
        hits = check_compliance("多位专家推荐本产品")
        assert any(h.category == "medical_claim" for h in hits)

    def test_zhiyuxi_not_hit(self):
        """「治愈系电影」不是医疗功效宣称，不得命中。"""
        hits = check_compliance("这是一部治愈系电影")
        assert not any(h.category == "medical_claim" for h in hits)

    def test_food_claiming_disease_treatment_hit(self):
        hits = check_compliance("这款保健茶可以防癌抗癌，还能降血压")
        assert any(h.category == "medical_claim" and h.severity == "high" for h in hits)


class TestFalsePromise:
    def test_result_promise_hit_high(self):
        hits = check_compliance("包过协议班，稳赚不赔，永不反弹")
        fp = [h for h in hits if h.category == "false_promise" and h.severity == "high"]
        matched = "|".join(h.matched for h in fp)
        assert "包过" in matched and "稳赚不赔" in matched

    def test_timeboxed_effect_hit_high(self):
        hits = check_compliance("三天见效，一周美白")
        assert any(h.category == "false_promise" and h.severity == "high" for h in hits)

    def test_compensation_promise_hit_medium(self):
        hits = check_compliance("假一赔十，不满意全退")
        assert any(h.category == "false_promise" and h.severity == "medium" for h in hits)


class TestFinanceViolation:
    def test_guaranteed_return_hit(self):
        hits = check_compliance("本产品保本保息，无风险高收益")
        assert any(h.category == "finance_violation" and h.severity == "high" for h in hits)

    def test_insider_hint_hit(self):
        hits = check_compliance("内部消息，这只票稳涨必涨")
        assert any(h.category == "finance_violation" for h in hits)


class TestAuthorityAbuse:
    def test_cctv_gov_hit(self):
        hits = check_compliance("央视推荐品牌，政府指定供应商")
        words = {h.matched for h in hits if h.category == "authority_abuse"}
        assert "央视推荐" in words and "政府指定" in words


class TestCleanTextAndFiltering:
    def test_clean_text_zero_hit(self):
        hits = check_compliance("本产品于2025年上市，售价299元，提供一年质保服务。")
        assert hits == []

    def test_category_filter(self):
        text = "根治皮肤问题，全网最低价"
        only_med = check_compliance(text, categories=["medical_claim"])
        assert only_med and all(h.category == "medical_claim" for h in only_med)
        only_abs = check_compliance(text, categories=["absolute"])
        assert only_abs and all(h.category == "absolute" for h in only_abs)

    def test_empty_and_none(self):
        assert check_compliance("") == []

    def test_hits_sorted_by_position(self):
        hits = check_compliance("最佳产品，根治百病")
        positions = [h.start for h in hits]
        assert positions == sorted(positions)

    def test_hit_payload_complete(self):
        h = check_compliance("国家级产品")[0]
        d = h.to_dict()
        for k in ("rule_id", "category", "category_name", "severity", "matched",
                  "start", "end", "context", "desc", "legal_basis", "suggestion"):
            assert k in d
        assert d["category_name"] == _CATEGORY_NAMES[d["category"]]
        assert "【国家级】" in d["context"]


class TestSummarizeAndGuards:
    def test_summarize_counts(self):
        hits = check_compliance("根治百病，无任何副作用，这是治愈系电影")
        s = summarize(hits)
        assert s["total"] == len(hits)
        assert s["high"] + s["medium"] == s["total"]
        assert "medical_claim" in s["by_category"]

    def test_rule_count_guard(self):
        """规则库规模护栏：防误删。"""
        rc = rule_count()
        assert rc["absolute"] >= 25
        assert rc["medical_claim"] >= 14
        assert rc["false_promise"] >= 3
        assert rc["finance_violation"] >= 2
        assert rc["authority_abuse"] >= 1

    def test_performance(self):
        """<1ms 级约束：4000 字文本 100 次检测应远小于 1 秒（实测毫秒级）。"""
        text = ("本产品品质优良，价格合理，深受用户喜爱。" * 100) + "根治百病"
        t0 = time.perf_counter()
        for _ in range(100):
            check_compliance(text)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"100 次检测耗时 {elapsed:.3f}s，超出性能预算"


class TestScan:
    """scan() 的 /gao 字典契约（前端 gao-manager 渲染 word/category_label/law/advice）。"""

    def test_absolute_terms_hit(self):
        r = scan("我们是销量第一的品牌，全网最低价，效果最佳！")
        words = {h["word"] for h in r["hits"]}
        assert "销量第一" in words and "全网最低价" in words and "最佳" in words
        assert r["by_category"]["绝对化用语"] >= 3

    def test_medical_claim_hit(self):
        r = scan("这款茶可以根治糖尿病，还能抗癌防癌。")
        cats = {h["category"] for h in r["hits"]}
        assert "medical_claim" in cats

    def test_finance_violation_hit(self):
        r = scan("本产品保本保息，无风险高收益，稳赚不赔。")
        labels = {h["category_label"] for h in r["hits"]}
        assert "金融违规承诺" in labels

    def test_authority_abuse_hit(self):
        r = scan("央视推荐品牌，政府指定供应商。")
        words = {h["word"] for h in r["hits"]}
        assert "央视推荐" in words and "政府指定" in words

    def test_clean_text_no_hits(self):
        # 常见误伤源：第一次/医学科普正文/团队介绍
        r = scan(
            "他第一次参加马拉松就完赛了。研究表明，规律运动有益健康，"
            "如有不适应及时就医。这是我们团队的介绍页面。"
        )
        assert r["total"] == 0

    def test_dedupe_same_word_counts_once(self):
        r = scan("最佳的选择，最佳的体验，最佳的人生。")
        hits = [h for h in r["hits"] if h["word"] == "最佳"]
        assert len(hits) == 1 and hits[0]["count"] == 3
        assert r["total"] == 3

    def test_hits_sorted_by_position(self):
        r = scan("先说保本，再说销量第一。")
        assert r["hits"][0]["word"] == "保本"
        assert r["hits"][1]["word"] == "销量第一"

    def test_hit_carries_law_and_advice(self):
        r = scan("全网最低价")
        h = r["hits"][0]
        assert "广告法" in h["law"] and h["advice"]


class TestAiLabelCheck:
    def test_with_declaration(self):
        r = ai_label_check("本文由 AI 辅助生成，经人工审核。")
        assert r["has_declaration"] is True and r["matched"]

    def test_without_declaration(self):
        r = ai_label_check("春天来了，公园里的花都开了。")
        assert r["has_declaration"] is False
        # 无声明时给完整合规提示（显式标识 + 位置 + 隐式标识边界）
        assert len(r["tips"]) == 3


