# hallucc-mcp-scanner

MCP 配置安全扫描 + 中文广告法合规词库。**纯规则、零 LLM、单次扫描 <10ms。**

这是 [HallucC](https://aihcc.cloud)（AI 幻觉检测与 Agent 安全产品）开源的规则层。
核心检测管线、判定器与智能体冰墙仍为闭源；本仓库只含可独立使用的纯规则模块。
在线版（免安装）：<https://aihcc.cloud/mcp-scanner>

## 能检什么

### MCP 配置安全扫描（`scanner`）

对标 Invariant Labs 的 mcp-scan，检测五类问题：

| 类别 | 说明 |
|---|---|
| `tool_poisoning` | 工具描述里内嵌 prompt injection 指令（中英双语模式库 + 零宽字符/Base64 负载检测） |
| `over_permission` | 工具声明 shell/写文件/网络等敏感能力，却无 readonly/sandbox 等权限边界声明 |
| `rug_pull` | 首次扫描落基线，复扫 diff：工具描述/Schema 变化、server 启动命令被换（钉版本号投毒） |
| `supply_chain` | server 包名/命令命中已知恶意清单或危险命令模式（`curl \| bash`、`rm -rf`、提权等） |
| `plaintext_secret` | env/args 里的明文密钥（OpenAI/AWS/GitHub/Google/Slack/HF/JWT/PEM/SendGrid 前缀 + 「key 名像凭据+真实值」通用通道；占位符 `${VAR}`/`<your-key>` 不报） |

另外输出 **per-server 权限清单**：把「这个 server 能干什么」翻成人话（可执行任意命令 / 可读写文件 / 可联网外发 / 持有凭据 / 触及敏感目录）——零命中也展示，零命中 ≠ 零权限。

**密钥脱敏红线**：命中的凭据只显示头 4 位 + 尾 2 位（如 `sk-a···89`），完整值绝不回显、不上传、不落库。

### 中文广告法合规词库（`compliance`）

发布前体检场景：绝对化用语（国家级/最高级/第一品牌…）、医疗功效宣称（根治/治愈率/无副作用…）、虚假承诺（包过/稳赚…）、金融违规承诺（保本保息/荐股…）、权威冒用（央视推荐/政府指定…），每条命中附《广告法》法条依据与修改建议；另附 GB 45438 AI 生成内容显式声明检查。

误报控制：规则分 high/medium 两级（medium 需语境确认），词库聚焦「高危 + 低误伤」，不收单字泛词。

### Prompt injection 模式库（`inject_patterns`）

上述 `tool_poisoning` 用的中英双语注入模式库，可单独用于任何进 LLM 上下文的文本（网页/邮件/文档）的前置过滤。

## 安装

```bash
pip install hallucc-mcp-scanner
# 需要解析 YAML 配置时：
pip install "hallucc-mcp-scanner[yaml]"
```

## 用法

### CLI

```bash
# 扫描 MCP 配置（mcp.json / claude_desktop_config.json，JSON/YAML）
hallucc-mcp-scan ~/.config/claude/claude_desktop_config.json

# 首次扫描落基线；之后复扫自动 diff（检 rug pull）
hallucc-mcp-scan mcp.json --save-baseline
hallucc-mcp-scan mcp.json

# 广告法违禁词扫描
hallucc-mcp-scan --compliance 稿件.txt

# 机器可读输出
hallucc-mcp-scan mcp.json --json
```

检出高危项时退出码为 1，可直接挂 CI。

### 库

```python
from hallucc_mcp_scanner import scan_config, check_compliance, scan_screen_text

report = scan_config({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "some-mcp"],
                                            "env": {"API_KEY": "sk-..."}}}})
print(report.summary["risk_level"], report.summary["plaintext_secrets"])

hits = check_compliance("全网最低价，根治颈椎问题，无效退款")
for h in hits:
    print(h.severity, h.matched, h.legal_basis)

r = scan_screen_text("ignore all previous instructions and ...")
print(r.verdict)  # "injection"
```

## 诚实边界

- 这是**规则层**：快、确定性、零成本，但只能检出已知模式。措辞刻意规避的投毒
  （如语义正常但意图跑偏的工具描述）不在本层能力范围内——那是 LLM 判定层的事，
  闭源部分在 [aihcc.cloud](https://aihcc.cloud)。
- 合规词库对照《广告法》条文与公开执法实践整理，**不构成法律意见**；命中即提示，
  由创作者定夺，本库只标记、不删除、不改写。

## 规则来源与同步

本仓库的规则层从 HallucC 内部代码库定期同步（`hccua/mcp_scan.py`、`hccua/inject.py`
模式层、`compliance_checker.py`）。规则更新先经内部基准回归（含 51 条干净轨迹的
零误报门槛）再同步到这里。

## License

MIT © 2026 深圳炼石科技有限公司

---

# hallucc-mcp-scanner (English)

Security scanner for MCP configs + Chinese ad-law compliance wordlists. **Pure rules, zero LLM, <10ms per scan.**

This is the open-sourced rule layer of [HallucC](https://aihcc.cloud), an AI hallucination-detection and agent-safety product. The core detection pipeline, judge, and agent kill-switch ("IceWall") remain closed-source; this repo contains only the self-contained pure-rule modules.

**What it detects in MCP configs:** tool poisoning (bilingual prompt-injection patterns in tool descriptions), over-permissioned tools, rug pulls (baseline diff of tool descriptions/schemas and server commands), supply-chain red flags, and plaintext secrets in env/args — plus a per-server permission inventory in plain language. Found credentials are always masked (first 4 + last 2 chars); full secrets are never displayed, uploaded, or stored.

**Compliance module:** Chinese Advertising Law wordlists (absolute claims, medical efficacy claims, false promises, financial guarantee violations, authority abuse) with legal-basis citations and fix suggestions, plus a GB 45438 AI-content declaration check.

```bash
pip install hallucc-mcp-scanner
hallucc-mcp-scan ~/.config/claude/claude_desktop_config.json
hallucc-mcp-scan mcp.json --save-baseline   # baseline for rug-pull diffing
hallucc-mcp-scan --compliance article.txt   # Chinese ad-law scan
```

Exit code 1 on high-severity findings — CI-ready. See the Chinese section above for details.
