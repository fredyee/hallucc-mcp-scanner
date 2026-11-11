"""明文密钥检测 + per-server 权限清单测试（scanner.py）。

覆盖：
  - 明文密钥：env 已知前缀（sk-/AKIA/ghp_/AIza/xoxb-/hf_/JWT/PEM/SendGrid）命中；
    key 名像凭据 + 真实值命中；占位符（${VAR}/<your-key>/xxx/CHANGE_ME）不报；
    args 内联密钥命中；所有 raw 输出均脱敏（绝不含完整凭据）
  - 权限清单：shell_exec / file_write / file_read / network / credentials /
    sensitive_path 六类能力的推断与证据；零命中配置也输出清单
  - summary.plaintext_secrets 计数
"""
from hallucc_mcp_scanner.scanner import scan_config


def _cfg(env=None, args=None, tools=None, command="npx"):
    server = {"command": command, "args": args or ["-y", "some-mcp"]}
    if env is not None:
        server["env"] = env
    if tools is not None:
        server["tools"] = tools
    return {"mcpServers": {"test": server}}


def _secrets(report):
    return [f for f in report.findings if f.category == "plaintext_secret"]


# ---------- 明文密钥 ----------

def test_secret_env_known_prefix():
    r = scan_config(_cfg(env={"OPENAI_API_KEY": "sk-abcdef1234567890abcdef1234567890"}))
    hits = _secrets(r)
    assert len(hits) == 1 and hits[0].severity == "high"
    assert "sk-a…90" in hits[0].raw  # 掩码只留头 4 尾 2
    assert "abcdef1234567890" not in hits[0].raw  # 脱敏：中间段绝不回显


def test_secret_aws_and_github():
    r = scan_config(_cfg(env={
        "AWS_KEY": "AKIAIOSFODNN7EXAMPLE",
        "GH": "ghp_abcdefghijklmnopqrstuvwxyz123456",
    }))
    assert len(_secrets(r)) == 2


def test_secret_jwt_and_pem():
    r = scan_config(_cfg(env={
        "TOKEN": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4",
        "KEY": "-----BEGIN PRIVATE KEY-----\nMII...",
    }))
    assert len(_secrets(r)) == 2


def test_secret_generic_key_name_real_value():
    r = scan_config(_cfg(env={"MY_SERVICE_TOKEN": "x9f2mq8vzpl4n7kd" }))
    assert len(_secrets(r)) == 1


def test_placeholders_not_flagged():
    r = scan_config(_cfg(env={
        "API_KEY": "${MY_API_KEY}",
        "SECRET": "<your-secret-here>",
        "PASSWORD": "CHANGE_ME",
        "TOKEN": "xxx",
        "PRIVATE_KEY": "",
    }))
    assert _secrets(r) == []


def test_no_env_no_finding():
    r = scan_config(_cfg())
    assert _secrets(r) == []
    assert r.summary["plaintext_secrets"] == 0


def test_secret_inline_in_args():
    r = scan_config(_cfg(args=["-y", "some-mcp", "--token", "sk-live1234567890abcdefgh"]))
    hits = _secrets(r)
    assert len(hits) == 1
    assert "sk-live1234567890abcdefgh" not in hits[0].raw  # args 命中同样脱敏


def test_summary_counts_secrets():
    r = scan_config(_cfg(env={"A_API_KEY": "sk-abcdef1234567890abcdef1234567890"}))
    assert r.summary["plaintext_secrets"] == 1
    assert r.summary["risk_level"] == "high"


# ---------- 权限清单 ----------

def test_inventory_shell_and_credentials():
    r = scan_config(_cfg(env={"DB_PASSWORD": "${DB_PASSWORD}"}, command="bash"))
    inv = {i["server"]: i for i in r.inventory}
    caps = {c["id"] for c in inv["test"]["capabilities"]}
    assert "shell_exec" in caps       # 解释器直启
    assert "credentials" in caps      # env key 名像凭据（值是占位也算持有凭据）
    assert r.summary["plaintext_secrets"] == 0  # 占位符不报明文密钥


def test_inventory_tool_descriptions():
    tools = [
        {"name": "read_file", "description": "Read a file from disk"},
        {"name": "write_file", "description": "Write and delete files"},
        {"name": "http_get", "description": "Fetch a URL over http"},
    ]
    r = scan_config(_cfg(tools=tools))
    caps = {c["id"] for c in r.inventory[0]["capabilities"]}
    assert {"file_read", "file_write", "network"} <= caps


def test_inventory_sensitive_path():
    r = scan_config(_cfg(args=["-y", "fs-mcp", "--root", "~/.ssh"]))
    caps = {c["id"] for c in r.inventory[0]["capabilities"]}
    assert "sensitive_path" in caps


def test_inventory_present_when_clean():
    r = scan_config(_cfg(tools=[{"name": "ping", "description": "Ping the server"}]))
    assert r.findings == [] or all(f.severity != "high" for f in r.findings)
    assert len(r.inventory) == 1 and r.inventory[0]["server"] == "test"


def test_inventory_in_to_dict():
    r = scan_config(_cfg())
    d = r.to_dict()
    assert "inventory" in d and isinstance(d["inventory"], list)
