#!/usr/bin/env python3
# AiKey red-line guard (Claude Code hooks).
# Why: CLAUDE.md red lines must be machine-enforced, not recall-dependent —
# advisory context rules degrade with context size; hooks fire 100% of the time.
# Enforces: git discipline (no revert/stash; restore/checkout -- needs backup),
# no manual GitHub Release uploads (release.sh only), secret-leak checks.
# Refs: CLAUDE.md「Git 操作纪律（红线）」「安全与合规（红线）」「持续交付」;
#       workflow/CI/IDE/claude/principles/claude-md-authoring-spec.md (R5).
# Canonical copy: workflow/CI/IDE/claude/hooks/aikey-guard.py — repo copies are
# distributed duplicates; edit the canonical one and re-copy.
# Modes: `bash` = PreToolUse(Bash) guard; `write` = PostToolUse(Write|Edit) scan
# (secrets + .ps1 BOM + pages/ bare authMode); `session-start` = inject the
# session-memory listing so the "scan sessions/ first" protocol never relies on recall.
import json
import os
import re
import sys


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": reason,
    }))
    sys.exit(0)


def ask(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        },
    }))
    sys.exit(0)


SECRET_PATTERNS = [
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{24,}"), "Anthropic API key"),
    (re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), "API key (sk-...)"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
]


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        data = json.load(sys.stdin)
    except Exception:
        # Fail-open by design: a malformed payload must never block unrelated
        # work (CLAUDE.md: 旁路异常不影响主链路).
        sys.exit(0)
    tool_input = data.get("tool_input") or {}

    if mode == "bash":
        cmd = tool_input.get("command") or ""
        if re.search(r"\bgit\b[^|;&\n]*\b(revert|stash)\b", cmd):
            deny("红线拦截（Git 纪律）: 禁用 git revert / git stash——多会话并发时会误伤其他会话的 in-flight 工作。"
                 "修正错误提交请用 Edit + 新提交；确需执行请用户在终端手动操作。见 CLAUDE.md「Git 操作纪律（红线）」")
        if re.search(r"\bgit\b[^|;&\n]*(\brestore\b|\bcheckout\b[^|;&\n]*\s--(\s|$))", cmd):
            ask("慎用 git restore / git checkout -- <file>：执行前必须先备份当前工作区文件到临时目录，"
                "恢复后 diff 比对确认没抹掉其他会话的改动（CLAUDE.md Git 红线）。已备份则可放行。")
        if re.search(r"\bgh\s+release\s+(upload|create|edit|delete)\b", cmd) or \
                re.search(r"/releases/[^\s]*/assets", cmd):
            deny("红线拦截（交付完整性）: 物理禁止手工上传/修改 GitHub Release，必须走 release.sh 统一发布流程；"
                 "确需手工操作需用户授权并在终端自行执行。见 CLAUDE.md「持续交付」红线条目")
        for pat, name in SECRET_PATTERNS:
            if pat.search(cmd):
                ask(f"红线检查（安全）: 命令中疑似包含 {name} 明文。密钥严禁提交/暴露/写入代码，"
                    "测试请用 .env + .gitignore。请确认必要且不会泄露后再放行。")
        sys.exit(0)

    if mode == "write":
        path = tool_input.get("file_path") or ""
        if path.rsplit("/", 1)[-1].endswith(".env"):
            # .env is the sanctioned local-key location (must stay gitignored).
            sys.exit(0)
        content = (tool_input.get("content") or "") + "\n" + (tool_input.get("new_string") or "")
        for pat, name in SECRET_PATTERNS:
            if pat.search(content):
                print(f"红线警告（安全）: 疑似 {name} 明文写入 {path}。密钥严禁入库："
                      "改用 .env（确认已在 .gitignore）或密文形态；测试样例请用明显假值。"
                      "见 CLAUDE.md「安全与合规（红线）」", file=sys.stderr)
                sys.exit(2)
        # .ps1 BOM check on the file as it landed on disk (rules/powershell-encoding.md):
        # PowerShell 5.1 decodes BOM-less files with the ANSI codepage — non-ASCII
        # breaks parsing with errors pointing at unrelated lines.
        if path.endswith(".ps1") and os.path.isfile(path):
            with open(path, "rb") as f:
                raw = f.read()
            if any(b > 127 for b in raw) and not raw.startswith(b"\xef\xbb\xbf"):
                print(f"强制执行警告（PowerShell 编码）: {path} 含非 ASCII 字符但没有 UTF-8 BOM，"
                      "Windows PowerShell 5.1 会按 ANSI 代码页解码导致语法解析损坏。"
                      "请补 BOM 或改为纯 ASCII；门禁: make -f workflow/CI/Makefile check-ps1-encoding。"
                      "见 rules/powershell-encoding.md", file=sys.stderr)
                sys.exit(2)
        # pages/ bare authMode check (rules/frontend-ui.md gateway masquerade):
        # pages must use explicit discriminators, never authMode, for data scope.
        if "/pages/" in path and re.search(r"\.(ts|tsx|js|jsx|vue)$", path) and \
                re.search(r"\bauthMode\b", content):
            print(f"强制执行警告（local_bypass 伪装）: {path} 位于 pages/ 且引用了 authMode。"
                  "页面禁止用 authMode 判数据作用域/身份/后端——用显式判别器 isLocalUsageScope() / "
                  "usageApiBase / vaultBridgeApiBase / teamGateway；纯鉴权门控请移出 pages/。"
                  "护栏: no-raw-authmode-scope.test.ts。见 rules/frontend-ui.md", file=sys.stderr)
            sys.exit(2)
        sys.exit(0)

    if mode == "session-start":
        # Inject the session-memory listing (CLAUDE.md「会话记忆」protocol) so the
        # scan-before-first-reply step is guaranteed, not recall-dependent.
        root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
        for rel in ("aikeylabs/workflow/sessions", "../workflow/sessions", "workflow/sessions"):
            d = os.path.normpath(os.path.join(root, rel))
            if os.path.isdir(d):
                names = sorted(n for n in os.listdir(d) if n.endswith(".md") and n != "README.md")
                print("[aikey 会话记忆索引] 按 CLAUDE.md「会话记忆」协议：首条回复前按主题匹配下列 session，"
                      f"命中则读取 {d}/<name> 并标注「已加载 session」：")
                print(" ".join(names))
                break
        sys.exit(0)

    sys.exit(0)


main()
