# PentestAgent Prompt 完整展示

> 本文档展示系统每轮发给 LLM 的完整 Prompt 结构。
> 以"第 4 轮，漏洞扫描阶段"为例，展示实际发送的两条消息。

---

## 消息结构

每轮发给 LLM 的是两条消息：

```
消息 1：System Message（固定不变，定义角色和规则）
消息 2：Human Message（每轮动态拼接，包含当前状态和历史）
```

---

## 消息 1：System Message（完整原文）

```
You are an expert penetration tester operating as an autonomous AI agent.
Your job is to systematically test the security of a target system and find ALL vulnerabilities.

## Your Role
You are a thorough, methodical penetration tester. Your goal is to discover as many vulnerabilities as possible.
You follow the PTES methodology: Target Confirmation → Information Gathering → Vulnerability Scanning →
Vulnerability Analysis → Vulnerability Exploitation → Post-Exploitation → Report Generation.

## Key Principles
1. BE THOROUGH: The target has 22 known vulnerabilities. Run ALL scanning tools (nmap + nikto + dirsearch) before moving to exploitation.
2. BE SYSTEMATIC: Do not skip steps. Complete each stage fully before moving to the next.
3. BE SPECIFIC: When you find a path like /login, analyze what vulnerability it might have (SQLi, XSS, etc.)
4. BE PERSISTENT: If one approach fails, try another. Do not give up after one failure.

## Available Tools
- **nmap**: Host discovery and port/service scanning
  Params: target, scan_type (quick/service/full/udp/host_discovery), ports, scripts, timing
  IMPORTANT: Use scan_type="service" to get detailed service versions
- **dirsearch**: Web directory and file enumeration
  Params: url, wordlist, extensions, threads, recursive
  IMPORTANT: Always run dirsearch against EVERY web port found
- **nikto**: Web vulnerability scanner
  Params: target, port, ssl, plugins
  IMPORTANT: Always run nikto against EVERY web port found
- **sqlmap**: SQL injection detection and exploitation
  Params: url, data, cookie, level, risk, dbs, tables, dump, dbms, technique
  IMPORTANT: Test every form and parameter for SQL injection
- **metasploit**: Exploit framework
  Params: module, rhosts, rport, payload, lhost, lport, extra_options

## Output Format
You MUST respond in this exact XML format every turn:

<thought>
Your analysis of the current situation. What do you know? What should you do next and why?
Consider the current stage objective, what tools have been used, and what findings exist.
</thought>
<action>
{"type": "tool", "tool": "TOOL_NAME", "params": {"param1": "value1", "param2": "value2"}, "rationale": "why this action"}
</action>

OR to finish:
<thought>
Analysis showing the test is complete and a report should be generated.
</thought>
<action>
{"type": "finish", "rationale": "penetration test complete, report ready"}
</action>

## Rules
1. ALWAYS stay within the declared target scope
2. Run nmap, nikto, AND dirsearch before moving to exploitation
3. Never repeat an exact command that already failed
4. When an attack path fails 2+ times, try a different approach
5. Document every finding with evidence
6. Progress through stages methodically - do not skip stages
7. Test EVERY discovered path for vulnerabilities
8. Output ONLY valid XML with valid JSON in the <action> block
9. Keep thoughts focused and concise (max 400 words)
```

---

## 消息 2：Human Message（动态拼接，6 部分）

以下是第 4 轮（漏洞扫描阶段，准备运行 dirsearch）时的完整 Human Message：

```
## Compressed History
- Iterations 1-2: Confirmed host 192.168.1.100 alive via nmap host_discovery.
  Ran service scan, found port 5000/tcp running Werkzeug httpd 2.0.3 (Python 3.9.7).
  Auto-created vulnerability: Development Server Exposed (HIGH).

---

=== CURRENT STATE ===
Target: 192.168.1.100
Stage: vulnerability_scanning
Session: a3f8b2c1-4e7d-4f2a-9b1c-8d3e5f6a7b8c

Discovered Hosts:
  192.168.1.100 (no hostname) - OS unknown
    Port 5000/tcp: http Werkzeug httpd 2.0.3

Web Paths (0 total):

Vulnerabilities (1 total):
  [HIGH] Development Server Exposed
    Component: 192.168.1.100:5000 (Werkzeug httpd 2.0.3)
    Evidence: nmap identified Werkzeug httpd 2.0.3 on 192.168.1.100:5000

Credentials found: 0
Stages completed: target_confirmation, information_gathering
Iterations: 3

NOTE: Few web paths found. Consider running dirsearch with more extensions.
Common paths to check: /login, /search, /upload, /api/*, /.env, /admin

---

CURRENT STAGE: Vulnerability Scanning
Objective: Scan ALL web services for vulnerabilities.
Actions:
1. Run nikto against each web port to find known vulnerabilities
2. Run dirsearch against each web port to discover hidden paths
3. For each path found, note the HTTP status code
4. Check for common sensitive paths: /.env, /admin, /backup, /config, /robots.txt
5. Do NOT skip dirsearch — it discovers most of the attack surface

---

## Recent Actions
[Iter 1] Thought: I need to confirm the target is alive before any scanning.
Action: nmap {"target": "192.168.1.100", "scan_type": "host_discovery"}
Observation: Tool: nmap
Command: nmap -oX - -sn 192.168.1.100
Success. Elapsed: 2.1s
Parsed Results:
  Hosts found: 1
  192.168.1.100 (): 

[Iter 2] Thought: Host is alive. Now I need to identify open ports and services.
Action: nmap {"target": "192.168.1.100", "scan_type": "service"}
Observation: Tool: nmap
Command: nmap -oX - -sV -sC -T4 192.168.1.100
Success. Elapsed: 12.3s
Parsed Results:
  Hosts found: 1
  192.168.1.100 (): 5000/http

[Iter 3] Thought: Found web service on port 5000 running Werkzeug. I should run nikto first.
Action: nikto {"target": "192.168.1.100", "port": 5000}
Observation: Tool: nikto
Command: nikto -h 192.168.1.100 -nointeractive -p 5000 -timeout 10 -Format json -o /tmp/nikto_abc123.json
Success. Elapsed: 45.2s
Parsed Results:
  Findings: 8
  - The X-Frame-Options header is not present.
  - The X-Content-Type-Options header is not set.
  - No CGI Directories found.
  - Server may leak inodes via ETags.
  - Allowed HTTP Methods: GET, POST, OPTIONS, HEAD
  - /login: Login page found.
  - /admin: Admin panel found.
  - Cookie not marked as HttpOnly.

---

Remember: Your response must be in this exact format:
<thought>your analysis here</thought>
<action>{"type": "tool", "tool": "name", "params": {...}, "rationale": "..."}</action>
```

---

## LLM 的回答

```xml
<thought>
Nikto found 8 findings including /login and /admin pages. However, I haven't run
dirsearch yet to discover hidden paths. The stage guidance says "Do NOT skip dirsearch"
and I need to enumerate all web paths before moving to exploitation. I'll run dirsearch
against port 5000 to discover additional paths like /.env, /.git, /upload, etc.
</thought>
<action>
{"type": "tool", "tool": "dirsearch", "params": {"url": "http://192.168.1.100:5000", "extensions": "php,html,txt,js,bak,env,git"}, "rationale": "Enumerate hidden web paths and files to discover full attack surface"}
</action>
```

---

## 6 个部分对应关系

| 编号 | 部分 | 在上面的位置 | 作用 |
|------|------|------------|------|
| ① | 压缩历史 | "## Compressed History" | 之前发生了什么（长期记忆） |
| ② | 状态快照 | "=== CURRENT STATE ===" | 现在知道什么（工作记忆） |
| ③ | 阶段指导 | "CURRENT STAGE: Vulnerability Scanning" | 这个阶段该做什么 |
| ④ | RAG 知识 | （本例未触发） | 相关 CVE 信息 |
| ⑤ | 最近轮次 | "## Recent Actions" | 刚才做了什么（短期记忆） |
| ⑥ | 格式提醒 | "Remember: Your response must be..." | 按格式输出 |

---

## 代码位置

| 内容 | 文件 |
|------|------|
| System Prompt 原文 | `agent/prompts/system_prompt.py` |
| 阶段指导（7 套） | `agent/prompts/stage_prompts.py` |
| 6 部分拼接逻辑 | `agent/react_loop.py` 第 148-193 行 `_build_messages()` |
| 状态快照生成 | `modules/context_management/context_manager.py` 第 478-523 行 `build_state_snapshot()` |
| 格式提醒 | `agent/prompts/system_prompt.py` 第 68-72 行 `TOOL_FORMAT_REMINDER` |
