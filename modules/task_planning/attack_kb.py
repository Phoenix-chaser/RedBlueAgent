# -*- coding: utf-8 -*-
"""内置 ATT&CK 式渗透知识库（attack_kb）——论文驱动 [8][9]。

设计依据：
- Guided Reasoning (arXiv:2509.07939)：确定性任务树约束 LLM 推理，
  中小模型子任务完成率提升 4-5 倍、查询开销大幅下降；
- RefPentester (arXiv:2505.07089)：知识按「阶段 + 上下文」条件检索，
  注入高层（tactic/technique）与低层（可执行 action）双层知识。

与向量库 RAG 的关系：本库为零依赖的内置常开知识源（chromadb RAG
仍是可选增强）；知识精选为与本项目五工具对齐的 ATT&CK/OTG 子集，
不追求覆盖全矩阵，只求「每个建议都可被现有工具直接执行」。
"""
from __future__ import annotations

from modules.context_management.state_schema import PentestState

# ── 知识条目 ─────────────────────────────────────────────────────────────
# condition 为声明式需求标记：web=存在 HTTP 服务端口；param_url=存在
# 带参数的 URL/表单路径；db=存在数据库端口；brute_svc=存在可爆破服务。
# 占位符：{host}=目标，{url}=按上下文推导的完整 URL。

KB: dict[str, list[dict]] = {
    "target_confirmation": [
        {"tactic": "TA0043 Reconnaissance", "technique": "T1595 Active Scanning",
         "need": [], "actions": [
             {"tool": "nmap", "params": {"target": "{host}", "scan_type": "host_discovery"}},
         ]},
    ],
    "information_gathering": [
        {"tactic": "TA0043 Reconnaissance", "technique": "T1595.002 Scanning IP Blocks",
         "need": [], "actions": [
             {"tool": "nmap", "params": {"target": "{host}", "scan_type": "service"}},
         ]},
    ],
    "vulnerability_scanning": [
        {"tactic": "TA0043 Reconnaissance", "technique": "T1592 Gather Victim Host Info",
         "need": ["web"], "actions": [
             {"tool": "nikto", "params": {"target": "{url}"}},
             {"tool": "dirsearch", "params": {"url": "{url}", "extensions": "php,html,txt,js,bak,asp"}},
         ]},
    ],
    "vulnerability_analysis": [
        {"tactic": "TA0043 Reconnaissance", "technique": "T1595.003 Wordlist Scanning",
         "need": ["web"], "actions": [
             {"tool": "dirsearch", "params": {"url": "{url}", "extensions": "env,config,backup,git,bak", "recursive": False}},
         ]},
    ],
    "vulnerability_exploitation": [
        {"tactic": "TA0001 Initial Access", "technique": "T1190 Exploit Public-Facing Application",
         "need": ["param_url"], "actions": [
             {"tool": "sqlmap", "params": {"url": "{param_url}", "level": 3, "risk": 2}},
             {"tool": "sqlmap", "params": {"url": "{param_url}", "level": 5, "risk": 3, "dbs": True}},
         ]},
        {"tactic": "TA0006 Credential Access", "technique": "T1110 Brute Force",
         "need": ["brute_svc"], "actions": [
             {"tool": "nmap", "params": {"target": "{host}", "script": "brute"}},
         ]},
        {"tactic": "TA0004 Privilege Escalation", "technique": "T1210 Exploitation of Remote Services",
         "need": ["web"], "actions": [
             {"tool": "metasploit", "params": {"module": "exploit/multi/handler", "rhosts": "{host}"}},
         ]},
    ],
    "post_exploitation": [
        {"tactic": "TA0006 Credential Access", "technique": "T1005 Data from Local System",
         "need": ["param_url"], "actions": [
             {"tool": "sqlmap", "params": {"url": "{param_url}", "tables": True}},
             {"tool": "sqlmap", "params": {"url": "{param_url}", "dump": True}},
         ]},
    ],
}

_DB_PORTS = {3306, 5432, 1433, 1521, 6379, 27017, 9200, 11211}
_BRUTE_SERVICES = {"ssh", "ftp", "telnet", "smb", "ms-wbt-server", "vnc", "mysql", "postgresql"}


def _web_urls(state: PentestState) -> list[str]:
    """从已发现服务中推导 HTTP(S) URL。"""
    urls = []
    for host in state.hosts:
        for svc in host.services:
            if svc.service and any(
                k in svc.service.lower() for k in ("http", "www", "nginx", "apache", "werkzeug", "flask", "iis", "tomcat")
            ) and svc.port:
                scheme = "https" if "https" in (svc.service or "").lower() or svc.port == 443 else "http"
                urls.append(f"{scheme}://{host.ip}:{svc.port}")
    return urls


def _param_urls(state: PentestState) -> list[str]:
    """带参数的 URL 候选：显式参数样式的路径，或表单类路径。"""
    out = []
    for url in _web_urls(state):
        base = url.rstrip("/")
        for path in state.web_paths:
            p = path if path.startswith("/") else "/" + path
            if any(h in p.lower() for h in ("login", "search", "user", "form", "api", "admin")):
                out.append(f"{base}{p}?id=1")
    # 无 web_paths 时退化为根路径常见参数位
    if not out:
        for url in _web_urls(state):
            out.append(f"{url.rstrip('/')}/?id=1")
    return out[:3]


def _state_conditions(state: PentestState) -> set[str]:
    conds: set[str] = set()
    if _web_urls(state):
        conds.add("web")
    if _param_urls(state):
        conds.add("param_url")
    for host in state.hosts:
        for svc in host.services:
            if svc.port in _DB_PORTS:
                conds.add("db")
            if (svc.service or "").lower() in _BRUTE_SERVICES:
                conds.add("brute_svc")
    return conds


def suggest_actions(state: PentestState, executed_hashes: set[int] | None = None,
                    limit: int = 3) -> list[dict]:
    """按「阶段 + 上下文条件」检索可执行动作建议（RefPentester 的
    条件检索简化版：阶段 → 战术/技术 → 填充实参的动作，零依赖）。

    返回: [{hypothesis, tactic, technique, tool, params, reason}]
    已执行（哈希命中）的动作自动排除；占位符从 state 填充。
    """
    import json as _json

    executed = executed_hashes or set()
    conds = _state_conditions(state)
    urls, purls = _web_urls(state), _param_urls(state)
    out: list[dict] = []

    for entry in KB.get(state.current_stage.value, []):
        need = set(entry["need"])
        if need and not need & conds:
            continue
        for act in entry["actions"]:
            params = dict(act["params"])
            target_url = (purls[0] if act["tool"] == "sqlmap" and purls
                          else (urls[0] if urls else ""))
            params = {
                k: (v.replace("{host}", state.target)
                     .replace("{url}", target_url)
                     .replace("{param_url}", purls[0] if purls else target_url)
                    if isinstance(v, str) else v)
                for k, v in params.items()
            }
            h = hash((act["tool"], _json.dumps(params, sort_keys=True, ensure_ascii=False)))
            if h in executed:
                continue
            out.append({
                "hypothesis": f"{entry['technique']}（{entry['tactic']}）",
                "tactic": entry["tactic"],
                "technique": entry["technique"],
                "tool": act["tool"],
                "params": params,
                "reason": f"阶段={state.current_stage.value} 条件={sorted(conds) or ['always']}",
            })
            if len(out) >= limit:
                return out
    return out
