"""
ContextManager - central state management hub.
Merges tool results into PentestState and builds prompts.
"""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from modules.context_management.state_schema import (
    ActionDecision,
    HostInfo,
    LLMTurn,
    PentestState,
    ServiceInfo,
    ToolResult,
    Vulnerability,
    Severity,
    AttackPathEntry,
)
from utils.clip import clip_marked

# Spotlighting delimiting 标记（arXiv:2403.14720）：工具原始数据包裹声明。
# 配套声明见 agent/prompts/system_prompt.py 的 Rule 10——两者必须成对存在。
UNTRUSTED_OPEN = "<<<UNTRUSTED_TOOL_OUTPUT>>>"
UNTRUSTED_END = "<<<END_UNTRUSTED_TOOL_OUTPUT>>>"


class ContextManager:
    """
    Merges ToolResult data into PentestState.
    Each tool's parsed output is normalized into the shared state model.
    """

    def update(
        self,
        state: PentestState,
        thought: str,
        action: ActionDecision,
        observation: ToolResult | str,
    ) -> PentestState:
        """Record a full Think-Act-Observe cycle into state."""
        state.total_iterations += 1

        obs_str = (
            observation if isinstance(observation, str)
            else self._tool_result_to_observation(observation)
        )

        turn = LLMTurn(
            iteration=state.total_iterations,
            thought=thought,
            action_type=action.type,
            action_tool=action.tool,
            action_params=action.params,
            observation=clip_marked(obs_str, 3000),  # Cap per-turn observation with explicit marker
        )
        state.llm_turns.append(turn)

        # Merge tool results into structured state
        if isinstance(observation, ToolResult) and observation.parsed:
            self._merge_tool_result(state, observation)

        state.touch()
        return state

    def _merge_tool_result(self, state: PentestState, result: ToolResult) -> None:
        tool = result.tool.lower()
        parsed = result.parsed

        if tool == "nmap":
            self._merge_nmap(state, parsed)
        elif tool == "dirsearch":
            self._merge_dirsearch(state, parsed)
        elif tool == "nikto":
            self._merge_nikto(state, parsed, result.command)
        elif tool == "sqlmap":
            self._merge_sqlmap(state, parsed)
        elif tool == "metasploit":
            self._merge_metasploit(state, parsed, result.command)

    def _merge_nmap(self, state: PentestState, parsed: dict) -> None:
        host_index = {h.ip: h for h in state.hosts}

        # Dangerous / unencrypted services → auto-create vulns
        DANGEROUS_SERVICES = {
            "telnet":   (Severity.HIGH,     "Telnet Service Exposed",          "Unencrypted remote access protocol; credentials transmitted in cleartext."),
            "ftp":      (Severity.HIGH,     "FTP Service Exposed",             "Unencrypted file transfer protocol; credentials transmitted in cleartext."),
            "rlogin":   (Severity.CRITICAL, "rlogin Service Exposed",          "Legacy unauthenticated remote login service."),
            "rsh":      (Severity.CRITICAL, "rsh Service Exposed",             "Legacy unauthenticated remote shell service."),
            "rexec":    (Severity.CRITICAL, "rexec Service Exposed",           "Legacy unauthenticated remote execution service."),
            "vnc":      (Severity.HIGH,     "VNC Service Exposed",             "Remote desktop protocol exposed; often has weak authentication."),
            "smb":      (Severity.HIGH,     "SMB Service Exposed",             "Windows file-sharing protocol; commonly targeted for lateral movement."),
            "ms-wbt-server": (Severity.MEDIUM, "RDP Service Exposed",         "Remote Desktop Protocol exposed; susceptible to brute force."),
            "mysql":    (Severity.HIGH,     "MySQL Database Exposed",          "Database port exposed externally; risk of direct credential attacks."),
            "postgresql":(Severity.HIGH,    "PostgreSQL Database Exposed",     "Database port exposed externally; risk of direct credential attacks."),
            "mssql":    (Severity.HIGH,     "MSSQL Database Exposed",          "Database port exposed externally; risk of direct credential attacks."),
            "redis":    (Severity.CRITICAL, "Redis Service Exposed",           "Redis is often unauthenticated; full data access and RCE possible."),
            "mongodb":  (Severity.CRITICAL, "MongoDB Exposed Without Auth",    "MongoDB may allow unauthenticated access when exposed."),
            "elasticsearch": (Severity.HIGH, "Elasticsearch Exposed",         "Elasticsearch exposed without authentication; full data access risk."),
        }

        for h_data in parsed.get("hosts", []):
            if not h_data.get("ip"):
                continue
            ip = h_data["ip"]
            if ip not in host_index:
                existing = HostInfo(ip=ip)
                state.hosts.append(existing)
                host_index[ip] = existing
            else:
                existing = host_index[ip]

            existing.hostname = h_data.get("hostname") or existing.hostname
            existing.is_alive = h_data.get("state") == "up"

            if os_info := h_data.get("os"):
                existing.os = os_info.get("name")

            seen = {(s.port, s.protocol) for s in existing.services}
            for port_data in h_data.get("ports", []):
                if port_data.get("state") != "open":
                    continue
                key = (port_data["port"], port_data.get("protocol", "tcp"))
                svc_name = port_data.get("service", "unknown").lower()
                version  = port_data.get("version") or ""

                if key not in seen:
                    seen.add(key)
                    existing.services.append(ServiceInfo(
                        port=key[0],
                        protocol=key[1],
                        service=port_data.get("service", "unknown"),
                        version=version,
                        banner=port_data.get("banner"),
                        state="open",
                    ))

                # Auto-create vulnerability for dangerous services
                if svc_name in DANGEROUS_SERVICES:
                    sev, title, desc = DANGEROUS_SERVICES[svc_name]
                    component = f"{ip}:{key[0]}/{key[1]} ({svc_name} {version})".strip()
                    vuln = Vulnerability(
                        title=title,
                        severity=sev,
                        affected_component=component,
                        description=f"{desc} Version: {version or 'unknown'}",
                        evidence=f"nmap found {svc_name} open on {ip}:{key[0]}",
                        discovered_by_tool="nmap",
                    )
                    state.add_vulnerability(vuln)

                # Detect development/framework servers exposed via HTTP
                if svc_name in ("http", "http-alt", "https", "https-alt") and version:
                    version_lower = version.lower()
                    DEV_SIGNATURES = {
                        "werkzeug":    (Severity.HIGH,   "Development Server Exposed",   "Werkzeug/Flask development server exposed on the network. Development servers have no rate limiting, may enable debug mode, and are not hardened for production."),
                        "flask":       (Severity.HIGH,   "Development Server Exposed",   "Flask development server exposed on the network."),
                        "django":      (Severity.HIGH,   "Development Server Exposed",   "Django development server (runserver) exposed on the network."),
                        "tornado":     (Severity.MEDIUM, "Development Server Exposed",   "Tornado development server exposed on the network."),
                        "ruby webrick":(Severity.HIGH,   "Development Server Exposed",   "WEBrick development server exposed on the network."),
                        "thin":        (Severity.MEDIUM, "Development Server Exposed",   "Thin Ruby web server exposed on the network."),
                        "aiohttp":     (Severity.MEDIUM, "Development Server Exposed",   "aiohttp development server exposed on the network."),
                        "uvicorn":     (Severity.MEDIUM, "Development Server Exposed",   "Uvicorn ASGI server exposed directly on the network without a reverse proxy."),
                        "gunicorn":    (Severity.LOW,    "Application Server Exposed",   "Gunicorn WSGI server exposed directly on the network without a reverse proxy."),
                        "jetty":       (Severity.MEDIUM, "Jetty Server Exposed",         "Jetty application server exposed on the network."),
                        "tomcat":      (Severity.MEDIUM, "Tomcat Server Exposed",        "Apache Tomcat server exposed. Check for manager interface and default credentials."),
                        "jboss":       (Severity.HIGH,   "JBoss Server Exposed",         "JBoss application server exposed; historically vulnerable to RCE via JMXInvokerServlet."),
                        "glassfish":   (Severity.HIGH,   "GlassFish Server Exposed",     "GlassFish admin console may be accessible."),
                    }
                    for sig, (sev, title, desc) in DEV_SIGNATURES.items():
                        if sig in version_lower:
                            component = f"{ip}:{key[0]} ({version})"
                            vuln = Vulnerability(
                                title=title,
                                severity=sev,
                                affected_component=component,
                                description=f"{desc} Detected version: {version}",
                                evidence=f"nmap identified {version} on {ip}:{key[0]}",
                                discovered_by_tool="nmap",
                            )
                            state.add_vulnerability(vuln)
                            break

    def _merge_dirsearch(self, state: PentestState, parsed: dict) -> None:
        SENSITIVE_PATHS = {
            # path keyword → (severity, title, description)
            "/.env":          (Severity.HIGH,     "Environment File Exposed",        "/.env file exposed; may contain secrets, API keys, database credentials."),
            "/backup":        (Severity.HIGH,     "Backup Directory Exposed",        "Backup directory accessible; may contain source code or sensitive data."),
            "/config":        (Severity.HIGH,     "Configuration File Exposed",      "Config endpoint accessible; may leak application secrets."),
            "/.git":          (Severity.CRITICAL, "Git Repository Exposed",          "/.git directory exposed; full source code and history can be downloaded."),
            "/admin":         (Severity.MEDIUM,   "Admin Panel Accessible",          "Admin panel endpoint found; verify authentication is enforced."),
            "/phpmyadmin":    (Severity.HIGH,     "phpMyAdmin Exposed",              "phpMyAdmin found; database management interface accessible."),
            "/wp-admin":      (Severity.MEDIUM,   "WordPress Admin Panel Found",     "WordPress admin login page exposed; susceptible to brute force."),
            "/actuator":      (Severity.HIGH,     "Spring Actuator Exposed",         "Spring Boot Actuator endpoints may expose sensitive runtime information."),
            "/swagger":       (Severity.LOW,      "Swagger UI Exposed",              "API documentation exposed; reveals all endpoints and parameters."),
            "/api-docs":      (Severity.LOW,      "API Docs Exposed",                "API documentation accessible; may aid attackers in enumeration."),
            "/console":       (Severity.HIGH,     "Web Console Exposed",             "Web console (e.g. H2, Rails) found; may allow code execution."),
            "/phpinfo":       (Severity.MEDIUM,   "phpinfo() Page Exposed",          "phpinfo() output exposed; leaks PHP config, paths, and env vars."),
            "/.htaccess":     (Severity.LOW,      "htaccess File Accessible",        ".htaccess file readable; may reveal rewrite rules and access controls."),
            "/server-status": (Severity.LOW,      "Apache server-status Exposed",    "Apache mod_status page leaks active connections and request details."),
            "/robots.txt":    (Severity.INFO,     "robots.txt Discloses Paths",      "robots.txt discloses internal path structure to attackers."),
        }

        existing_paths = set(state.web_paths)
        for item in parsed.get("paths", []):
            path = item.get("path", "")
            status = item.get("status", 0)
            if path and path not in existing_paths:
                existing_paths.add(path)
                state.web_paths.append(path)

            # Create vulnerability for sensitive paths with 200/403 responses
            if status in (200, 403, 301, 302):
                path_lower = path.lower()
                for keyword, (sev, title, desc) in SENSITIVE_PATHS.items():
                    if keyword in path_lower:
                        vuln = Vulnerability(
                            title=title,
                            severity=sev,
                            affected_component=path,
                            description=desc,
                            evidence=f"dirsearch found {path} → HTTP {status}",
                            discovered_by_tool="dirsearch",
                        )
                        state.add_vulnerability(vuln)
                        break

    def _nikto_severity(self, desc: str) -> Severity:
        """Infer severity from Nikto finding description keywords."""
        d = desc.lower()
        if any(k in d for k in [
            "remote code", "rce", "command execut", "arbitrary code",
            "buffer overflow", "shell upload", "backdoor", "webshell",
            "code execut",
        ]):
            return Severity.CRITICAL
        if any(k in d for k in [
            "sql inject", "xss", "cross-site script", "file inclus",
            "directory traversal", "path traversal", "ssrf",
            "xml external", "xxe", "deserializ", "unrestricted upload",
            "remote file", "local file", "inject",
        ]):
            return Severity.HIGH
        if any(k in d for k in [
            "csrf", "clickjack", "anti-clickjack", "open redirect",
            "idor", "cookie", "session", "password", "credential",
            "htpasswd", "basic auth", "authentication", "disclosure",
            "default password", "phpinfo", "phpmyadmin",
            "admin", "backup", "config", "interesting",
        ]):
            return Severity.MEDIUM
        if any(k in d for k in [
            "header", "x-frame", "x-content", "content-security",
            "x-xss", "hsts", "strict-transport", "referrer-policy",
            "listing", "debug", "trace", "options", "methods",
            "etag", "inode", "robots", "server", "version",
            "not present", "not set", "not defined", "missing", "allowed",
        ]):
            return Severity.LOW
        return Severity.INFO

    # Canonical path → (severity, title) mirroring _merge_dirsearch's SENSITIVE_PATHS.
    # Lets _merge_nikto reuse the same titles/components so dedup with dirsearch works.
    _PATH_CANONICAL: dict = {
        "/.env":          (Severity.HIGH,     "Environment File Exposed"),
        "/backup":        (Severity.HIGH,     "Backup Directory Exposed"),
        "/config":        (Severity.HIGH,     "Configuration File Exposed"),
        "/.git":          (Severity.CRITICAL, "Git Repository Exposed"),
        "/admin":         (Severity.MEDIUM,   "Admin Panel Accessible"),
        "/phpmyadmin":    (Severity.HIGH,     "phpMyAdmin Exposed"),
        "/wp-admin":      (Severity.MEDIUM,   "WordPress Admin Panel Found"),
        "/actuator":      (Severity.HIGH,     "Spring Actuator Exposed"),
        "/swagger":       (Severity.LOW,      "Swagger UI Exposed"),
        "/api-docs":      (Severity.LOW,      "API Docs Exposed"),
        "/console":       (Severity.HIGH,     "Web Console Exposed"),
        "/phpinfo":       (Severity.MEDIUM,   "phpinfo() Page Exposed"),
        "/.htaccess":     (Severity.LOW,      "htaccess File Accessible"),
        "/server-status": (Severity.LOW,      "Apache server-status Exposed"),
        "/robots.txt":    (Severity.INFO,     "robots.txt Discloses Paths"),
    }

    # Canonical service keywords → (severity, title) mirroring _merge_nmap's DANGEROUS_SERVICES.
    _SERVICE_CANONICAL: dict = {
        "telnet":        (Severity.HIGH,     "Telnet Service Exposed"),
        "ftp":           (Severity.HIGH,     "FTP Service Exposed"),
        "rlogin":        (Severity.CRITICAL, "rlogin Service Exposed"),
        "rsh":           (Severity.CRITICAL, "rsh Service Exposed"),
        "rexec":         (Severity.CRITICAL, "rexec Service Exposed"),
        "vnc":           (Severity.HIGH,     "VNC Service Exposed"),
        "smb":           (Severity.HIGH,     "SMB Service Exposed"),
        "rdp":           (Severity.MEDIUM,   "RDP Service Exposed"),
        "mysql":         (Severity.HIGH,     "MySQL Database Exposed"),
        "postgresql":    (Severity.HIGH,     "PostgreSQL Database Exposed"),
        "mssql":         (Severity.HIGH,     "MSSQL Database Exposed"),
        "redis":         (Severity.CRITICAL, "Redis Service Exposed"),
        "mongodb":       (Severity.CRITICAL, "MongoDB Exposed Without Auth"),
        "elasticsearch": (Severity.HIGH,     "Elasticsearch Exposed"),
    }

    def _nikto_canonical(
        self, desc: str, url: str, target: str
    ) -> tuple[str, "Severity", str]:
        """
        Map a nikto finding to a canonical (title, severity, component).

        Returns the same canonical title as nmap/dirsearch so that
        add_vulnerability's dedup (with prefix matching) correctly merges
        nikto findings with those already recorded by other tools.
        Component is set to the actual URL path when available so the dedup
        prefix match works in both directions.
        """
        url_lower = url.lower()
        desc_lower = desc.lower()

        # Derive the path component from the actual URL (for dedup accuracy).
        url_path = urlparse(url).path.rstrip("/") if url else ""

        # Path-based: use same titles as _merge_dirsearch; component = actual path
        for path_key, (sev, canonical_title) in self._PATH_CANONICAL.items():
            if path_key in url_lower or path_key in desc_lower:
                # Use actual URL path when available, fall back to path_key
                component = url_path or path_key
                return canonical_title, sev, component

        # Service-based: use same titles as _merge_nmap; component = target
        for svc_key, (sev, canonical_title) in self._SERVICE_CANONICAL.items():
            if svc_key in desc_lower or svc_key in url_lower:
                return canonical_title, sev, target

        # No canonical mapping — nikto-specific finding
        return f"Nikto: {desc[:80]}", self._nikto_severity(desc), target

    def _merge_nikto(self, state: PentestState, parsed: dict, command: str) -> None:
        target = parsed.get("target") or "web server"

        # Pre-build lookup structures for O(1) attribution checks
        existing_titles = {v.title for v in state.vulnerabilities}
        _canonical_titles = (
            {title for _, title in self._PATH_CANONICAL.values()} |
            {title for _, title in self._SERVICE_CANONICAL.values()}
        )
        # Paths already found by dirsearch (for attribution)
        known_web_paths = set(state.web_paths)
        # Services already found by nmap (for attribution)
        known_services = {s.service.lower() for h in state.hosts for s in h.services}

        for finding in parsed.get("findings", []):
            desc = finding.get("description", "")
            if not desc:
                continue

            url = finding.get("url", "")
            title, sev, component = self._nikto_canonical(desc, url, target)

            # Dedup: if a canonical vuln with this title was already added
            # (possibly by nmap/dirsearch with a different component format), skip.
            if title in _canonical_titles and title in existing_titles:
                continue

            # --- Attribution: credit whoever found the underlying data first ---
            desc_lower = desc.lower()
            url_lower = url.lower()

            if title in {t for _, t in self._PATH_CANONICAL.values()}:
                # Path-based finding: credit dirsearch if it already found the path.
                # component = actual URL path (or path_key fallback) from _nikto_canonical.
                check_path = component.lower().rstrip("/")
                discovered_by = (
                    "dirsearch"
                    if check_path and any(
                        check_path == p.lower().rstrip("/")
                        or check_path.startswith(p.lower().rstrip("/"))
                        or p.lower().rstrip("/").startswith(check_path)
                        for p in known_web_paths
                    )
                    else "nikto"
                )
            elif title in {t for _, t in self._SERVICE_CANONICAL.values()}:
                # Service-based finding: credit nmap if it already found the service
                discovered_by = (
                    "nmap"
                    if any(svc in desc_lower or svc in url_lower for svc in known_services)
                    else "nikto"
                )
            else:
                # Truly nikto-unique finding (headers, CVEs, misc)
                discovered_by = "nikto"

            vuln = Vulnerability(
                title=title,
                cve_id=None,
                severity=sev,
                affected_component=component,
                description=desc,
                evidence=f"Found by nikto: {url}",
                discovered_by_tool=discovered_by,
            )
            state.add_vulnerability(vuln)
            existing_titles.add(title)

    def _merge_sqlmap(self, state: PentestState, parsed: dict) -> None:
        if parsed.get("injectable"):
            params_str = ", ".join(str(p) for p in parsed.get("parameters", []))
            vuln = Vulnerability(
                title="SQL Injection Vulnerability",
                severity=Severity.CRITICAL,
                affected_component=params_str or "database parameter",
                description=(
                    f"SQL injection found. Injectable parameters: {params_str}. "
                    f"Databases: {', '.join(parsed.get('databases', []))}"
                ),
                evidence=parsed.get("raw_summary", "")[:500],
                discovered_by_tool="sqlmap",
            )
            state.add_vulnerability(vuln)

    def _merge_metasploit(self, state: PentestState, parsed: dict, command: str) -> None:
        if parsed.get("exploit_success") or parsed.get("session_opened"):
            # Mark existing vulns as exploited or create new entry
            module = parsed.get("module_used", "unknown module")
            vuln = Vulnerability(
                title=f"Remote Code Execution via {module}",
                severity=Severity.CRITICAL,
                affected_component=module,
                description=f"Successfully exploited using Metasploit module: {module}",
                evidence=parsed.get("raw_summary", "")[:500],
                exploited=True,
                discovered_by_tool="metasploit",
            )
            state.add_vulnerability(vuln)

    def _tool_result_to_observation(self, result: ToolResult) -> str:
        """Compact text summary of a ToolResult for LLM consumption.

        工具原始数据（parsed 摘要）包裹在 UNTRUSTED 分隔符内——Spotlighting
        的 delimiting 变体（arXiv:2403.14720）：配合 system prompt 声明，
        为 ContextGuard 未检出的注入载荷提供第二层防御。harness 生成的
        诊断与存档指引在标记之外（可信文本）。
        """
        lines = [f"Tool: {result.tool}", f"Command: {result.command[:200]}"]

        if not result.success:
            lines.append(f"ERROR: {result.error_message}")
        else:
            lines.append(f"Success. Elapsed: {result.elapsed_seconds:.1f}s")

        diagnostics: list[str] = []
        if result.parsed:
            parsed_lines = ["Parsed Results:"]
            # Tool-specific summarization
            tool = result.tool.lower()
            parsed = result.parsed

            if tool == "nmap":
                hosts = parsed.get("hosts", [])
                if not hosts:
                    diagnostics.append(
                        "  DIAGNOSTIC: 0 hosts found —— 目标可能离线、被防火墙过滤或禁 ping。\n"
                        "  下一步（可执行）：用 nmap 对同一 target 执行 scan_type="
                        "'host_discovery' 重试一次；仍为 0 则结论为「主机离线/被过滤」，"
                        "转向 scope 内其他目标，不要第三次原样重扫。")
                else:
                    if len(hosts) > 5:
                        parsed_lines.append(f"  共 {len(hosts)} 台主机，显示前 5 台（全部已并入状态）")
                    parsed_lines.append(f"  Hosts found: {len(hosts)}")
                    for h in hosts[:5]:
                        ports_summary = ", ".join(
                            f"{p['port']}/{p['service']}" for p in h.get("ports", [])[:10]
                        )
                        parsed_lines.append(f"  {h['ip']} ({h.get('hostname','')}): {ports_summary}")

            elif tool == "dirsearch":
                paths = parsed.get("paths", [])
                if not paths:
                    diagnostics.append(
                        "  DIAGNOSTIC: 0 paths found —— 字典可能不适用于该技术栈，"
                        "或目标对未知路径做了统一响应。\n"
                        "  下一步（可执行）：对同一 url 重发 dirsearch 并换 extensions"
                        "（如 php,html,js,asp,jsp）；仍为 0 则该结论有效，"
                        "转向 nmap 已发现的其他端口。")
                else:
                    if len(paths) > 20:
                        parsed_lines.append(f"  共 {len(paths)} 条路径，显示前 20 条（全部已并入状态）")
                    parsed_lines.append(f"  Paths found: {len(paths)}")
                    for p in paths[:20]:
                        parsed_lines.append(f"  [{p['status']}] {p['path']}")

            elif tool == "nikto":
                findings = parsed.get("findings", [])
                if not findings:
                    diagnostics.append(
                        "  DIAGNOSTIC: 0 findings —— nikto 未发现问题，这是有效结论。\n"
                        "  下一步（可执行）：基于已并入状态的 nmap 服务版本选择利用动作"
                        "（如对带参数的 URL 发起 sqlmap），无需重跑 nikto。")
                else:
                    if len(findings) > 10:
                        parsed_lines.append(f"  共 {len(findings)} 条发现，显示前 10 条（全部已并入状态）")
                    parsed_lines.append(f"  Findings: {len(findings)}")
                    for f in findings[:10]:
                        parsed_lines.append(f"  - {f['description'][:150]}")

            elif tool == "sqlmap":
                parsed_lines.append(f"  Injectable: {parsed.get('injectable', False)}")
                if parsed.get("databases"):
                    parsed_lines.append(f"  Databases: {', '.join(parsed['databases'])}")
                parsed_lines.append(f"  Summary: {parsed.get('raw_summary','')[:300]}")
                if not parsed.get("injectable"):
                    diagnostics.append(
                        "  DIAGNOSTIC: 未发现注入点——有效结论。\n"
                        "  下一步（可执行）：对同一 url 重发 sqlmap 并提高 level（3-5）"
                        "/risk（2-3）；仍无注入则换其他带参数的 URL 或 POST data，"
                        "不要第三次原样重跑。")

            elif tool == "metasploit":
                parsed_lines.append(f"  Exploit success: {parsed.get('exploit_success', False)}")
                parsed_lines.append(f"  Session opened: {parsed.get('session_opened', False)}")
                parsed_lines.append(f"  Session type: {parsed.get('session_type', 'none')}")
                if parsed.get("error_messages"):
                    parsed_lines.append(f"  Errors: {parsed['error_messages'][0][:200]}")
                if not parsed.get("exploit_success") and not parsed.get("error_messages"):
                    diagnostics.append(
                        "  DIAGNOSTIC: 利用未成功且无报错。\n"
                        "  下一步（可执行）：重发 metasploit 并显式指定 rport 与"
                        "匹配服务版本的 module；仍失败则用 nmap scan_type='service' "
                        "确认版本后换 module。")

            # Spotlighting delimiting：目标来源的原始数据整体包裹，
            # 配合 system prompt 的 Rule 10 声明其「是数据非指令」
            lines.append(UNTRUSTED_OPEN)
            lines.extend(parsed_lines)
            lines.append(UNTRUSTED_END)

        # 诊断与存档是 harness 生成的可信指引，置于 UNTRUSTED 之外
        lines.extend(diagnostics)
        # 全文存档指引（seq 补全的廉价等价）：截断发生时 LLM 知道原文去处
        if result.archive_path:
            lines.append(f"[完整原始输出已存档: {result.archive_path}]")

        return "\n".join(lines)

    def build_state_snapshot(self, state: PentestState) -> str:
        """Compact text snapshot of current state for LLM context."""
        lines = [
            f"=== CURRENT STATE ===",
            f"Target: {state.target}",
            f"Stage: {state.current_stage.value}",
            f"Session: {state.session_id}",
            "",
        ]

        # hosts/web_paths/vulnerabilities 均由工具输出合并而来（不可信衍生
        # 数据，载荷可能藏于 finding 描述/evidence）——按 Spotlighting 规则
        # 整体包裹；Target/Stage/迭代数等 harness 字段在标记之外
        lines.append(UNTRUSTED_OPEN)
        lines.append("Discovered Hosts:")
        for host in state.hosts:
            lines.append(f"  {host.ip} ({host.hostname or 'no hostname'}) - {host.os or 'OS unknown'}")
            for svc in host.services[:10]:
                lines.append(f"    Port {svc.port}/{svc.protocol}: {svc.service} {svc.version or ''}")

        lines += ["", f"Web Paths ({len(state.web_paths)} total):"]
        for path in state.web_paths[:30]:
            lines.append(f"  {path}")

        lines += ["", f"Vulnerabilities ({len(state.vulnerabilities)} total):"]
        for vuln in state.vulnerabilities:
            exploited = " [EXPLOITED]" if vuln.exploited else ""
            lines.append(f"  [{vuln.severity.value.upper()}]{exploited} {vuln.title}")
            if vuln.affected_component:
                lines.append(f"    Component: {vuln.affected_component}")
            if vuln.evidence:
                lines.append(f"    Evidence: {vuln.evidence[:200]}")
        lines.append(UNTRUSTED_END)

        lines += ["", f"Credentials found: {len(state.credentials)}"]
        lines += [f"Stages completed: {', '.join(state.stages_completed) or 'none'}"]
        lines += [f"Iterations: {state.total_iterations}"]

        # Add guidance for next steps based on current state
        if state.current_stage.value == "VULNERABILITY_SCANNING":
            web_paths = [p for p in state.web_paths if p.startswith("/")]
            if len(web_paths) < 5:
                lines += ["", "NOTE: Few web paths found. Consider running dirsearch with more extensions."]
                lines += ["Common paths to check: /login, /search, /upload, /api/*, /.env, /admin"]

        if state.current_stage.value == "VULNERABILITY_ANALYSIS":
            vulns = [v for v in state.vulnerabilities if v.severity.value in ("critical", "high")]
            if len(vulns) < 3:
                lines += ["", "NOTE: Few high-severity vulnerabilities found. Consider checking more paths for injection flaws."]

        return "\n".join(lines)
