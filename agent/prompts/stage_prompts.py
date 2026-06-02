"""
Stage-specific prompt additions that guide the LLM's behavior per phase.
Optimized for LLM decision quality — not hardcoded rules.
"""
from modules.context_management.state_schema import PentestStage

STAGE_GUIDANCE: dict[str, str] = {
    PentestStage.TARGET_CONFIRMATION.value: """
CURRENT STAGE: Target Confirmation
Objective: Verify the target is alive and identify the running services.
Actions:
1. Run nmap with scan_type="host_discovery" to confirm host is up
2. Run nmap with scan_type="service" to get port/service overview
3. Note all web ports for the next stage
""",

    PentestStage.INFORMATION_GATHERING.value: """
CURRENT STAGE: Information Gathering
Objective: Enumerate ALL open ports, services, and versions.
Actions:
1. Run nmap with scan_type="service" for comprehensive service detection
2. Note every HTTP port (80, 443, 5000, 8080, etc.) for web scanning
3. Check for SSH, FTP, database ports
4. Document all findings before proceeding
""",

    PentestStage.VULNERABILITY_SCANNING.value: """
CURRENT STAGE: Vulnerability Scanning
Objective: Scan ALL web services for vulnerabilities.
Actions:
1. Run nikto against each web port to find known vulnerabilities
2. Run dirsearch against each web port to discover hidden paths
3. For each path found, note the HTTP status code
4. Check for common sensitive paths: /.env, /admin, /backup, /config, /robots.txt
5. Do NOT skip dirsearch — it discovers most of the attack surface
""",

    PentestStage.VULNERABILITY_ANALYSIS.value: """
CURRENT STAGE: Vulnerability Analysis
Objective: Analyze findings and build exploitation hypotheses.
Actions:
1. Review all discovered paths and identify potential vulnerabilities
2. For each web path, consider what vulnerability it might have:
   - Forms (login, search, upload) → injection flaws
   - API endpoints (/api/*) → SSRF, XXE, deserialization
   - Config files (/.env, /backup) → information disclosure
3. Prioritize findings by severity and exploitability
4. Form specific exploitation plans
""",

    PentestStage.VULNERABILITY_EXPLOITATION.value: """
CURRENT STAGE: Vulnerability Exploitation
Objective: Verify vulnerabilities by attempting exploitation.
Actions:
1. For SQL injection candidates: use sqlmap with appropriate parameters
2. For SSTI/command injection: test with crafted payloads
3. For file upload: test uploading restricted file types
4. For each attempt, document success or failure with evidence
5. If one approach fails, try a different technique
""",

    PentestStage.POST_EXPLOITATION.value: """
CURRENT STAGE: Post-Exploitation
Objective: Document all findings and evidence.
Actions:
1. List ALL vulnerabilities found with severity levels
2. For each vulnerability, document: path, type, evidence, impact
3. Summarize overall security posture
4. Signal finish when documentation is complete
""",

    PentestStage.REPORT_GENERATION.value: """
CURRENT STAGE: Report Generation
Objective: All testing is complete. Signal finish to generate the report.
Action: Issue a "finish" action.
""",
}


def get_stage_prompt(stage_value: str) -> str:
    return STAGE_PROMPT_MAP.get(stage_value, "Continue penetration testing.")


STAGE_PROMPT_MAP = STAGE_GUIDANCE
