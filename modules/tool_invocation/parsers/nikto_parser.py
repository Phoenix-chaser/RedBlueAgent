"""
NiktoParser - parses nikto plain-text and JSON output.
"""
from __future__ import annotations

import json
import re
from modules.tool_invocation.parsers.base_parser import BaseOutputParser


class NiktoParser(BaseOutputParser):
    def parse(self, stdout: str, stderr: str = "") -> dict:
        result = {"findings": [], "target": None, "total_found": 0}

        if not stdout.strip():
            return result

        # Try JSON first (nikto -Format json)
        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                vuln_items = data.get("vulnerabilities", data.get("items", []))
                result["target"] = data.get("host") or data.get("target")
                for item in vuln_items:
                    result["findings"].append({
                        "id": item.get("id", item.get("osvdbid", "")),
                        "url": item.get("url", item.get("uri", "")),
                        "method": item.get("method", "GET"),
                        "description": item.get("msg", item.get("description", "")),
                        "osvdb": item.get("osvdbid", item.get("osvdb", "")),
                    })
                result["total_found"] = len(result["findings"])
                return result
        except (json.JSONDecodeError, TypeError):
            pass

        # Plain text parsing
        # Prefixes that indicate nikto metadata (header/footer/stats), not actual findings
        SKIP_PREFIXES = (
            "target ip:", "target hostname:", "target port:",
            "start time:", "end time:",
            "server:", "ip address:",
        )
        SKIP_PATTERNS = (
            re.compile(r"^\d+\s+request", re.IGNORECASE),   # "239 requests: 0 error(s)..."
            re.compile(r"^\d+\s+host\(s\)", re.IGNORECASE), # "1 host(s) tested"
        )

        for line in stdout.splitlines():
            line = line.strip()
            # "- Nikto v2.1.6"
            if line.startswith("- Target"):
                m = re.search(r"Target.*?:\s*(.+)", line)
                if m:
                    result["target"] = m.group(1).strip()
            # "+ OSVDB-xxxxx: /path: description"
            elif line.startswith("+") or (line.startswith("-") and "OSVDB" in line):
                # Extract OSVDB ID if present
                osvdb_match = re.search(r"OSVDB-(\d+)", line)
                osvdb_id = osvdb_match.group(1) if osvdb_match else None

                # Strip leading +/- and OSVDB prefix
                desc_raw = re.sub(r"^[+\-]\s*(OSVDB-\d+:\s*)?", "", line).strip()

                # Skip nikto metadata/stats lines that are not security findings
                desc_lower_raw = desc_raw.lower()
                if any(desc_lower_raw.startswith(p) for p in SKIP_PREFIXES):
                    continue
                if any(pat.match(desc_raw) for pat in SKIP_PATTERNS):
                    continue

                # Extract URL/path: nikto plain text uses "/path: description" format
                url = ""
                if desc_raw.startswith("/"):
                    colon_idx = desc_raw.find(": ")
                    if colon_idx > 0:
                        url = desc_raw[:colon_idx].strip()
                        desc = desc_raw[colon_idx + 2:].strip()
                    else:
                        url = desc_raw
                        desc = desc_raw
                else:
                    desc = desc_raw

                if desc and len(desc) > 10:
                    result["findings"].append({
                        "id": f"OSVDB-{osvdb_id}" if osvdb_id else "",
                        "url": url,
                        "method": "GET",
                        "description": desc[:500],
                        "osvdb": osvdb_id,
                    })

        result["total_found"] = len(result["findings"])
        return result
