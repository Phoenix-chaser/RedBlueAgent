from __future__ import annotations

import json
import re
from urllib.parse import urlparse
from modules.tool_invocation.parsers.base_parser import BaseOutputParser


class DirsearchParser(BaseOutputParser):
    def parse(self, stdout: str, stderr: str = "") -> dict:
        result = {"paths": [], "total_found": 0}

        if not stdout.strip():
            return result

        # Try JSON parsing first (dirsearch --format json)
        try:
            data = json.loads(stdout)
            # dirsearch JSON: {"results": [{"status": 200, "path": "/admin", ...}]}
            if isinstance(data, dict) and "results" in data:
                for item in data["results"]:
                    result["paths"].append({
                        "path": item.get("path", ""),
                        "status": item.get("status", 0),
                        "size": item.get("content-length", 0),
                        "redirect": item.get("redirect", None),
                    })
            elif isinstance(data, list):
                for item in data:
                    result["paths"].append({
                        "path": item.get("path", item.get("url", "")),
                        "status": item.get("status", item.get("status_code", 0)),
                        "size": item.get("size", item.get("content-length", 0)),
                        "redirect": item.get("redirect", None),
                    })
            result["total_found"] = len(result["paths"])
            return result
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: parse plain text output
        # Modern dirsearch format: [HH:MM:SS] STATUS -  SIZE  - http://host/path
        # Legacy format:           STATUS   SIZE  http://host/path
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("["):
                # Modern: [11:22:33] 200 -  3KB - http://host/path
                m = re.search(r'\]\s+(\d{3})\s+-\s+\S+\s+-\s+(https?://\S+)', line)
                if m:
                    try:
                        status = int(m.group(1))
                        path = urlparse(m.group(2)).path.rstrip("/") or "/"
                        result["paths"].append({
                            "path": path,
                            "status": status,
                            "size": None,
                            "redirect": None,
                        })
                    except (ValueError, IndexError):
                        pass
                continue

            # Legacy: "200   3KB  http://target/admin"
            parts = line.split()
            if len(parts) >= 3:
                try:
                    status = int(parts[0])
                    raw = parts[-1]
                    # Extract path from full URL if needed
                    if raw.startswith("http"):
                        path = urlparse(raw).path.rstrip("/") or "/"
                    else:
                        path = raw
                    result["paths"].append({
                        "path": path,
                        "status": status,
                        "size": None,
                        "redirect": None,
                    })
                except (ValueError, IndexError):
                    continue

        result["total_found"] = len(result["paths"])
        return result