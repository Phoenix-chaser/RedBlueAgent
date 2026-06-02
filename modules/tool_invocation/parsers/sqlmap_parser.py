"""
SqlmapParser - parses sqlmap output (JSON mode preferred).
"""
from __future__ import annotations

import json
import re
from modules.tool_invocation.parsers.base_parser import BaseOutputParser


class SqlmapParser(BaseOutputParser):
    def parse(self, stdout: str, stderr: str = "") -> dict:
        result = {
            "injectable": False,
            "parameters": [],
            "databases": [],
            "tables": [],
            "data": [],
            "os_info": None,
            "raw_summary": "",
        }

        if not stdout.strip():
            return result

        # Try JSON output (sqlmap --batch --output-dir with JSON)
        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                result["injectable"] = bool(data.get("data") or data.get("parameters"))
                result["parameters"] = data.get("parameters", [])
                result["databases"] = data.get("databases", [])
                result["data"] = data.get("data", [])
                return result
        except (json.JSONDecodeError, TypeError):
            pass

        # Plain text parsing
        lines = stdout.splitlines()

        in_db_list = False
        in_table_list = False

        for i, line in enumerate(lines):
            line_lower = line.lower()
            stripped = line.strip()

            # Injectable parameter detection
            if "parameter:" in line_lower and "is vulnerable" in line_lower:
                result["injectable"] = True
                result["parameters"].append(stripped)
            elif re.search(r"parameter.*appears to be.*injectable", line_lower):
                result["injectable"] = True
                result["parameters"].append(stripped)

            # Database section header: "[*] available databases [N]:"
            if re.search(r"available databases", line_lower):
                in_db_list = True
                in_table_list = False
                # Also try extracting from the header line itself
                db_match = re.search(r"'(.+?)'", line)
                if db_match:
                    result["databases"].append(db_match.group(1))
                continue

            # Table section header
            if re.search(r"database.*tables|available tables", line_lower):
                in_table_list = True
                in_db_list = False
                continue

            # Capture list items (lines like "[*] 'dbname'" or "| dbname |")
            if in_db_list:
                db_match = re.search(r"'([^']+)'", line)
                if db_match:
                    result["databases"].append(db_match.group(1))
                elif re.match(r"\s*\[\*\]\s+\S", line):
                    # "[*] dbname" without quotes
                    name = re.sub(r"\s*\[\*\]\s+", "", stripped)
                    if name:
                        result["databases"].append(name)
                elif stripped and not stripped.startswith("["):
                    in_db_list = False  # End of db list

            if in_table_list:
                tbl_match = re.search(r"'([^']+)'", line)
                if tbl_match:
                    result["tables"].append(tbl_match.group(1))
                elif stripped and not stripped.startswith("["):
                    in_table_list = False

            # Legacy single-line extraction (not in a list context)
            if not in_db_list and re.search(r"^\[[\*\+]\].*database", line_lower):
                db_match = re.search(r"'(.+?)'", line)
                if db_match:
                    result["databases"].append(db_match.group(1))

            if not in_table_list and re.search(r"^\[[\*\+]\].*table", line_lower):
                tbl_match = re.search(r"'(.+?)'", line)
                if tbl_match:
                    result["tables"].append(tbl_match.group(1))

            if "operating system:" in line_lower:
                result["os_info"] = line.split(":", 1)[-1].strip()

        # Summary: last 20 lines
        result["raw_summary"] = "\n".join(lines[-20:])
        return result
