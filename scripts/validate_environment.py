#!/usr/bin/env python3
"""
validate_environment.py - Pre-flight checks before running the agent.
Verifies tools are installed, API key is set, and environment is ready.
"""
import sys
import os
import shutil
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))


def check(label: str, ok: bool, detail: str = "") -> bool:
    icon = "✓" if ok else "✗"
    color = "\033[32m" if ok else "\033[31m"
    reset = "\033[0m"
    print(f"  {color}{icon}{reset} {label}" + (f": {detail}" if detail else ""))
    return ok


def main():
    print("PentestAgent Environment Validation\n")
    all_ok = True

    # 检查是否在 venv 中运行
    in_venv = sys.prefix != sys.base_prefix
    venv_exists = os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "venv"))
    if venv_exists and not in_venv:
        print("\033[33m[!] 检测到 venv 目录但未激活，请先运行:\033[0m")
        print("    source venv/bin/activate")
        print("    python3 scripts/validate_environment.py\n")
        sys.exit(1)

    # API Keys - at least one required
    print("\nLLM API Keys (至少需要设置一个):")
    from agent.llm_factory import PROVIDER_CONFIGS
    any_key = False
    for prov, cfg in PROVIDER_CONFIGS.items():
        key_val = os.getenv(cfg["env_key"], "")
        has_key = bool(key_val)
        any_key = any_key or has_key
        display = f"{'set (' + key_val[:8] + '...)' if has_key else 'not set'}"
        check(f"{prov:12} {cfg['env_key']}", has_key or True, display)  # Non-blocking
    if not any_key:
        all_ok &= check("At least one API key", False, "set at least one provider key in .env")

    # Python packages
    packages = ["anthropic", "langchain", "langchain_anthropic", "pydantic", "click", "rich", "yaml", "dotenv"]
    print("\nPython Packages:")
    for pkg in packages:
        try:
            __import__(pkg.replace("-", "_"))
            all_ok &= check(pkg, True)
        except ImportError:
            all_ok &= check(pkg, False, "not installed - run: pip install -r requirements.txt")

    # Optional packages
    optional_packages = [("chromadb", "RAG support"), ("sentence_transformers", "RAG embeddings")]
    print("\nOptional Packages (RAG):")
    for pkg, purpose in optional_packages:
        try:
            __import__(pkg)
            check(pkg, True, purpose)
        except ImportError:
            check(pkg, False, f"optional ({purpose}) - run: pip install {pkg}")

    # Security tools
    tools = {
        "nmap": "network scanner",
        "dirsearch": "web enumeration",
        "nikto": "web vulnerability scanner",
        "sqlmap": "SQL injection tool",
        "msfconsole": "Metasploit framework",
    }
    print("\nSecurity Tools:")
    for tool, desc in tools.items():
        found = shutil.which(tool) is not None
        if not found and tool != "msfconsole":
            all_ok &= check(f"{tool} ({desc})", False, "not found in PATH")
        else:
            check(f"{tool} ({desc})", found, "optional" if tool == "msfconsole" else "")

    # Data directories
    print("\nData Directories:")
    from pathlib import Path
    dirs = [
        "data/sessions",
        "data/reports",
        "data/knowledge_base/cve_entries",
        "data/knowledge_base/exploit_techniques",
    ]
    for d in dirs:
        path = Path(d)
        existed = path.exists()
        if not existed:
            path.mkdir(parents=True, exist_ok=True)
        check(d, True, "exists" if existed else "created")

    # Config file
    print("\nConfiguration:")
    config_ok = Path("config.yaml").exists()
    all_ok &= check("config.yaml", config_ok, "" if config_ok else "missing - copy from template")

    env_ok = Path(".env").exists()
    check(".env", env_ok, "optional (can use environment variables directly)")

    print(f"\n{'All checks passed!' if all_ok else 'Some checks failed. Fix issues before running.'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
