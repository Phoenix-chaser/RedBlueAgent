#!/usr/bin/env python3
"""collect_tool_outputs.py - 用 agent 自己的工具扫一遍靶场，把原始输出存成会话存档。

这些存档是蓝队检测器「领域适配」的数据源（差分重放 [5]）：工具输出不经 LLM，
构造即良性。全程不调用 LLM，所以不需要 API Key；需要真实工具（在 agent 镜像里跑）。

只对已授权的目标运行（内置靶场：172.20.0.10）。

用法（agent 镜像内）:
    python3 scripts/collect_tool_outputs.py --target 172.20.0.10 \\
        --sqlmap-url http://172.20.0.10:5000/search?q=1 --sqlmap-url http://172.20.0.10:5000/user/1
然后:
    cd blueteam && python3 -m src.toolout_bench --sessions-dir ../data/sessions --split-half
    python3 -m src.train        # 自动并入 data/extra_benign.jsonl
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.session_log import EventLog
from modules.context_management.state_schema import ActionDecision, ToolResult
from modules.tool_invocation.invoker import ToolInvoker

MAX_ROBOTS_PATHS = 12
MAX_LINKS = 30
_ROBOTS_LINE = re.compile(r"^(?:Disallow|Allow):\s*(/\S*)", re.I)
_SAME_ORIGIN_LINK = re.compile(r"""href=["'](/[^"'#?]*)""", re.I)


def first_web_port(result: ToolResult) -> tuple[int, bool] | None:
    """(port, tls) of the first http(s) service nmap found."""
    for host in (getattr(result, "parsed", None) or {}).get("hosts", []) or []:
        for port in host.get("ports", []) or []:
            service = str(port.get("service") or "").lower()
            if service in ("http", "http-alt", "https", "ssl"):
                number = port.get("port")
                if str(number).isdigit():
                    return int(number), service in ("https", "ssl")
    return None


def _skip(path: str) -> bool:
    # 静态资源不是守卫会读的内容；蜜标不碰（合法测试永不需要，内容也不该进训练数据）
    return path.startswith(("/static/", "/assets/")) or "honeytoken" in path.lower()


def page_links(result: ToolResult) -> list[str]:
    """Same-origin paths linked from a page's raw HTML (depth 1, no query strings)."""
    html: str = getattr(result, "raw_stdout", "") or ""
    links, seen = [], set()
    for match in _SAME_ORIGIN_LINK.finditer(html):
        path = match.group(1)
        if path not in seen and not _skip(path):
            seen.add(path)
            links.append(path)
    return links[:MAX_LINKS]


def robots_paths(result: ToolResult) -> list[str]:
    """Paths listed in robots.txt."""
    paths = []
    for line in (getattr(result, "parsed", None) or {}).get("lines", []) or []:
        match = _ROBOTS_LINE.match(str(line))
        if match and not _skip(match.group(1)):
            paths.append(match.group(1))
    return paths[:MAX_ROBOTS_PATHS]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True, help="已授权的目标 IP/主机名")
    ap.add_argument("--web-port", default=None,
                    help="Web 端口；默认取 nmap 发现的第一个 http(s) 服务")
    ap.add_argument("--sqlmap-url", action="append", default=[], metavar="URL",
                    help="可选：带参数的 URL，用 sqlmap 跑一次；可重复给出多个")
    ap.add_argument("--out", default="data/sessions/toolout-collect",
                    help="存档目录（一个只含 tool_outputs/ 的会话目录）")
    args = ap.parse_args()

    invoker = ToolInvoker()
    log = EventLog(Path(args.out))
    counter = {"n": 0}

    def run(tool: str, params: dict) -> ToolResult:
        counter["n"] += 1
        print(f"[{counter['n']}] {tool} {params}", flush=True)
        result = invoker.invoke(ActionDecision(type="tool", tool=tool, params=params))
        path = log.save_tool_output(result, counter["n"])
        if result.success:
            print(f"    ok ({result.elapsed_seconds:.1f}s) -> {Path(path).name}", flush=True)
        else:
            print(f"    FAILED ({result.elapsed_seconds:.1f}s): "
                  f"{str(result.error_message)[:160]} -> {Path(path).name}", flush=True)
        return result

    run("nmap", {"target": args.target, "scan_type": "host_discovery"})
    services = run("nmap", {"target": args.target, "scan_type": "service"})

    scheme = "http"
    if args.web_port:
        port, tls = int(args.web_port), False
    else:
        found = first_web_port(services)
        if found is None:
            print("nmap 没有发现 Web 服务，到此为止。")
            return 0
        port, tls = found
        scheme = "https" if tls else "http"
    base = f"{scheme}://{args.target}:{port}"

    # 只带快速脚本：vuln 类脚本对一个小 Web 服务也要跑 5 分钟以上，会撞上工具超时
    run("nmap", {"target": args.target, "scan_type": "service", "ports": str(port),
                 "scripts": "default,http-enum,http-backup-finder,http-config-backup"})
    home = run("read_url", {"url": f"{base}/"})
    robots = run("read_url", {"url": f"{base}/robots.txt"})
    # 页面正文是守卫最常见的误报来源：把首页链到的页面都读一遍（深度 1）
    read = {"/", "/robots.txt"}
    for path in robots_paths(robots) + page_links(home):
        if path not in read:
            read.add(path)
            run("read_url", {"url": base + path})
    run("nikto", {"target": base})
    run("dirsearch", {"target": base})
    for url in args.sqlmap_url:
        run("sqlmap", {"url": url, "batch": True})

    print(f"\n{counter['n']} 份输出已存档 -> {args.out}/tool_outputs/")
    print("下一步: cd blueteam && python3 -m src.toolout_bench "
          "--sessions-dir ../data/sessions --split-half")
    return 0


if __name__ == "__main__":
    sys.exit(main())
