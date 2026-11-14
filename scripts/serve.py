#!/usr/bin/env python3
"""
serve.py - RedBlueAgent 生产级 HTTP 服务入口。

用法:
    REDBLUEAGENT_TOKEN=$(openssl rand -hex 32) python scripts/serve.py
    REDBLUEAGENT_TOKEN=... python scripts/serve.py --workers 2 --proxy-headers
    # 浏览器打开 http://127.0.0.1:8095/

环境:
    REDBLUEAGENT_TOKEN            必填（Bearer 认证）
    REDBLUEAGENT_HOST/PORT        默认 127.0.0.1:8095
    REDBLUEAGENT_SESSIONS_DIR     默认 data/sessions
    REDBLUEAGENT_MAX_CONCURRENT   默认 3（并发会话上限）
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    parser = argparse.ArgumentParser(description="RedBlueAgent server")
    parser.add_argument("--host", default=os.getenv("REDBLUEAGENT_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("REDBLUEAGENT_PORT", "8095")))
    parser.add_argument("--workers", type=int, default=1,
                        help="uvicorn worker 数（默认 1）")
    parser.add_argument("--proxy-headers", action="store_true",
                        help="信任 X-Forwarded-For（反向代理后启用）")
    parser.add_argument("--max-concurrent", type=int,
                        default=int(os.getenv("REDBLUEAGENT_MAX_CONCURRENT", "3")))
    parser.add_argument("--validation-interval", type=int,
                        default=int(os.getenv("REDBLUEAGENT_VALIDATION_INTERVAL", "300")))
    parser.add_argument("--no-validation", action="store_true",
                        help="禁用持续验证循环")
    args = parser.parse_args()

    token = os.getenv("REDBLUEAGENT_TOKEN") or os.getenv("PENTESTAGENT_TOKEN", "")
    if not token or token.startswith("change-me"):
        print("ERROR: REDBLUEAGENT_TOKEN 未设置或为占位值。生成: "
              "openssl rand -hex 32")
        return 1

    import uvicorn
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from server.app import create_app

    app = create_app(
        sessions_dir=os.getenv("REDBLUEAGENT_SESSIONS_DIR", "data/sessions"),
        token=token,
        max_concurrent_sessions=args.max_concurrent,
    )

    # 持续验证循环（「一边测试验证一边运行」）
    validation = None
    if not args.no_validation:
        try:
            from server.validation import ValidationLoop
            validation = ValidationLoop(interval=args.validation_interval)
            validation.start()
        except Exception as e:
            print(f"[ValidationLoop] 启动失败（不阻断服务）: {e}")

    host = args.host
    port = args.port
    banner = Text()
    banner.append("⚔ RedBlueAgent Server\n\n", style="bold cyan")
    banner.append("➜ 控制台    ", style="dim")
    if host == "0.0.0.0":
        banner.append(f"http://<本机IP>:{port}/", style="bold green")
        banner.append("（已监听全部网卡）\n", style="dim")
    else:
        banner.append(f"http://{host}:{port}/\n", style="bold green")
    banner.append("➜ 健康检查  ", style="dim")
    banner.append(f"http://{host}:{port}/health", style="cyan")
    banner.append("（无认证，LB/k8s 探针）\n", style="dim")
    banner.append("➜ 指标     ", style="dim")
    banner.append(f"http://{host}:{port}/metrics", style="cyan")
    banner.append("（Prometheus，需 Token）\n\n", style="dim")
    banner.append(f"并发: {args.max_concurrent} | Workers: {args.workers} | ")
    if validation:
        banner.append(f"自检: ✓ 每{args.validation_interval}s", style="green")
    else:
        banner.append("自检: 已禁用", style="yellow")
    banner.append("\n\n靶场:\n", style="bold")
    banner.append("  cd docker && docker compose -f docker-compose.prod.yml up -d\n",
                  style="cyan")

    Console().print(Panel(banner, border_style="blue", title="就绪", title_align="left"))

    try:
        uvicorn.run(app, host=host, port=port, log_level="info",
                    proxy_headers=args.proxy_headers,
                    forwarded_allow_ips="*" if args.proxy_headers else None)
    finally:
        if validation:
            validation.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
