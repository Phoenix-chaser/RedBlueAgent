#!/usr/bin/env python3
"""
serve.py - PentestAgent HTTP 服务入口（P2-3）。

用法:
    PENTESTAGENT_TOKEN=$(openssl rand -hex 32) python scripts/serve.py
    # 浏览器打开 http://127.0.0.1:8095/ ，右上角填入 Token

环境:
    PENTESTAGENT_TOKEN  必填（Bearer 认证；缺失时拒绝启动——不裸奔）
    PENTESTAGENT_HOST/PORT  默认 127.0.0.1:8095（仅本机监听）
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    token = os.getenv("PENTESTAGENT_TOKEN", "")
    if not token or token.startswith("change-me"):
        print("ERROR: PENTESTAGENT_TOKEN 未设置或为占位值。生成: "
              "openssl rand -hex 32")
        return 1

    import uvicorn
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from server.app import create_app

    host = os.getenv("PENTESTAGENT_HOST", "127.0.0.1")
    port = int(os.getenv("PENTESTAGENT_PORT", "8095"))
    app = create_app(
        sessions_dir=os.getenv("PENTESTAGENT_SESSIONS_DIR", "data/sessions"),
        token=token,
    )

    banner = Text()
    banner.append("⚔ PentestAgent Console\n\n", style="bold cyan")
    banner.append("➜ 控制台  ", style="dim")
    if host == "0.0.0.0":
        banner.append(f"http://<本机IP或容器IP>:{port}/", style="bold green")
        banner.append("（已监听全部网卡；容器内运行时用 docker inspect 取容器 IP）\n", style="dim")
    else:
        banner.append(f"http://{host}:{port}/\n", style="bold green")
    banner.append("三步上手：\n", style="bold")
    banner.append("  1. 打开控制台，右上角粘贴 Token（本进程的 PENTESTAGENT_TOKEN）\n")
    banner.append("  2. 左上角「目标」填入已授权目标 IP → 开始测试\n")
    banner.append("  3. 实时事件流在中央；危险操作在右侧「待审批」按钮放行/拒绝\n\n")
    banner.append("靶场（另开终端）：\n", style="bold")
    banner.append("  cd docker && docker compose up -d target", style="cyan")
    banner.append("            # ★☆☆ VulnApp   172.20.0.10:5000 / localhost:8080\n", style="dim")
    banner.append("  cd docker && docker compose --profile hard up -d", style="cyan")
    banner.append("  # ★★★ JuiceShop 172.20.0.13:3000 / localhost:3000\n", style="dim")

    Console().print(Panel(banner, border_style="blue", title="就绪", title_align="left"))

    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
