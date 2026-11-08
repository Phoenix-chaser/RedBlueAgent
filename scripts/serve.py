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
    from server.app import create_app

    app = create_app(
        sessions_dir=os.getenv("PENTESTAGENT_SESSIONS_DIR", "data/sessions"),
        token=token,
    )
    uvicorn.run(
        app,
        host=os.getenv("PENTESTAGENT_HOST", "127.0.0.1"),
        port=int(os.getenv("PENTESTAGENT_PORT", "8095")),
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
