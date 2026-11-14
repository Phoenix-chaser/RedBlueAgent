# -*- coding: utf-8 -*-
"""PentestAgent HTTP 服务层（P2-3）。

单进程 FastAPI：会话提交（后台线程执行）、SSE 实时事件流（tail
events.jsonl）、file 审批模式的 HTTP 桥（复用 P0-5 的
data/approvals/<sid>/{pending,decisions} 协议）。

认证：单一 Bearer Token（env PENTESTAGENT_TOKEN，借 SPECTRE
INTERNAL_TOKEN 的最小密钥面思想——单机单用户，不做多用户体系）。
分层上对标 spectre 的 gateway/runtime 拆分，但单机形态下一个进程足够。
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

_STATIC_DIR = Path(__file__).resolve().parent / "static"


class SessionCreate(BaseModel):
    target: str
    scope: list[str] | None = None
    session_id: str | None = None


class ApprovalDecision(BaseModel):
    approved: bool


def create_app(
    sessions_dir: str | Path = "data/sessions",
    token: str | None = None,
    agent_runner=None,
) -> FastAPI:
    """sessions_dir: 会话数据根；token: Bearer 令牌（默认取 env
    PENTESTAGENT_TOKEN，为空则所有请求 403，除非显式传 "" 关闭认证）；
    agent_runner: 可注入的会话执行器 fn(target, scope, session_id)，
    默认惰性构造 PentestAgent（无 LLM Key 时返回 503 可行动错误）。
    """
    sessions_dir = Path(sessions_dir)
    token = token if token is not None else os.getenv("REDBLUEAGENT_TOKEN") or os.getenv("PENTESTAGENT_TOKEN", "")

    app = FastAPI(title="PentestAgent", version="0.3.0")

    def require_token(request: Request) -> None:
        if token == "":
            return  # auth explicitly disabled (tests / localhost-only setups)
        # EventSource 无法携带 Authorization 头，SSE 场景允许 ?token= query
        q_token = request.query_params.get("token", "")
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {token}" and q_token != token:
            raise HTTPException(status_code=401, detail="invalid or missing token")

    # ── 会话 ────────────────────────────────────────────────────────────

    def _default_runner(target: str, scope, session_id):
        from agent.core import PentestAgent  # lazy: needs LLM key in env
        agent = PentestAgent(interactive=False)
        agent.run(target=target, scope=scope, session_id=session_id)

    runner = agent_runner or _default_runner

    @app.post("/api/sessions", dependencies=[Depends(require_token)])
    def create_session(body: SessionCreate):
        sid = body.session_id or datetime.utcnow().strftime("%Y%m%d-%H%M%S") + "-web"
        if (sessions_dir / sid / "events.jsonl").exists():
            raise HTTPException(status_code=409, detail=f"session {sid} already exists")
        try:
            threading.Thread(
                target=runner, args=(body.target, body.scope, sid), daemon=True
            ).start()
        except Exception as e:  # noqa: BLE001 — surface actionable startup errors
            raise HTTPException(status_code=503, detail=f"agent runner failed: {e}")
        return {"session_id": sid}

    @app.get("/api/sessions", dependencies=[Depends(require_token)])
    def list_sessions():
        if not sessions_dir.exists():
            return {"sessions": []}
        sids = sorted(
            p.parent.name for p in sessions_dir.glob("*/events.jsonl"))
        return {"sessions": sids}

    @app.get("/api/sessions/{sid}", dependencies=[Depends(require_token)])
    def session_state(sid: str):
        snap = sessions_dir / sid / "snapshot.json"
        if not snap.exists():
            raise HTTPException(status_code=404, detail="no snapshot yet")
        return json.loads(snap.read_text(encoding="utf-8"))

    # ── SSE：tail events.jsonl ─────────────────────────────────────────

    @app.get("/api/sessions/{sid}/events", dependencies=[Depends(require_token)])
    async def session_events(sid: str, since: int = 0, follow: int = 1):
        path = sessions_dir / sid / "events.jsonl"
        if not path.exists():
            raise HTTPException(status_code=404, detail="no event log")

        async def gen():
            offset = 0
            idle_ticks = 0
            with open(path, encoding="utf-8") as fh:
                fh.seek(offset)
                while True:
                    pushed = False
                    while True:
                        pos = fh.tell()
                        line = fh.readline()
                        if not line:
                            break
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            fh.seek(pos)  # torn mid-write; retry after poll
                            break
                        if entry.get("seq", 0) <= since:
                            continue
                        pushed = True
                        idle_ticks = 0
                        yield f"data: {json.dumps(entry, ensure_ascii=False)}\n\n"
                        if entry.get("t") == "finish":
                            return
                    if not follow:
                        return
                    if not pushed:
                        idle_ticks += 1
                        if idle_ticks % 10 == 0:
                            yield ": ping\n\n"
                        await asyncio.sleep(0.5)

        return StreamingResponse(gen(), media_type="text/event-stream")

    # ── 审批桥（file 模式协议）────────────────────────────────────────

    @app.get("/api/sessions/{sid}/approvals", dependencies=[Depends(require_token)])
    def list_approvals(sid: str):
        pending_dir = sessions_dir.parent / "approvals" / sid / "pending"
        if not pending_dir.exists():
            return {"pending": []}
        items = []
        for f in sorted(pending_dir.glob("*.json")):
            try:
                items.append(json.loads(f.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                continue
        return {"pending": items}

    @app.post("/api/sessions/{sid}/approvals/{req_id}",
              dependencies=[Depends(require_token)])
    def decide_approval(sid: str, req_id: str, decision: ApprovalDecision):
        pending = sessions_dir.parent / "approvals" / sid / "pending" / f"{req_id}.json"
        if not pending.exists():
            raise HTTPException(status_code=404, detail="unknown approval request")
        decisions = pending.parent.parent / "decisions"
        decisions.mkdir(parents=True, exist_ok=True)
        (decisions / f"{req_id}.json").write_text(
            json.dumps({"id": req_id, "approved": decision.approved}),
            encoding="utf-8")
        return {"id": req_id, "approved": decision.approved}

    # ── 最小前端 ────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (_STATIC_DIR / "index.html").read_text(encoding="utf-8")

    return app
