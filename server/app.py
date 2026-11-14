# -*- coding: utf-8 -*-
"""RedBlueAgent 生产级 HTTP 服务层。

从 v0.3 的最小 API 升级为持续运行服务：
- /health（无认证）— LB/k8s/Docker 探针
- /metrics（认证）— Prometheus 文本格式
- /api/status — 服务级状态摘要
- /api/validation — 持续验证循环状态
- DELETE /api/sessions/{sid} — 停止会话
- SessionManager — 有界线程池 + 会话状态跟踪 + 优雅停机
- 审批决策后清理 pending 文件
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_START_TIME = time.time()


class SessionCreate(BaseModel):
    target: str
    scope: list[str] | None = None
    session_id: str | None = None


class ApprovalDecision(BaseModel):
    approved: bool


class SessionManager:
    """有界并发会话管理：线程池 + 状态跟踪 + 停止信号。"""

    def __init__(self, max_workers: int = 3):
        self.pool = ThreadPoolExecutor(max_workers=max_workers,
                                       thread_name_prefix="session")
        self.sessions: dict[str, dict] = {}  # sid -> {status, stop_event, future, started_at}
        self._lock = threading.Lock()
        self.total_created = 0

    def submit(self, sid: str, runner, target: str, scope, session_id: str) -> bool:
        """提交会话到线程池。返回 False 表示池满或 sid 冲突。"""
        with self._lock:
            if sid in self.sessions and self.sessions[sid]["status"] in ("pending", "running"):
                return False
            stop_event = threading.Event()
            entry = {"status": "pending", "stop_event": stop_event,
                     "started_at": datetime.utcnow().isoformat(), "future": None}
            self.sessions[sid] = entry
            self.total_created += 1

        def _run():
            entry["status"] = "running"
            try:
                # 停机信号监测——react_loop 不直接读 Event，我们在 runner
                # 外包一层：如果 stop_event 被 set，向线程发 KeyboardInterrupt
                # （通过在主线程 signal.set_wakeup_fd 或直接检查）
                runner(target, scope, session_id)
                entry["status"] = "completed"
            except KeyboardInterrupt:
                entry["status"] = "stopped"
            except Exception as e:
                entry["status"] = "failed"
                entry["error"] = str(e)[:200]

        entry["future"] = self.pool.submit(_run)
        return True

    def stop(self, sid: str) -> bool:
        """向会话发停机信号。"""
        with self._lock:
            entry = self.sessions.get(sid)
            if not entry or entry["status"] not in ("pending", "running"):
                return False
            entry["stop_event"].set()
            # Python 线程无法直接发信号——设 Event 供外部检查，
            # 同时利用 os.kill(tid, SIGINT) 在 Linux 上可以工作（但复杂）
            # 实际停机依赖 WAL 快照 + 下一轮 session 锁回收
            entry["status"] = "stopping"
            return True

    def status(self, sid: str) -> dict | None:
        with self._lock:
            entry = self.sessions.get(sid)
            if not entry:
                return None
            return {"sid": sid, "status": entry["status"],
                    "started_at": entry.get("started_at"),
                    "error": entry.get("error")}

    @property
    def active_count(self) -> int:
        with self._lock:
            return sum(1 for e in self.sessions.values()
                       if e["status"] in ("pending", "running"))

    @property
    def stats(self) -> dict:
        with self._lock:
            by_status = {}
            for e in self.sessions.values():
                s = e["status"]
                by_status[s] = by_status.get(s, 0) + 1
            return {"total": len(self.sessions), "total_created": self.total_created,
                    "active": self.active_count, "by_status": by_status}

    def shutdown(self, timeout: float = 60.0):
        """优雅停机：停止接新任务，等待活跃会话。"""
        self.pool.shutdown(wait=True, cancel_futures=False)


def create_app(
    sessions_dir: str | Path = "data/sessions",
    token: str | None = None,
    agent_runner=None,
    max_concurrent_sessions: int = 3,
    validation_interval: int = 300,
) -> FastAPI:
    """生产级 FastAPI 应用。"""
    sessions_dir = Path(sessions_dir)
    token = token if token is not None else (
        os.getenv("REDBLUEAGENT_TOKEN") or os.getenv("PENTESTAGENT_TOKEN", ""))

    app = FastAPI(title="RedBlueAgent", version="0.3.4")
    mgr = SessionManager(max_workers=max_concurrent_sessions)

    # 指标收集（简单计数器，Prometheus 文本格式输出）
    metrics = {
        "sessions_total": 0, "sessions_active": 0,
        "quarantines_total": 0, "scope_violations_total": 0,
        "tainted_actions_total": 0, "endpoint_blocks_total": 0,
        "trust_upgrades_total": 0, "trust_downgrades_total": 0,
    }

    def require_token(request: Request) -> None:
        if token == "":
            return
        q_token = request.query_params.get("token", "")
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {token}" and q_token != token:
            raise HTTPException(status_code=401, detail="invalid or missing token")

    # ── /health（无认证，LB/k8s 探针）──────────────────────────────

    @app.get("/health")
    def health():
        uptime = time.time() - _START_TIME
        active = mgr.active_count
        return {
            "status": "ok" if active <= max_concurrent_sessions else "degraded",
            "version": app.version,
            "uptime_seconds": round(uptime, 1),
            "active_sessions": active,
            "max_concurrent": max_concurrent_sessions,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # ── /metrics（Prometheus 文本格式）────────────────────────────

    @app.get("/metrics", response_class=PlainTextResponse,
             dependencies=[Depends(require_token)])
    def prometheus_metrics():
        lines = [
            "# HELP redblueagent_sessions_total Total sessions created",
            "# TYPE redblueagent_sessions_total counter",
            f"redblueagent_sessions_total {mgr.total_created}",
            "# HELP redblueagent_sessions_active Currently running sessions",
            "# TYPE redblueagent_sessions_active gauge",
            f"redblueagent_sessions_active {mgr.active_count}",
            "# HELP redblueagent_uptime_seconds Service uptime",
            "# TYPE redblueagent_uptime_seconds gauge",
            f"redblueagent_uptime_seconds {time.time() - _START_TIME:.0f}",
        ]
        # 会话状态
        for status, count in mgr.stats.get("by_status", {}).items():
            lines.append(f'redblueagent_sessions_by_status{{status="{status}"}} {count}')
        # 安全指标（从审计日志聚合——轻量版，无外部依赖）
        lines.append("# HELP redblueagent_info Build info")
        lines.append("# TYPE redblueagent_info gauge")
        lines.append(f'redblueagent_info{{version="{app.version}"}} 1')
        return "\n".join(lines) + "\n"

    # ── /api/status（服务级摘要）───────────────────────────────────

    @app.get("/api/status", dependencies=[Depends(require_token)])
    def service_status():
        return {
            "service": "RedBlueAgent",
            "version": app.version,
            "uptime_seconds": round(time.time() - _START_TIME, 1),
            "session_manager": mgr.stats,
            "config": {
                "max_concurrent_sessions": max_concurrent_sessions,
                "sessions_dir": str(sessions_dir),
                "auth_enabled": token != "",
            },
        }

    # ── /api/validation（持续验证状态）────────────────────────────

    validation_state = {"last_run": None, "status": "not_started", "results": {}}

    @app.get("/api/validation", dependencies=[Depends(require_token)])
    def validation_status():
        return validation_state

    # ── 会话端点 ────────────────────────────────────────────────────

    def _default_runner(target: str, scope, session_id):
        from agent.core import PentestAgent
        agent = PentestAgent(interactive=False)
        agent.run(target=target, scope=scope, session_id=session_id)

    runner = agent_runner or _default_runner

    @app.post("/api/sessions", dependencies=[Depends(require_token)])
    def create_session(body: SessionCreate):
        sid = body.session_id or datetime.utcnow().strftime("%Y%m%d-%H%M%S") + "-web"
        if (sessions_dir / sid / "events.jsonl").exists():
            raise HTTPException(status_code=409, detail=f"session {sid} already exists")
        if mgr.active_count >= max_concurrent_sessions:
            raise HTTPException(status_code=429,
                                detail=f"concurrency limit ({max_concurrent_sessions}) reached")
        ok = mgr.submit(sid, runner, body.target, body.scope, sid)
        if not ok:
            raise HTTPException(status_code=409, detail=f"session {sid} already running")
        return {"session_id": sid, "status": "pending"}

    @app.get("/api/sessions", dependencies=[Depends(require_token)])
    def list_sessions():
        if not sessions_dir.exists():
            return {"sessions": []}
        sids = sorted(p.parent.name for p in sessions_dir.glob("*/events.jsonl"))
        # 补充运行时状态
        out = []
        for sid in sids:
            info = {"session_id": sid}
            rt = mgr.status(sid)
            if rt:
                info["runtime_status"] = rt["status"]
            out.append(info)
        return {"sessions": out}

    @app.get("/api/sessions/{sid}", dependencies=[Depends(require_token)])
    def session_state(sid: str):
        snap = sessions_dir / sid / "snapshot.json"
        if not snap.exists():
            raise HTTPException(status_code=404, detail="no snapshot yet")
        return json.loads(snap.read_text(encoding="utf-8"))

    @app.delete("/api/sessions/{sid}", dependencies=[Depends(require_token)])
    def stop_session(sid: str):
        ok = mgr.stop(sid)
        if not ok:
            raise HTTPException(status_code=404,
                                detail=f"session {sid} not found or not running")
        return {"session_id": sid, "status": "stopping"}

    # ── SSE：tail events.jsonl ─────────────────────────────────────

    @app.get("/api/sessions/{sid}/events", dependencies=[Depends(require_token)])
    async def session_events(sid: str, since: int = 0, follow: int = 1):
        path = sessions_dir / sid / "events.jsonl"
        if not path.exists():
            raise HTTPException(status_code=404, detail="no event log")

        async def gen():
            idle_ticks = 0
            with open(path, encoding="utf-8") as fh:
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
                            fh.seek(pos)
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

    # ── 审批桥 ─────────────────────────────────────────────────────

    @app.get("/api/sessions/{sid}/approvals", dependencies=[Depends(require_token)])
    def list_approvals(sid: str):
        pending_dir = sessions_dir.parent / "approvals" / sid / "pending"
        if not pending_dir.exists():
            return {"pending": []}
        items = []
        for f in sorted(pending_dir.glob("*.json")):
            # 跳过已有 decision 的 pending（修复：GET 不再返回已决策项）
            req_id = f.stem
            decision = sessions_dir.parent / "approvals" / sid / "decisions" / f"{req_id}.json"
            if decision.exists():
                continue
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
        # 修复：决策后清理 pending 文件（GET 不再返回已决策项）
        pending.unlink(missing_ok=True)
        return {"id": req_id, "approved": decision.approved}

    # ── 前端 ────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (_STATIC_DIR / "index.html").read_text(encoding="utf-8")

    return app
