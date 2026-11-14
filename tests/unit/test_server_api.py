# -*- coding: utf-8 -*-
"""Unit tests for the HTTP service layer (P2-3).

Covers: bearer auth, session listing, snapshot state, non-following SSE
replay (since-cursor), and the file-approval HTTP bridge. Skipped
automatically when fastapi isn't installed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from server.app import create_app  # noqa: E402

TOKEN = "test-token"


def make_client(tmp_path: Path, sessions: dict | None = None) -> TestClient:
    for sid, events in (sessions or {}).items():
        d = tmp_path / "sessions" / sid
        d.mkdir(parents=True)
        (d / "events.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n",
            encoding="utf-8")
    app = create_app(sessions_dir=tmp_path / "sessions", token=TOKEN)
    return TestClient(app)


def auth(client: TestClient) -> dict:
    return {"Authorization": f"Bearer {TOKEN}"}


def seed_events():
    return [
        {"seq": 1, "t": "start", "d": {"target": "192.168.1.100", "scope": ["192.168.1.100"]}},
        {"seq": 2, "t": "action", "d": {"thought": "scan", "action": {"tool": "nmap"}}},
        {"seq": 3, "t": "finish", "d": {"iterations": 2, "vulnerabilities": 0}},
    ]


# -- auth ----------------------------------------------------------------------


def test_missing_token_401(tmp_path):
    client = make_client(tmp_path)
    assert client.get("/api/sessions").status_code == 401
    assert client.get("/api/sessions", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_token_grants_access(tmp_path):
    client = make_client(tmp_path, sessions={"s1": seed_events()})
    assert client.get("/api/sessions", headers=auth(client)).status_code == 200


# -- sessions ------------------------------------------------------------------


def test_list_sessions(tmp_path):
    client = make_client(tmp_path, sessions={"s1": seed_events(), "s2": seed_events()})
    r = client.get("/api/sessions", headers=auth(client))
    assert [s["session_id"] for s in r.json()["sessions"]] == ["s1", "s2"]


def test_unknown_session_events_404(tmp_path):
    client = make_client(tmp_path)
    assert client.get("/api/sessions/nope/events", headers=auth(client)).status_code == 404


# -- SSE replay -----------------------------------------------------------------


def test_events_replay_since_cursor(tmp_path):
    client = make_client(tmp_path, sessions={"s1": seed_events()})
    r = client.get("/api/sessions/s1/events?since=1&follow=0", headers=auth(client))
    assert r.status_code == 200
    body = r.text
    # only seq 2 and 3 are replayed; the finish event closes the stream
    assert '"seq": 2' in body and '"seq": 3' in body
    assert '"seq": 1,' not in body
    assert '"t": "finish"' in body


def test_events_replay_all_by_default(tmp_path):
    client = make_client(tmp_path, sessions={"s1": seed_events()})
    r = client.get("/api/sessions/s1/events?follow=0", headers=auth(client))
    assert '"seq": 1' in r.text and '"seq": 3' in r.text


# -- approval bridge -------------------------------------------------------------


def seed_approval(tmp_path: Path, sid: str = "s1", req_id: str = "r1"):
    pending = tmp_path / "approvals" / sid / "pending"
    pending.mkdir(parents=True, exist_ok=True)
    (pending / f"{req_id}.json").write_text(
        json.dumps({"id": req_id, "tool": "metasploit", "params": {}}),
        encoding="utf-8")


def test_approval_list_and_decide(tmp_path):
    seed_approval(tmp_path)
    client = make_client(tmp_path, sessions={"s1": seed_events()})

    r = client.get("/api/sessions/s1/approvals", headers=auth(client))
    assert [p["id"] for p in r.json()["pending"]] == ["r1"]

    r = client.post("/api/sessions/s1/approvals/r1",
                    headers=auth(client), json={"approved": True})
    assert r.json() == {"id": "r1", "approved": True}
    decision = tmp_path / "approvals" / "s1" / "decisions" / "r1.json"
    assert json.loads(decision.read_text(encoding="utf-8"))["approved"] is True

    # decided requests disappear from pending listing
    # (pending file remains for audit; the gate consumes the decision)
    assert client.post("/api/sessions/s1/approvals/unknown",
                       headers=auth(client), json={"approved": True}).status_code == 404


def test_create_session_spawns_runner(tmp_path):
    started = []

    def fake_runner(target, scope, session_id):
        started.append((target, scope, session_id))

    app = create_app(sessions_dir=tmp_path / "sessions", token=TOKEN,
                     agent_runner=fake_runner)
    client = TestClient(app)
    r = client.post("/api/sessions", headers=auth(client),
                    json={"target": "192.168.1.100"})
    assert r.status_code == 200
    sid = r.json()["session_id"]
    assert started and started[0][0] == "192.168.1.100" and started[0][2] == sid


def test_create_session_conflict_409(tmp_path):
    client = make_client(tmp_path, sessions={"s1": seed_events()})
    r = client.post("/api/sessions", headers=auth(client),
                    json={"target": "192.168.1.100", "session_id": "s1"})
    assert r.status_code == 409


def test_query_token_for_eventsource(tmp_path):
    """EventSource cannot send Authorization headers; SSE must accept ?token=."""
    client = make_client(tmp_path, sessions={"s1": seed_events()})
    r = client.get("/api/sessions/s1/events?follow=0&token=" + TOKEN)
    assert r.status_code == 200 and '"seq": 3' in r.text
    # wrong query token still rejected
    assert client.get("/api/sessions/s1/events?token=wrong").status_code == 401
