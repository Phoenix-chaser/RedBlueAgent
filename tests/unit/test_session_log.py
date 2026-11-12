"""Unit tests for the session WAL: EventLog, SessionLock, replay (P1-1).

Covers the persistence contract adopted from SPECTRE:
fsync-before-ack, torn-tail tolerance, fatal mid-file corruption,
snapshot+tail replay, interrupted-turn (腰斩) detection, instance locking.
"""
import os
import subprocess
import sys
import pytest


from agent.session_log import (
    EVENTS_FILE,
    LOCK_FILE,
    EventLog,
    SessionLock,
    replay_into_state,
)
from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import (
    ActionDecision,
    PentestStage,
    PentestState,
    ToolResult,
)


def make_state() -> PentestState:
    return PentestState(session_id="wal-test", target="192.168.1.100", scope=["192.168.1.100"])


def nmap_result() -> ToolResult:
    return ToolResult(
        tool="nmap",
        command="nmap -oX - 192.168.1.100",
        success=True,
        parsed={
            "hosts": [
                {
                    "ip": "192.168.1.100",
                    "state": "up",
                    "ports": [
                        {"port": 23, "protocol": "tcp", "state": "open",
                         "service": "telnet", "version": ""}
                    ],
                }
            ]
        },
    )


# -- EventLog -----------------------------------------------------------------


def test_eventlog_roundtrip_and_seq_continuity(tmp_path):
    log = EventLog(tmp_path).open()
    log.append("start", {"target": "192.168.1.100", "scope": ["192.168.1.100"]})
    log.append("observation", {
        "iteration": 1, "thought": "t", "action": {"type": "wait"},
        "kind": "text", "payload": "hi",
    })
    assert log.seq == 2
    log.close()

    log2 = EventLog(tmp_path).open()
    assert log2.seq == 2  # seq continues across reopens
    entries = log2.read_all()
    assert [e["t"] for e in entries] == ["start", "observation"]
    log2.append("finish", {"iterations": 1, "vulnerabilities": 0})
    assert log2.seq == 3


def test_torn_tail_dropped_not_fatal(tmp_path, capsys):
    log = EventLog(tmp_path).open()
    log.append("start", {"target": "x", "scope": ["x"]})
    log.append("observation", {
        "iteration": 1, "thought": "t", "action": {"type": "wait"},
        "kind": "text", "payload": "hi",
    })
    log.close()

    # Simulate a crash mid-write: half a line without newline
    with open(tmp_path / EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write('{"seq": 3, "t": "obs')

    log2 = EventLog(tmp_path).open()
    entries = log2.read_all()
    assert len(entries) == 2  # torn tail dropped
    assert "撕裂" in capsys.readouterr().out


def test_midfile_corruption_is_fatal(tmp_path):
    log = EventLog(tmp_path).open()
    log.append("start", {"target": "x", "scope": ["x"]})
    log.append("observation", {
        "iteration": 1, "thought": "t", "action": {"type": "wait"},
        "kind": "text", "payload": "hi",
    })
    log.close()

    lines = (tmp_path / EVENTS_FILE).read_text(encoding="utf-8").splitlines()
    lines[0] = "{corrupted beyond repair"
    (tmp_path / EVENTS_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError):
        EventLog(tmp_path).open()


def test_snapshot_roundtrip(tmp_path):
    log = EventLog(tmp_path).open()
    state = make_state()
    log.append("start", {"target": state.target, "scope": list(state.scope)})
    log.checkpoint(state)

    snap = EventLog(tmp_path).open().load_snapshot()
    assert snap is not None
    restored, seq = snap
    assert seq == 1
    assert restored.target == "192.168.1.100"
    assert restored.scope == ["192.168.1.100"]
    assert restored.session_id == "wal-test"


# -- SessionLock -----------------------------------------------------------------


def test_lock_acquire_release_and_double_acquire(tmp_path):
    lock = SessionLock(tmp_path / LOCK_FILE)
    assert lock.acquire() is True
    assert int((tmp_path / LOCK_FILE).read_text()) == os.getpid()

    other = SessionLock(tmp_path / LOCK_FILE)
    assert other.acquire() is False  # held by our live PID

    lock.release()
    assert SessionLock(tmp_path / LOCK_FILE).acquire() is True


def test_stale_lock_is_reclaimed(tmp_path):
    # Spawn a child, wait for it to die, use its PID as the stale holder
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    (tmp_path / LOCK_FILE).write_text(str(proc.pid))

    lock = SessionLock(tmp_path / LOCK_FILE)
    assert lock.acquire() is True


# -- replay -----------------------------------------------------------------


def test_replay_rebuilds_state_and_merges():
    cm = ContextManager()
    state = make_state()
    tr = nmap_result()
    action = {"type": "tool", "tool": "nmap", "params": {"target": "192.168.1.100"}}
    events = [
        {"seq": 1, "t": "start", "d": {"target": state.target, "scope": list(state.scope)}},
        {"seq": 2, "t": "action", "d": {"iteration": 1, "thought": "scan host", "action": action}},
        {"seq": 3, "t": "observation", "d": {
            "iteration": 1, "thought": "scan host", "action": action,
            "kind": "tool_result", "payload": tr.model_dump()}},
        {"seq": 4, "t": "stage_advance", "d": {
            "from": "target_confirmation",
            "to": PentestStage.INFORMATION_GATHERING.value, "iteration": 1}},
    ]
    state2, interrupted, hashes = replay_into_state(state, events, cm)

    assert interrupted is None
    assert len(state2.llm_turns) == 1
    assert state2.total_iterations == 1
    assert state2.hosts and state2.hosts[0].ip == "192.168.1.100"
    # telnet → dangerous-service auto-inference re-ran on replay
    assert any("Telnet" in v.title for v in state2.vulnerabilities)
    assert hashes  # repeated-action guard seeded
    assert state2.current_stage == PentestStage.INFORMATION_GATHERING


def test_replay_detects_interrupted_action():
    cm = ContextManager()
    state = make_state()
    events = [
        {"seq": 1, "t": "start", "d": {"target": state.target, "scope": list(state.scope)}},
        {"seq": 2, "t": "action", "d": {
            "iteration": 1, "thought": "test sqli",
            "action": {"type": "tool", "tool": "sqlmap",
                       "params": {"url": "http://192.168.1.100/?id=1"}}}},
    ]
    state2, interrupted, hashes = replay_into_state(state, events, cm)
    assert interrupted is not None
    assert interrupted["action"]["tool"] == "sqlmap"
    assert len(state2.llm_turns) == 0  # half turn never materialized
    assert hashes


def test_full_wal_cycle_snapshot_then_crash_then_resume(tmp_path):
    """End-to-end: two completed turns → snapshot → action logged → 'crash'."""
    log = EventLog(tmp_path).open()
    state = make_state()
    log.append("start", {"target": state.target, "scope": list(state.scope)})

    cm = ContextManager()
    nmap_action = ActionDecision(type="tool", tool="nmap", params={"target": "192.168.1.100"})
    wait_action = ActionDecision(type="wait")
    for i, obs in enumerate([nmap_result(), "plain text observation"]):
        action = nmap_action if i == 0 else wait_action
        state = cm.update(state, f"think {i}", action, obs)
        log.append("observation", {
            "iteration": state.total_iterations, "thought": f"think {i}",
            "action": action.model_dump(),
            "kind": "tool_result" if i == 0 else "text",
            "payload": obs.model_dump() if i == 0 else str(obs),
        })
    log.checkpoint(state)

    # Crash mid-turn: the action was fsynced, the observation never came
    log.append("action", {
        "iteration": 3, "thought": "enumerate web",
        "action": {"type": "tool", "tool": "dirsearch",
                   "params": {"url": "http://192.168.1.100/"}},
    })
    log.close()

    # --- resume path ---
    log2 = EventLog(tmp_path).open()
    snap = log2.load_snapshot()
    assert snap is not None
    restored, seq = snap

    tail = [e for e in log2.read_all() if e["seq"] > seq]
    restored, interrupted, hashes = replay_into_state(restored, tail, ContextManager())

    assert len(restored.llm_turns) == 2
    assert restored.hosts[0].ip == "192.168.1.100"
    assert interrupted is not None
    assert interrupted["action"]["tool"] == "dirsearch"
    assert hashes  # nmap + dirsearch hashes survive for the no-repeat guard


def test_collect_action_hashes_covers_pre_snapshot_history():
    """Live-test M2 finding: hashes must come from the WHOLE log, else actions
    executed before the last snapshot could be re-run after resume."""
    from agent.session_log import collect_action_hashes
    events = [
        {"seq": 1, "t": "start", "d": {"target": "t", "scope": ["t"]}},
        {"seq": 2, "t": "action", "d": {"thought": "a", "action": {
            "type": "tool", "tool": "nmap", "params": {"target": "192.168.1.100"}}}},
        {"seq": 3, "t": "observation", "d": {
            "iteration": 1, "thought": "a",
            "action": {"type": "tool", "tool": "nmap", "params": {"target": "192.168.1.100"}},
            "kind": "text", "payload": "ok"}},
        # snapshot boundary here (seq=3); crash after seq=4's action
        {"seq": 4, "t": "action", "d": {"thought": "b", "action": {
            "type": "tool", "tool": "nikto", "params": {"target": "http://192.168.1.100"}}}},
    ]
    hashes = collect_action_hashes(events)
    assert len(hashes) == 2  # nmap (pre-snapshot) + nikto (post-snapshot)


def test_endpoint_key_ignores_query_and_scheme():
    from agent.session_log import endpoint_key
    a = endpoint_key("sqlmap", {"url": "http://172.20.0.13:3000/rest/product/search?q=1&level=5"})
    b = endpoint_key("sqlmap", {"url": "https://172.20.0.13:3000/rest/product/search?q=999"})
    assert a == b == ("sqlmap", "172.20.0.13:3000/rest/product/search")
    # 裸 host（nmap target）与带端口 URL 不同键；不同 path 不同键
    assert endpoint_key("nmap", {"target": "172.20.0.13"}) == ("nmap", "172.20.0.13/")
    assert endpoint_key("sqlmap", {"url": "http://h:1/a"}) != endpoint_key("sqlmap", {"url": "http://h:1/b"})
    assert endpoint_key(None, {"target": "x"}) is None


def test_collect_endpoint_counts_from_events():
    from agent.session_log import collect_endpoint_counts
    events = [
        {"seq": 1, "t": "action", "d": {"action": {"tool": "sqlmap", "params": {"url": "http://h:1/p?q=1"}}}},
        {"seq": 2, "t": "action", "d": {"action": {"tool": "sqlmap", "params": {"url": "http://h:1/p?q=2"}}}},
        {"seq": 3, "t": "action", "d": {"action": {"tool": "sqlmap", "params": {"url": "http://h:1/p?q=3"}}}},
        {"seq": 4, "t": "action", "d": {"action": {"tool": "nmap", "params": {"target": "h"}}}},
    ]
    counts = collect_endpoint_counts(events)
    assert counts[("sqlmap", "h:1/p")] == 3
    assert counts[("nmap", "h/")] == 1
