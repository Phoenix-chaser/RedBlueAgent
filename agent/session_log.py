"""
SessionEventLog - append-only event journal + snapshots + instance lock.

WAL discipline adopted from SPECTRE (backend/src/persist.mjs):
- The "action" event is flushed+fsynced BEFORE the tool subprocess runs, so a
  crash can never lose the record of a side effect that already happened
  (write-ahead: journal first, side effect second).
- The last line may be torn by a crash mid-write; recovery drops it with a
  warning. A corrupt line in the MIDDLE is not explainable by a crash and is
  fatal (prefix guarantee).
- Snapshots (state + event seq) are acceleration, not truth: recovery loads
  the latest snapshot, then replays only events with a higher seq.
- An instance lock (O_CREAT|O_EXCL + PID) prevents two processes from running
  the same session against the same data directory; stale locks (dead PID)
  are reclaimed.

Event types (all entries: {"seq", "ts", "t", "d"}):
- start          d={target, scope}                       — session bootstrap
- action         d={iteration, thought, action}          — BEFORE tool exec (WAL)
- observation    d={iteration, thought, action, kind, payload} — after update
- llm_error      same shape as observation, kind=text     — LLM failure turn
- stage_advance  d={from, to, iteration}
- finish         d={iterations, vulnerabilities}         — agent signalled done
- resume         d={note}                                — re-run after crash
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from modules.context_management.state_schema import (
    ActionDecision,
    PentestStage,
    PentestState,
    ToolResult,
)

EVENTS_FILE = "events.jsonl"
SNAPSHOT_FILE = "snapshot.json"
LOCK_FILE = "session.lock"


class EventLog:
    """Append-only JSONL journal with fsync-before-ack + torn-tail tolerance."""

    def __init__(self, session_dir: Path | str):
        self.session_dir = Path(session_dir)
        self.path = self.session_dir / EVENTS_FILE
        self._fh = None
        self._seq = 0

    # -- write side ---------------------------------------------------------

    def open(self) -> "EventLog":
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        if self.path.exists():
            for entry in self._read_entries(strict=True):
                self._seq = max(self._seq, int(entry.get("seq", 0)))
        self._fh = open(self.path, "a", encoding="utf-8")
        return self

    def append(self, t: str, d: dict) -> int:
        """Write one event; flush+fsync before returning (WAL contract)."""
        if self._fh is None:
            self.open()
        self._seq += 1
        entry = {
            "seq": self._seq,
            "ts": datetime.utcnow().isoformat(),
            "t": t,
            "d": d,
        }
        self._fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        return self._seq

    @property
    def seq(self) -> int:
        return self._seq

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    # -- read side ----------------------------------------------------------

    def _read_entries(self, strict: bool = True) -> list[dict]:
        if not self.path.exists():
            return []
        lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
        entries: list[dict] = []
        errors: list[tuple[int, str]] = []
        for idx, line in enumerate(lines):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                errors.append((idx, str(e)))
        for idx, err in errors:
            if idx == len(lines) - 1:
                # Torn tail from a crash mid-write — expected, drop it
                print(f"[SessionLog] 检测到撕裂尾行（进程中断所致），已丢弃: {err}")
            elif strict:
                raise RuntimeError(
                    f"事件日志第 {idx + 1} 行损坏且非尾行——不是进程中断可解释的，"
                    f"疑似磁盘级损坏，拒绝重放: {err}"
                )
        return entries

    def read_all(self) -> list[dict]:
        return self._read_entries(strict=True)

    # -- snapshot side ------------------------------------------------------

    def checkpoint(self, state: PentestState) -> None:
        """Atomically write a snapshot tagged with the current event seq."""
        snap = self.session_dir / SNAPSHOT_FILE
        tmp = snap.with_name(SNAPSHOT_FILE + ".tmp")
        payload = {
            "saved_at": datetime.utcnow().isoformat(),
            "events_seq": self._seq,
            "state": json.loads(state.model_dump_json()),
        }
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(snap)
        # fsync the directory so the rename is durable
        dir_fd = os.open(self.session_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def load_snapshot(self) -> tuple[PentestState, int] | None:
        snap = self.session_dir / SNAPSHOT_FILE
        if not snap.exists():
            return None
        payload = json.loads(snap.read_text(encoding="utf-8"))
        return PentestState(**payload["state"]), int(payload["events_seq"])

    def save_tool_output(self, result, iteration: int) -> str:
        """Archive the full raw output of one tool run; returns the path.

        The truncated marker the LLM sees points here — the cheap local
        equivalent of SPECTRE's seq-completion channel.
        """
        out_dir = self.session_dir / "tool_outputs"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_tool = "".join(c if c.isalnum() or c in "-_" else "_" for c in result.tool)
        path = out_dir / f"{iteration:04d}_{safe_tool}.txt"
        path.write_text(
            f"# tool: {result.tool}\n# iteration: {iteration}\n"
            f"# command: {result.command}\n\n"
            f"## stdout ({len(result.raw_stdout)} chars)\n{result.raw_stdout}\n\n"
            f"## stderr ({len(result.raw_stderr)} chars)\n{result.raw_stderr}\n",
            encoding="utf-8",
        )
        return str(path)


class SessionLock:
    """O_CREAT|O_EXCL lock file holding the PID; stale locks are reclaimed."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._held = False

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                old_pid = int(self.path.read_text().strip() or "0")
            except ValueError:
                old_pid = 0
            if old_pid and self._pid_alive(old_pid):
                return False  # genuinely held by a live process
            self.path.unlink(missing_ok=True)  # stale — reclaim
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        try:
            os.write(fd, str(os.getpid()).encode())
        finally:
            os.close(fd)
        self._held = True
        return True

    def release(self) -> None:
        if self._held:
            self.path.unlink(missing_ok=True)
            self._held = False

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # alive, owned by another user


# -- replay -----------------------------------------------------------------


def replay_into_state(
    state: PentestState,
    events: list[dict],
    context_mgr,
) -> tuple[PentestState, dict | None, set[int]]:
    """Rebuild state by replaying events (those after the snapshot's seq).

    Observation/llm_error events are self-contained (thought+action+payload),
    so replay re-runs the real ContextManager merge path. Returns
    (state, interrupted_action_or_None, action_hashes):
    - interrupted_action: the trailing "action" event with no observation —
      a turn cut in half by a crash (腰斩回合).
    - action_hashes: hashes of every executed action, to seed the loop's
      repeated-action guard after resume.
    """
    interrupted: dict | None = None
    hashes: set[int] = set()

    for e in events:
        t = e.get("t")
        d = e.get("d") or {}
        if t == "action":
            interrupted = d
            a = d.get("action") or {}
            tool = a.get("tool")
            if tool:
                hashes.add(
                    hash(
                        (
                            tool,
                            json.dumps(a.get("params") or {}, sort_keys=True, ensure_ascii=False),
                        )
                    )
                )
        elif t in ("observation", "llm_error"):
            interrupted = None
            action = ActionDecision(**(d.get("action") or {"type": "wait"}))
            payload = d.get("payload")
            if d.get("kind") == "tool_result":
                observation: ToolResult | str = ToolResult(**payload)
            else:
                observation = str(payload or "")
            state = context_mgr.update(
                state, str(d.get("thought") or ""), action, observation
            )
        elif t == "stage_advance":
            try:
                state.current_stage = PentestStage(d["to"])
            except Exception:
                pass  # unknown stage label from an older log — keep snapshot value
        elif t == "finish":
            state.current_stage = PentestStage.REPORT_GENERATION

    return state, interrupted, hashes
