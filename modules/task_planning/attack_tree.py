"""
AttackTree - dynamic attack path planning with backtracking support.
Uses UCB1-inspired scoring to balance exploration vs exploitation.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4

from modules.context_management.state_schema import AttackNodeStatus


@dataclass
class AttackNode:
    hypothesis: str
    stage: str
    tool: str
    suggested_params: dict = field(default_factory=dict)
    priority: float = 1.0       # LLM-assigned confidence (0-1)
    node_id: str = field(default_factory=lambda: str(uuid4())[:8])
    parent_id: Optional[str] = None
    children: list["AttackNode"] = field(default_factory=list)
    status: AttackNodeStatus = AttackNodeStatus.PENDING
    evidence: Optional[str] = None
    visit_count: int = 0
    success_count: int = 0


class AttackTree:
    """
    Tree of hypotheses the agent can explore.
    - add_node(): LLM proposes new attack hypotheses
    - get_next_candidate(): returns highest-priority PENDING node (UCB1-scored)
    - mark_node(): updates node status after tool execution
    - backtrack(): finds sibling of a failed node to try next
    """

    def __init__(self):
        self._nodes: dict[str, AttackNode] = {}
        self._root_ids: list[str] = []
        self._total_visits: int = 0

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_root_node(self, node: AttackNode) -> None:
        self._nodes[node.node_id] = node
        self._root_ids.append(node.node_id)

    def add_child_node(self, parent_id: str, child: AttackNode) -> bool:
        if parent_id not in self._nodes:
            return False
        child.parent_id = parent_id
        self._nodes[child.node_id] = child
        self._nodes[parent_id].children.append(child)
        return True

    def expand_from_llm_suggestions(
        self, parent_id: str, suggestions: list[dict]
    ) -> list[AttackNode]:
        """Add multiple child nodes from LLM-generated list of dicts."""
        added = []
        for s in suggestions:
            node = AttackNode(
                hypothesis=s.get("hypothesis", ""),
                stage=s.get("stage", ""),
                tool=s.get("tool", ""),
                suggested_params=s.get("params", {}),
                priority=float(s.get("priority", 0.5)),
            )
            if self.add_child_node(parent_id, node):
                added.append(node)
        return added

    def mark_node(
        self,
        node_id: str,
        status: AttackNodeStatus,
        evidence: str = "",
    ) -> None:
        if node_id not in self._nodes:
            return
        node = self._nodes[node_id]
        node.status = status
        node.evidence = evidence
        node.visit_count += 1
        self._total_visits += 1
        if status == AttackNodeStatus.SUCCEEDED:
            node.success_count += 1

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get_next_candidate(self) -> AttackNode | None:
        """
        Returns the highest-scored PENDING leaf node.
        Score = priority * (1 - failure_rate) + exploration_bonus
        """
        candidates = [n for n in self._nodes.values() if n.status == AttackNodeStatus.PENDING]
        if not candidates:
            return None

        def score(n: AttackNode) -> float:
            # Unvisited nodes: assume zero fail rate (optimistic initialization)
            fail_rate = (
                (n.visit_count - n.success_count) / n.visit_count
                if n.visit_count > 0 else 0.0
            )
            exploit_score = n.priority * (1 - fail_rate)
            explore_bonus = math.sqrt(
                math.log(max(self._total_visits, 1)) / max(n.visit_count, 1)
            ) * 0.3
            return exploit_score + explore_bonus

        return max(candidates, key=score)

    def backtrack(self, failed_node_id: str) -> AttackNode | None:
        """
        Walk up from failed node, find first PENDING sibling or cousin.
        Returns the next candidate to try after backtracking.
        """
        node = self._nodes.get(failed_node_id)
        if node is None:
            return None

        # Walk up the tree looking for pending siblings
        current = node
        while current.parent_id:
            parent = self._nodes.get(current.parent_id)
            if parent is None:
                break
            for sibling in parent.children:
                if sibling.node_id != current.node_id and sibling.status == AttackNodeStatus.PENDING:
                    return sibling
            current = parent

        # No siblings found - look for any pending node in the whole tree
        return self.get_next_candidate()

    def get_all_nodes(self) -> list[AttackNode]:
        return list(self._nodes.values())

    def pending_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.status == AttackNodeStatus.PENDING)

    def succeeded_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.status == AttackNodeStatus.SUCCEEDED)

    # ------------------------------------------------------------------
    # Prompt representation
    # ------------------------------------------------------------------

    def to_prompt_summary(self) -> str:
        if not self._nodes:
            return "Attack tree: (empty - no hypotheses yet)"

        lines = ["Attack Tree:"]
        for node_id in self._root_ids:
            lines.extend(self._format_node(node_id, indent=0))

        summary = "\n".join(lines)
        # Cap at 2000 chars for context efficiency
        if len(summary) > 2000:
            summary = summary[:1950] + "\n... (truncated)"
        return summary

    def _format_node(self, node_id: str, indent: int) -> list[str]:
        node = self._nodes.get(node_id)
        if not node:
            return []

        prefix = "  " * indent
        status_icon = {
            AttackNodeStatus.PENDING: "⬜",
            AttackNodeStatus.IN_PROGRESS: "🔄",
            AttackNodeStatus.SUCCEEDED: "✅",
            AttackNodeStatus.FAILED: "❌",
            AttackNodeStatus.SKIPPED: "⏭",
        }.get(node.status, "?")

        lines = [f"{prefix}{status_icon} [{node.tool}] {node.hypothesis} (p={node.priority:.1f})"]

        for child in node.children:
            lines.extend(self._format_node(child.node_id, indent + 1))

        return lines
