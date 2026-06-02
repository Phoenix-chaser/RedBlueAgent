"""Unit tests for AttackTree."""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.task_planning.attack_tree import AttackTree, AttackNode
from modules.context_management.state_schema import AttackNodeStatus


def make_node(hypothesis: str, tool: str = "nmap", priority: float = 0.8) -> AttackNode:
    return AttackNode(hypothesis=hypothesis, stage="test", tool=tool, priority=priority)


def test_add_root_node():
    tree = AttackTree()
    node = make_node("Scan target for open ports")
    tree.add_root_node(node)
    assert tree.pending_count() == 1


def test_get_next_candidate_returns_highest_priority():
    tree = AttackTree()
    low = make_node("Low priority scan", priority=0.3)
    high = make_node("High priority exploit", priority=0.9)
    tree.add_root_node(low)
    tree.add_root_node(high)

    candidate = tree.get_next_candidate()
    assert candidate is not None
    # High priority should be selected
    assert candidate.priority >= 0.9


def test_mark_node_succeeded():
    tree = AttackTree()
    node = make_node("Test node")
    tree.add_root_node(node)

    tree.mark_node(node.node_id, AttackNodeStatus.SUCCEEDED, evidence="Got shell")
    assert tree.succeeded_count() == 1
    assert tree.pending_count() == 0


def test_mark_node_failed():
    tree = AttackTree()
    node = make_node("Test node")
    tree.add_root_node(node)

    tree.mark_node(node.node_id, AttackNodeStatus.FAILED)
    assert tree.pending_count() == 0


def test_backtrack_finds_sibling():
    tree = AttackTree()
    parent = make_node("Parent")
    tree.add_root_node(parent)

    child1 = make_node("Child 1")
    child2 = make_node("Child 2")
    tree.add_child_node(parent.node_id, child1)
    tree.add_child_node(parent.node_id, child2)

    tree.mark_node(child1.node_id, AttackNodeStatus.FAILED)
    next_node = tree.backtrack(child1.node_id)

    assert next_node is not None
    assert next_node.node_id == child2.node_id


def test_expand_from_llm_suggestions():
    tree = AttackTree()
    parent = make_node("Parent")
    tree.add_root_node(parent)

    suggestions = [
        {"hypothesis": "Try CVE-2021-41773", "stage": "exploitation", "tool": "metasploit", "params": {"module": "exploit/foo"}, "priority": 0.9},
        {"hypothesis": "Try SQLi on login form", "stage": "exploitation", "tool": "sqlmap", "params": {"url": "http://target/login"}, "priority": 0.7},
    ]
    added = tree.expand_from_llm_suggestions(parent.node_id, suggestions)
    assert len(added) == 2
    assert tree.pending_count() == 3  # parent + 2 children


def test_to_prompt_summary():
    tree = AttackTree()
    node = make_node("Scan for services")
    tree.add_root_node(node)
    summary = tree.to_prompt_summary()
    assert "Attack Tree" in summary
    assert "Scan for services" in summary


def test_empty_tree_returns_none():
    tree = AttackTree()
    assert tree.get_next_candidate() is None


def test_all_failed_returns_none():
    tree = AttackTree()
    node = make_node("Failed attempt")
    tree.add_root_node(node)
    tree.mark_node(node.node_id, AttackNodeStatus.FAILED)
    assert tree.get_next_candidate() is None
