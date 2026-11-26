# -*- coding: utf-8 -*-
"""容器集成测试（宿主机侧驱动）：在 agent 镜像里用真实工具打内置靶场。

不调用 LLM：模型由一段固定的动作序列代替，所以不需要 API Key。验证的是
执行链路——真实 nmap / nikto / dirsearch / read_url、真实的准入检查、审批门
对真实命令的判定、蜜标闭环——而不是模型的决策质量。需要真实模型的五个场景
实测仍按 docs/live-test-report.md 进行。

需要：Docker、agent 镜像（REDBLUEAGENT_IMAGE，默认 redblueagent:live，构建方式见
docker/Dockerfile.agent）和内置靶场（未运行时由本测试启动，结束后停止；已在
运行的靶场会被复用，不会被动）。

运行：python -m pytest tests/integration -m docker -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.docker

ROOT = Path(__file__).resolve().parents[2]
AGENT_IMAGE = os.environ.get("REDBLUEAGENT_IMAGE", "redblueagent:live")
TARGET_URL = os.environ.get("REDBLUEAGENT_TARGET", "http://172.20.0.10:5000")
NETWORK = "docker_pentest_net"
COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker" / "docker-compose.yml")]


def _docker(*args, timeout=120, check=True):
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        result = subprocess.CompletedProcess(["docker", *args], 127, "", "docker: command not found")
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
    return result


@pytest.fixture(scope="module")
def target():
    if _docker("image", "inspect", AGENT_IMAGE, check=False).returncode != 0:
        pytest.skip(f"agent image {AGENT_IMAGE} is not built (see docker/Dockerfile.agent)")
    probe = _docker("run", "--rm", "--network", NETWORK, AGENT_IMAGE,
                    "curl", "-fsS", f"{TARGET_URL}/health", check=False)
    started = False
    if probe.returncode != 0:
        _docker(*COMPOSE, "up", "-d", "--wait", "target", timeout=420)
        started = True
    yield
    if started:   # only a range this test started is stopped again
        _docker(*COMPOSE, "stop", "target", check=False)


@pytest.fixture(scope="module")
def pytest_site(tmp_path_factory):
    """A site-packages directory holding only pytest and its dependencies.

    The image has no test dependencies, and pytest is pure Python, so this
    directory is mounted into the container as-is. It is built in a throwaway
    venv rather than taken from the running interpreter, whose site-packages may
    hold compiled extensions for another Python version.
    REDBLUEAGENT_PYTEST_PATH overrides it with an existing directory.
    """
    override = os.environ.get("REDBLUEAGENT_PYTEST_PATH")
    if override:
        return Path(override)
    minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    venv = tmp_path_factory.mktemp("pytest-env") / "venv"
    if shutil.which("uv"):
        subprocess.run(["uv", "venv", str(venv), "--python", minor],
                       check=True, capture_output=True, timeout=300)
        install = ["uv", "pip", "install", "--python", str(venv / "bin" / "python"), "pytest"]
    else:
        try:
            subprocess.run([sys.executable, "-m", "venv", str(venv)],
                           check=True, capture_output=True, timeout=300)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("need uv, or a Python whose venv module works, to build a pytest-only environment")
        install = [str(venv / "bin" / "python"), "-m", "pip", "install", "-q", "pytest"]
    try:
        subprocess.run(install, check=True, capture_output=True, text=True, timeout=600)
    except subprocess.CalledProcessError as error:
        pytest.skip(f"could not install pytest into the throwaway venv:\n{error.stderr}")
    return venv / "lib" / f"python{minor}" / "site-packages"


def test_real_tools_against_the_built_in_range(target, pytest_site):
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", NETWORK,
         "-v", f"{ROOT}:/src:ro",
         "-v", f"{pytest_site}:/pytest:ro",
         "-w", "/src",
         "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/src:/pytest",
         "-e", "REDBLUEAGENT_IN_CONTAINER=1", "-e", f"REDBLUEAGENT_TARGET={TARGET_URL}",
         AGENT_IMAGE, "python3", "-m", "pytest",
         "tests/integration/in_container", "-q", "-p", "no:cacheprovider",
         "-W", "ignore::DeprecationWarning", "--durations=5"],
        capture_output=True, text=True, timeout=1500)
    output = result.stdout + result.stderr
    print(output)
    assert result.returncode == 0, output
    assert "skipped" not in output.rsplit("=", 1)[-1], output[-400:]
