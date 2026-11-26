# -*- coding: utf-8 -*-
"""LLM Kernel —— 零依赖的极简 LLM 客户端（替代 LangChain）。

设计动机（去框架化）：
本项目对 LLM 层的全部需求是「把一组消息发给某家模型、拿回一段文本」。
LangChain 在此场景下引入了庞大的依赖树与版本兼容负担，收益却只有
两个薄封装类。本内核用纯标准库实现同一接口（约百行）：

  - OpenAI 兼容协议（DeepSeek / Kimi / GLM / OpenAI 通用，仅 base_url 不同）
  - Anthropic Messages 原生协议（system 提取 + x-api-key 鉴权）
  - 消息类型 SystemMessage / HumanMessage / AIMessage 与调用接口
    invoke(messages) -> LLMResponse(.content)，与原 LangChain 用法
    逐位兼容——react_loop / summarizer / generator 的调用代码零改动。

不做抽象基类、不做回调链、不做 token 计数——需要时再加。
2026-11（P1-3）：加入传输层韧性——瞬态错误（429/5xx/超时/网络抖动）指数退避重试，
永久错误（401/402/403 等鉴权与计费类）立即失败并给出可行动提示；429 触发账户级
冷却闸门（跨 invoke 生效），避免下一轮立即再撞限速。思想取自 SPECTRE 的 pi.mjs（lalalala5678/spectre，MIT）。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


# ────────────────────────── 消息类型 ──────────────────────────
@dataclass
class _Message:
    content: str

    def __str__(self) -> str:  # 兼容原有 f-string 用法
        return self.content


class SystemMessage(_Message):
    role = "system"


class HumanMessage(_Message):
    role = "user"


class AIMessage(_Message):
    role = "assistant"


@dataclass
class LLMResponse:
    content: str
    raw: dict = field(default_factory=dict)


# ────────────────────────── 客户端 ──────────────────────────
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
OPENAI_DEFAULT_URL = "https://api.openai.com/v1"
TIMEOUT_SECONDS = 300

# 瞬态可重试：限速 / 请求超时 / 服务端错误。其余 4xx 视为永久（鉴权/计费/参数）。
RETRYABLE_STATUS = {408, 409, 429}
PERMANENT_HINT = {401: "检查 API Key 是否正确",
                  402: "账户余额不足，请充值",
                  403: "无权使用该模型/接口，检查套餐与权限"}


class LLMError(RuntimeError):
    """status: HTTP 状态码（网络错误为 None）；transient: 是否值得重试。"""

    def __init__(self, msg: str, status: int | None = None,
                 transient: bool | None = None):
        super().__init__(msg)
        self.status = status
        self.transient = transient


class MinimalLLMClient:
    """provider: "openai"（兼容 DeepSeek/Kimi/GLM/OpenAI）或 "anthropic"。"""

    def __init__(self, provider: str, model: str, api_key: str,
                 base_url: str | None = None,
                 max_tokens: int = 8192, temperature: float = 0.1,
                 max_retries: int = 3,
                 retry_base_delay: float = 5.0,
                 retry_max_delay: float = 60.0,
                 sleep_fn=time.sleep, now_fn=time.monotonic):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.base_url = (base_url or OPENAI_DEFAULT_URL).rstrip("/")
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.max_retries = max_retries
        self.retry_base_delay = retry_base_delay
        self.retry_max_delay = retry_max_delay
        self.sleep_fn = sleep_fn
        self.now_fn = now_fn
        # 账户级限速闸门：429 后指数冷却（5s×2^strikes，封顶 60s），
        # 后续 invoke 先过闸再请求，防止连环撞限速
        self._gate_until = 0.0
        self._strikes = 0

    # ── 传输层：单次请求 ──
    def _post_once(self, url: str, payload: dict, anthropic: bool = False) -> dict:
        headers = {"Content-Type": "application/json"}
        if anthropic:
            headers |= {"x-api-key": self.api_key,
                        "anthropic-version": ANTHROPIC_VERSION}
        else:
            headers |= {"Authorization": f"Bearer {self.api_key}"}
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:400]
            status = e.code
            transient = status in RETRYABLE_STATUS or status >= 500
            hint = PERMANENT_HINT.get(status, "")
            msg = f"LLM API {status}：{detail}" + (f"（{hint}）" if hint else "")
            raise LLMError(msg, status=status, transient=transient) from e
        except urllib.error.URLError as e:
            # 网络层抖动（DNS/连接/超时）——按瞬态处理，重试可自愈
            raise LLMError(f"LLM API 网络错误：{e}", transient=True) from e

    # ── 传输层：重试 + 限速闸门 ──
    def _wait_for_gate(self) -> None:
        remaining = self._gate_until - self.now_fn()
        if remaining > 0:
            print(f"[LLM] 限速冷却中，等待 {remaining:.0f}s 后再请求")
            self.sleep_fn(remaining)

    def _note_rate_limit(self) -> None:
        self._strikes += 1
        self._gate_until = self.now_fn() + min(
            5.0 * (2 ** (self._strikes - 1)), self.retry_max_delay)

    def _post(self, url: str, payload: dict, anthropic: bool = False) -> dict:
        attempt = 0
        while True:
            self._wait_for_gate()
            try:
                body = self._post_once(url, payload, anthropic)
                self._strikes = 0
                self._gate_until = 0.0
                return body
            except LLMError as e:
                transient = e.transient if e.transient is not None else True
                if e.status == 429:
                    self._note_rate_limit()
                if not transient or attempt >= self.max_retries:
                    raise
                delay = min(self.retry_base_delay * (2 ** attempt),
                            self.retry_max_delay)
                print(f"[LLM] 临时错误，{delay:.0f}s 后重试 "
                      f"({attempt + 1}/{self.max_retries}): {str(e)[:120]}")
                self.sleep_fn(delay)
                # 退避睡眠已满足闸门冷却，避免同一轮里双重等待
                self._gate_until = 0.0
                attempt += 1

    # ── 对外主接口：与 LangChain ChatModel.invoke 兼容 ──
    def invoke(self, messages) -> LLMResponse:
        if self.provider == "anthropic":
            system, rest = self._split_system(messages)
            payload = dict(model=self.model, max_tokens=self.max_tokens,
                           temperature=self.temperature, messages=rest)
            if system:
                payload["system"] = system
            body = self._post(ANTHROPIC_URL, payload, anthropic=True)
            text = "".join(b.get("text", "") for b in body.get("content", []))
        else:
            payload = dict(
                model=self.model, max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[dict(role=getattr(m, "role", "user"), content=str(m.content))
                          for m in messages])
            body = self._post(f"{self.base_url}/chat/completions", payload)
            try:
                text = body["choices"][0]["message"]["content"]
            except (KeyError, IndexError) as e:
                raise LLMError(f"响应格式异常：{json.dumps(body, ensure_ascii=False)[:400]}") from e
        return LLMResponse(content=text, raw=body)

    # ── 内部 ──
    @staticmethod
    def _split_system(messages):
        system, rest = [], []
        for m in messages:
            if getattr(m, "role", "") == "system":
                system.append(str(m.content))
            else:
                rest.append(dict(role=getattr(m, "role", "user"),
                                 content=str(m.content)))
        return "\n\n".join(system), rest
