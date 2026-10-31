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
"""
from __future__ import annotations

import json
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


class LLMError(RuntimeError):
    pass


class MinimalLLMClient:
    """provider: "openai"（兼容 DeepSeek/Kimi/GLM/OpenAI）或 "anthropic"。"""

    def __init__(self, provider: str, model: str, api_key: str,
                 base_url: str | None = None,
                 max_tokens: int = 8192, temperature: float = 0.1):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.base_url = (base_url or OPENAI_DEFAULT_URL).rstrip("/")
        self.max_tokens = max_tokens
        self.temperature = temperature

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

    def _post(self, url: str, payload: dict, anthropic: bool = False) -> dict:
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
            raise LLMError(f"LLM API {e.code}：{detail}") from e
        except urllib.error.URLError as e:
            raise LLMError(f"LLM API 网络错误：{e}") from e
