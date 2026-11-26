"""
LLM Provider Factory - supports Anthropic Claude and domestic Chinese models
(DeepSeek, Kimi/Moonshot, GLM/Zhipu) via OpenAI-compatible API.

Supported providers:
  anthropic  - Claude (Sonnet, Opus, Haiku)
  deepseek   - DeepSeek-V3 / DeepSeek-R1
  moonshot   - Kimi (moonshot-v1-8k / moonshot-v1-32k / moonshot-v1-128k)
  zhipu      - GLM-4 / GLM-4-Flash
  openai     - OpenAI GPT models (bonus)
"""
from __future__ import annotations

import os
from typing import Any


# ---------------------------------------------------------------------------
# Provider configuration table
# ---------------------------------------------------------------------------

PROVIDER_CONFIGS: dict[str, dict] = {
    "anthropic": {
        "env_key": "ANTHROPIC_API_KEY",
        "base_url": None,
        "default_model": "claude-sonnet-4-6",
        "description": "Anthropic Claude (international)",
    },
    "deepseek": {
        "env_key": "DEEPSEEK_API_KEY",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "description": "DeepSeek (国产-深度求索)",
    },
    "moonshot": {
        "env_key": "MOONSHOT_API_KEY",
        "base_url": "https://api.moonshot.cn/v1",
        "default_model": "moonshot-v1-32k",
        "description": "Kimi (国产-月之暗面)",
    },
    "zhipu": {
        "env_key": "ZHIPU_API_KEY",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-4",
        "description": "GLM (国产-智谱AI)",
    },
    "openai": {
        "env_key": "OPENAI_API_KEY",
        "base_url": None,
        "default_model": "gpt-4o",
        "description": "OpenAI GPT",
    },
}

# Model aliases for user convenience
MODEL_ALIASES: dict[str, tuple[str, str]] = {
    # alias -> (provider, model_id)
    "deepseek-v3":      ("deepseek",   "deepseek-chat"),
    "deepseek-r1":      ("deepseek",   "deepseek-reasoner"),
    "deepseek-coder":   ("deepseek",   "deepseek-coder"),
    "kimi":             ("moonshot",   "moonshot-v1-32k"),
    "kimi-8k":          ("moonshot",   "moonshot-v1-8k"),
    "kimi-128k":        ("moonshot",   "moonshot-v1-128k"),
    "glm-4":            ("zhipu",      "glm-4"),
    "glm-4-flash":      ("zhipu",      "glm-4-flash"),
    "glm-4-air":        ("zhipu",      "glm-4-air"),
    "claude-sonnet":    ("anthropic",  "claude-sonnet-4-6"),
    "claude-opus":      ("anthropic",  "claude-opus-4-6"),
    "claude-haiku":     ("anthropic",  "claude-haiku-4-5-20251001"),
}


def create_llm(
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    max_tokens: int = 8192,
    temperature: float = 0.1,
    **kwargs: Any,
):
    """
    Create a LangChain chat model for the specified provider/model.

    Auto-detects provider from:
    1. Explicit `provider` parameter
    2. Model alias lookup (e.g. "deepseek-v3" → deepseek provider)
    3. Environment variables (tries each provider's API key in order)
    4. Falls back to Anthropic

    Examples:
        create_llm(provider="deepseek")
        create_llm(provider="moonshot", model="moonshot-v1-128k")
        create_llm(model="glm-4-flash")
        create_llm(provider="zhipu", api_key="your-key")
    """
    # Resolve model alias
    if model and model in MODEL_ALIASES:
        resolved_provider, resolved_model = MODEL_ALIASES[model]
        provider = provider or resolved_provider
        model = resolved_model

    # Auto-detect provider from environment if not specified
    if not provider:
        provider = _detect_provider()

    provider = provider.lower().strip()

    if provider not in PROVIDER_CONFIGS:
        raise ValueError(
            f"Unknown provider: '{provider}'. "
            f"Supported: {list(PROVIDER_CONFIGS.keys())}"
        )

    cfg = PROVIDER_CONFIGS[provider]
    resolved_model = model or os.getenv("LLM_MODEL") or cfg["default_model"]
    resolved_api_key = api_key or os.getenv(cfg["env_key"]) or ""
    resolved_base_url = base_url or cfg["base_url"]

    if not resolved_api_key:
        raise ValueError(
            f"API key not found for provider '{provider}'. "
            f"Set the {cfg['env_key']} environment variable."
        )

    print(f"[LLM] Provider: {provider} | Model: {resolved_model} | {cfg['description']}")

    if provider == "anthropic":
        return _create_anthropic(resolved_model, resolved_api_key, max_tokens, temperature, **kwargs)
    else:
        return _create_openai_compat(
            resolved_model, resolved_api_key, resolved_base_url,
            max_tokens, temperature, **kwargs
        )


def _create_anthropic(model, api_key, max_tokens, temperature, **kwargs):
    from agent.llm_kernel import MinimalLLMClient
    return MinimalLLMClient(
        provider="anthropic", model=model, api_key=api_key,
        max_tokens=max_tokens, temperature=temperature, **kwargs)


def _create_openai_compat(model, api_key, base_url, max_tokens, temperature, **kwargs):
    """统一走极简内核的 OpenAI 兼容协议（DeepSeek / Kimi / GLM / OpenAI 通用）。

    kwargs 透传给内核（如 max_retries）——以前在这里被悄悄丢掉。"""
    from agent.llm_kernel import MinimalLLMClient
    return MinimalLLMClient(
        provider="openai", model=model, api_key=api_key, base_url=base_url,
        max_tokens=max_tokens, temperature=temperature, **kwargs)


def _detect_provider() -> str:
    """Auto-detect provider by checking which API keys are set."""
    # Priority order for auto-detection
    priority = ["anthropic", "deepseek", "moonshot", "zhipu", "openai"]
    for p in priority:
        if os.getenv(PROVIDER_CONFIGS[p]["env_key"]):
            return p
    return "anthropic"  # Default fallback


def list_providers() -> str:
    """Return a human-readable list of supported providers."""
    lines = ["Supported LLM Providers:", ""]
    for name, cfg in PROVIDER_CONFIGS.items():
        key_status = "✓ SET" if os.getenv(cfg["env_key"]) else "✗ not set"
        lines.append(f"  {name:12} | {cfg['description']:30} | {cfg['env_key']} ({key_status})")
    lines += ["", "Model aliases (use with --model):"]
    for alias, (prov, mid) in MODEL_ALIASES.items():
        lines.append(f"  {alias:20} → {prov}/{mid}")
    return "\n".join(lines)
