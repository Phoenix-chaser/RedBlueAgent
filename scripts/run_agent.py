#!/usr/bin/env python3
"""
run_agent.py - CLI entry point for the Penetration Testing Agent.

Usage:
    python scripts/run_agent.py --target 192.168.1.100
    python scripts/run_agent.py --target 192.168.1.100 --provider deepseek
    python scripts/run_agent.py --target 192.168.1.100 --provider moonshot --model moonshot-v1-128k
    python scripts/run_agent.py --target 192.168.1.100 --provider zhipu --model glm-4-flash
    python scripts/run_agent.py --session-id <sid>        # resume an interrupted session
    python scripts/run_agent.py --list-providers
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
from rich.console import Console

console = Console()


@click.command()
@click.option("--target", default=None, help="Target IP address or hostname")
@click.option(
    "--scope",
    multiple=True,
    help="In-scope IPs/CIDRs (can specify multiple times). Defaults to target only.",
)
@click.option(
    "--provider",
    default=None,
    help="LLM provider: anthropic | deepseek | moonshot | zhipu | openai",
    type=click.Choice(["anthropic", "deepseek", "moonshot", "zhipu", "openai"], case_sensitive=False),
)
@click.option(
    "--model",
    default=None,
    help=(
        "Model name or alias. Examples:\n"
        "  deepseek-chat, deepseek-reasoner,\n"
        "  moonshot-v1-32k, moonshot-v1-128k,\n"
        "  glm-4, glm-4-flash,\n"
        "  claude-sonnet-4-6"
    ),
)
@click.option(
    "--config",
    default="config.yaml",
    show_default=True,
    help="Path to config.yaml",
)
@click.option(
    "--no-interactive",
    is_flag=True,
    default=False,
    help="Disable interactive approval prompts (auto-deny dangerous operations)",
)
@click.option(
    "--session-id",
    default=None,
    help="Custom session ID. If this session already exists on disk, it is RESUMED "
    "(events replayed, snapshot restored) instead of starting a new one.",
)
@click.option(
    "--list-providers",
    is_flag=True,
    default=False,
    help="List all supported LLM providers and their configuration status",
)
def main(
    target: str | None,
    scope: tuple,
    provider: str | None,
    model: str | None,
    config: str,
    no_interactive: bool,
    session_id: str | None,
    list_providers: bool,
):
    """LLM-Driven Automated Penetration Testing Agent (支持国产大模型)"""
    from dotenv import load_dotenv
    load_dotenv()

    if list_providers:
        from agent.llm_factory import list_providers as _list
        console.print(_list())
        return 0

    if not target and not session_id:
        console.print("[red]ERROR: --target is required (or pass --session-id to resume an existing session).[/red]")
        console.print("Usage: python scripts/run_agent.py --target <IP>")
        console.print("       python scripts/run_agent.py --session-id <sid>   # resume")
        return 1

    # Inject provider/model into env so factory picks them up
    if provider:
        os.environ["LLM_PROVIDER"] = provider
    if model:
        os.environ["LLM_MODEL"] = model

    scope_list = list(scope) if scope else ([target] if target else [])
    interactive = not no_interactive

    resuming = bool(session_id and not target)
    console.print(f"[bold]{'Resuming' if resuming else 'Starting'} penetration test[/bold]")
    if resuming:
        console.print(f"  Session  : [cyan]{session_id}[/cyan]")
    console.print(f"  Target   : [cyan]{target or '(from session state)'}[/cyan]")
    console.print(f"  Scope    : [cyan]{', '.join(scope_list) or '(from session state)'}[/cyan]")
    console.print(f"  Provider : [yellow]{provider or 'auto-detect'}[/yellow]")
    console.print(f"  Model    : [yellow]{model or 'provider default'}[/yellow]")
    console.print(f"  Config   : [dim]{config}[/dim]")

    # Check that at least one API key is set
    from agent.llm_factory import PROVIDER_CONFIGS
    any_key = any(os.getenv(cfg["env_key"]) for cfg in PROVIDER_CONFIGS.values())
    if not any_key:
        console.print("[red]ERROR: No LLM API key found.[/red]")
        console.print("Set one of: ANTHROPIC_API_KEY, DEEPSEEK_API_KEY, MOONSHOT_API_KEY, ZHIPU_API_KEY")
        console.print("Copy .env.example to .env and fill in your API key.")
        return 1

    try:
        from agent.core import PentestAgent
        agent = PentestAgent(config_path=config, interactive=interactive)
        report = agent.run(
            target=target, scope=scope_list or None, session_id=session_id)
        console.print(f"\n[bold green]Report generated successfully.[/bold green]")
        console.print(f"Session ID: {report.session_id}")
        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted.[/yellow]")
        return 1
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
