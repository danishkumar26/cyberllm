"""CyberLLM command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .analyzer import Analyzer
from .config import Settings
from .reporter import format_event

app = typer.Typer(
    name="cyberllm",
    help="LLM-powered security analysis platform for logs, alerts, and threat intelligence.",
    rich_markup_mode="rich",
)
console = Console()


def _load_settings() -> Settings:
    return Settings.load()


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Path to a log file or '-' for stdin"),
    provider: str = typer.Option(None, help="LLM provider: ollama or openai"),
    model: str = typer.Option(None, help="Model name (e.g. llama3.2, gpt-4o)"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, json, siem"),
    out: str = typer.Option(None, "--out", "-o", help="Write report to file instead of stdout"),
    context: str = typer.Option(None, "--context", "-c", help="Additional context for the analyst"),
    enable_ti: bool = typer.Option(None, "--ti/--no-ti", help="Enable threat intel enrichment"),
) -> None:
    """Analyze a log file and produce a structured security report."""
    settings = _load_settings()
    if provider:
        settings.provider = provider
    if model:
        settings.model = model
    if enable_ti is not None:
        settings.enable_ti = enable_ti

    analyzer = Analyzer(settings)

    if path == "-":
        import sys

        text = sys.stdin.read()
        event = analyzer.analyze_text(text, source="stdin", context=context)
    else:
        p = Path(path)
        if not p.exists():
            console.print(f"[red]Error:[/red] file not found: {path}")
            raise typer.Exit(1)
        events = analyzer.analyze_file(str(p), context=context)
        if not events:
            console.print("[yellow]No analyzable events found.[/yellow]")
            raise typer.Exit(0)
        event = events[0]

    report = format_event(event, format)
    if out:
        Path(out).write_text(report, encoding="utf-8")
        console.print(f"[green]Report written to[/green] {out}")
    else:
        console.print(report)


@app.command()
def version() -> None:
    """Show the CyberLLM version."""
    from . import __version__

    console.print(f"CyberLLM v{__version__}")


@app.command()
def config() -> None:
    """Show the effective configuration."""
    settings = _load_settings()
    table = Table(title="CyberLLM Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    for field in [
        "provider", "model", "ollama_base_url", "temperature", "max_tokens",
        "max_lines", "enable_mitre", "enable_ti", "ti_providers",
        "default_format", "output_dir", "store_corrections", "corrections_dir",
    ]:
        value = getattr(settings, field)
        table.add_row(field, str(value))
    console.print(table)


if __name__ == "__main__":
    app()
