"""llmscan CLI — `python -m llmscan scan ...`"""
from __future__ import annotations

from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from . import targets as T
from .detect import evaluate
from .report import risk_grade, write_html, write_markdown

app = typer.Typer(add_completion=False, help="llmscan - an OWASP-LLM-Top-10 red-team scanner for LLM apps.")
console = Console()


@app.callback()
def _main() -> None:
    """llmscan - red-team your LLM apps for prompt injection & system-prompt leaks."""
    # Keeps `scan` as an explicit subcommand (room for `probes`, `report`, … later).


def _load_probes(path: str | None) -> dict:
    src = Path(path) if path else Path(__file__).parent / "probes.yaml"
    return yaml.safe_load(src.read_text(encoding="utf-8"))


def _print_table(results: list[dict]) -> None:
    table = Table(show_header=True, header_style="bold")
    table.add_column("Probe")
    table.add_column("OWASP")
    table.add_column("Sev")
    table.add_column("Result")
    for r in results:
        status = "[red]VULNERABLE[/]" if r["vulnerable"] else "[green]pass[/]"
        if r.get("judged") and not r["vulnerable"]:
            status = "[green]pass[/] [dim](judged)[/]"
        table.add_row(f"{r['id']} {r['name']}", r["owasp"].split(':')[0], r["severity"], status)
    console.print(table)


@app.command()
def scan(
    model: str = typer.Option(..., "--model", "-m", help="Target model id, e.g. llama3.1 or gpt-4o-mini"),
    provider: str = typer.Option("ollama", "--provider", "-p", help="ollama | openai | anthropic"),
    base_url: str = typer.Option(None, "--base-url", help="Override the API base URL"),
    system_prompt: str = typer.Option(None, "--system-prompt", "-s", help="The system prompt to protect (defaults to the built-in demo app)"),
    probes: str = typer.Option(None, "--probes", help="Path to a custom probes.yaml"),
    out: str = typer.Option("llmscan-report.md", "--out", "-o", help="Markdown report output path"),
    html: str = typer.Option(None, "--html", help="Also write an HTML report to this path"),
    judge: bool = typer.Option(False, "--judge/--no-judge", help="Enable LLM-as-judge for nuanced probes"),
    judge_model: str = typer.Option(None, "--judge-model", help="Model to use as the judge (default: the target model)"),
    judge_provider: str = typer.Option(None, "--judge-provider", help="Provider for the judge model (default: the target provider)"),
) -> None:
    """Run the probe suite against a target LLM and report vulnerabilities."""
    cfg = _load_probes(probes)
    canary = cfg.get("canary", "")
    sysp = (system_prompt or cfg.get("default_system_prompt", "")).replace("{{CANARY}}", canary)
    target = T.load_target(provider, model, base_url, sysp)

    judge_fn = None
    if judge:
        jt = T.load_target(judge_provider or provider, judge_model or model, None, None)
        judge_fn = lambda p: T.query(jt, p)  # noqa: E731 — small adapter closure

    probe_list = cfg.get("probes", [])
    extras = "  [judge on]" if judge else ""
    console.print(f"[bold]llmscan[/] → {provider}:{model}  ({len(probe_list)} probes){extras}\n")

    results: list[dict] = []
    for p in probe_list:
        try:
            response = T.query(target, p["prompt"])
        except Exception as e:  # network/auth/etc. — record, don't crash the run
            response = f"[error: {e}]"
        verdict = evaluate(response, p, canary, judge_fn=judge_fn)
        results.append({**p, "response": response, **verdict})

    _print_table(results)
    write_markdown(out, provider, model, results)
    if html:
        write_html(html, provider, model, results)

    vulns = sum(1 for r in results if r["vulnerable"])
    grade = risk_grade(results)
    colour = "red" if vulns else "green"
    console.print(
        f"\n[bold {colour}]{vulns}/{len(results)} probes found a vulnerability[/]  "
        f"·  risk grade [bold]{grade}[/]  ·  report → {out}"
        + (f" + {html}" if html else "")
    )
    raise typer.Exit(code=1 if vulns else 0)  # non-zero so it can gate CI


if __name__ == "__main__":
    app()
