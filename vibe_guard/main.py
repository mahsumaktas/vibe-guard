"""vibe-guard - security scanner for AI-generated code."""
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from vibe_guard.rules import hardcoded, rce, sqli, quality
from vibe_guard.rules.hardcoded import Finding
from vibe_guard.scorer import calculate_vibe_score, score_label, score_emoji

app = typer.Typer(
    help="Security scanner for vibe-coded (AI-generated) code",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

VERSION = "0.0.6"

SEVERITY_COLORS = {
    "critical": "bold red",
    "warning": "yellow",
    "info": "dim cyan",
}

SEVERITY_ICONS = {
    "critical": "",
    "warning": "⚠️",
    "info": "ℹ️",
}


def _scan_path(path: Path) -> list[Finding]:
    """Run all scanners on a file or directory."""
    all_findings: list[Finding] = []

    files: list[Path] = []
    if path.is_file():
        files = [path]
    elif path.is_dir():
        # Collect all non-hidden, non-venv files
        skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
                     '.mypy_cache', '.pytest_cache', 'dist', 'build', '.eggs'}
        for f in path.rglob('*'):
            if f.is_file():
                if any(part in skip_dirs for part in f.parts):
                    continue
                files.append(f)

    for f in files:
        all_findings.extend(hardcoded.scan_file(f))
        all_findings.extend(rce.scan_file(f))
        all_findings.extend(sqli.scan_file(f))
        all_findings.extend(quality.scan_file(f))

    return all_findings


def _print_findings(findings: list[Finding], path: str) -> None:
    """Print findings as a rich table."""
    if not findings:
        console.print("\n[bold green]  No issues found![/bold green]\n")
        return

    table = Table(
        title=f"Findings in [bold]{path}[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Sev", style="bold", width=8)
    table.add_column("Rule", style="cyan", width=24)
    table.add_column("Location", style="dim", width=28)
    table.add_column("Description", width=44)

    for f in sorted(findings, key=lambda x: (
        {"critical": 0, "warning": 1, "info": 2}.get(x.severity.lower(), 3),
        x.filename,
        x.line_number,
    )):
        sev = f.severity.lower()
        icon = SEVERITY_ICONS.get(sev, "?")
        color = SEVERITY_COLORS.get(sev, "white")
        location = f"{Path(f.filename).name}:{f.line_number}"
        table.add_row(
            f"[{color}]{icon} {sev.upper()}[/{color}]",
            f.rule_id,
            location,
            f.description[:60],
        )

    console.print(table)


def _make_report(findings: list[Finding], path: str, score: int) -> str:
    """Generate a Markdown report."""
    label = score_label(score)
    emoji = score_emoji(score)
    lines = [
        f"# vibe-guard Report",
        f"",
        f"**Path:** `{path}`",
        f"**Vibe Score:** {emoji} {score}/100 ({label})",
        f"**Total findings:** {len(findings)}",
        f"",
    ]

    if not findings:
        lines.append("No issues found!")
        return "\n".join(lines)

    # Summary by severity
    critical = [f for f in findings if f.severity.lower() == "critical"]
    warning = [f for f in findings if f.severity.lower() == "warning"]
    info = [f for f in findings if f.severity.lower() == "info"]

    lines += [
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| Critical | {len(critical)} |",
        f"| Warning  | {len(warning)} |",
        f"| Info     | {len(info)} |",
        f"",
        f"## Findings",
        f"",
    ]

    for f in sorted(findings, key=lambda x: (
        {"critical": 0, "warning": 1, "info": 2}.get(x.severity.lower(), 3),
    )):
        lines += [
            f"### [{f.severity.upper()}] {f.rule_id}",
            f"",
            f"- **File:** `{f.filename}:{f.line_number}`",
            f"- **Description:** {f.description}",
            f"- **Code:** `{f.line_content}`",
            f"",
        ]

    return "\n".join(lines)


@app.command()
def scan(
    path: str = typer.Argument(".", help="Directory or file to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file (.md)"),
    strict: bool = typer.Option(False, "--strict", help="Exit with code 1 if any findings"),
    no_score: bool = typer.Option(False, "--no-score", help="Suppress score display"),
) -> None:
    """Scan code for security vulnerabilities and calculate Vibe Score."""
    console.print(f"\n[bold cyan]vibe-guard[/bold cyan] [dim]v{VERSION}[/dim]\n")

    scan_path = Path(path).resolve()
    if not scan_path.exists():
        err_console.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(code=2)

    console.print(f"[dim]Scanning:[/dim] [bold]{path}[/bold]")
    findings = _scan_path(scan_path)

    console.print(f"[dim]Found {len(findings)} issue(s)[/dim]\n")

    _print_findings(findings, path)

    if not no_score:
        score = calculate_vibe_score(findings)
        label = score_label(score)
        emoji = score_emoji(score)

        # Score panel
        sev_color = "green" if score >= 90 else "yellow" if score >= 70 else "orange3" if score >= 50 else "red"
        console.print(Panel(
            f"[bold {sev_color}]{emoji} Vibe Score: {score}/100[/bold {sev_color}]  [dim]{label}[/dim]",
            title="Result",
            border_style=sev_color,
            padding=(0, 2),
        ))

    # Save report
    if output:
        score = calculate_vibe_score(findings)
        report = _make_report(findings, path, score)
        Path(output).write_text(report)
        console.print(f"\n[dim]Report saved to: {output}[/dim]")

    if strict and findings:
        raise typer.Exit(code=1)


@app.command()
def score(
    path: str = typer.Argument(".", help="Directory or file to score"),
) -> None:
    """Show only the Vibe Score without full findings list."""
    scan_path = Path(path).resolve()
    if not scan_path.exists():
        err_console.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(code=2)

    findings = _scan_path(scan_path)
    vibe_score = calculate_vibe_score(findings)
    label = score_label(vibe_score)
    emoji = score_emoji(vibe_score)

    console.print(f"\n{emoji} [bold]{vibe_score}[/bold]/100 - {label}")
    console.print(f"[dim]({len(findings)} findings)[/dim]\n")


if __name__ == "__main__":
    app()
