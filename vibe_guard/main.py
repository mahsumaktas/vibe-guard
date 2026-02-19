import click
from pathlib import Path
from .rules import hardcoded, rce, sqli, quality
from .scorer import calculate_vibe_score, score_label, score_emoji

try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None

def collect_findings(path: str):
    findings = []
    findings.extend(hardcoded.scan_directory(path))
    findings.extend(rce.scan_directory(path))
    findings.extend(sqli.scan_directory(path))
    findings.extend(quality.scan_directory(path))
    return findings

@click.group()
def main():
    """vibe-guard: Security scanner for AI-generated code."""
    pass

@main.command()
@click.argument('path', default='.')
@click.option('--output', '-o', help='Output report to markdown file')
@click.option('--strict', is_flag=True, help='Exit code 1 if issues found')
def scan(path, output, strict):
    """Scan directory for security issues."""
    findings = collect_findings(path)
    score = calculate_vibe_score(findings)
    
    if RICH:
        console.print(f"\n[bold]vibe-guard[/bold] v0.0.6\n")
        console.print(f"Scanning: {path}\n")
        
        critical = [f for f in findings if f.severity == "critical"]
        warnings = [f for f in findings if f.severity == "warning"]
        infos = [f for f in findings if f.severity == "info"]
        
        if critical:
            console.print(f"[red bold]CRITICAL ({len(critical)})[/red bold]")
            for f in critical:
                console.print(f"  {f.filename}:{f.line_number} — {f.description}")
        
        if warnings:
            console.print(f"\n[yellow bold]WARNING ({len(warnings)})[/yellow bold]")
            for f in warnings:
                console.print(f"  {f.filename}:{f.line_number} — {f.description}")
        
        if infos:
            console.print(f"\n[blue bold]INFO ({len(infos)})[/blue bold]")
            for f in infos:
                console.print(f"  {f.filename}:{f.line_number} — {f.description}")
        
        if not findings:
            console.print("[green]No issues found![/green]")
        
        console.print(f"\nVibe Score: {score_emoji(score)} {score}/100 — {score_label(score)}\n")
    else:
        print(f"vibe-guard v0.0.6")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.filename}:{f.line_number} — {f.description}")
        print(f"\nVibe Score: {score}/100 — {score_label(score)}")
    
    if output:
        with open(output, 'w') as fp:
            fp.write(f"# vibe-guard Security Report\n\n")
            fp.write(f"**Vibe Score: {score}/100** — {score_label(score)}\n\n")
            for f in findings:
                fp.write(f"- [{f.severity.upper()}] `{f.filename}:{f.line_number}` — {f.description}\n")
    
    if strict and findings:
        raise SystemExit(1)

@main.command()
@click.argument('path', default='.')
def score(path):
    """Show only the Vibe Score."""
    findings = collect_findings(path)
    s = calculate_vibe_score(findings)
    print(f"{score_emoji(s)} Vibe Score: {s}/100 — {score_label(s)}")

if __name__ == '__main__':
    main()