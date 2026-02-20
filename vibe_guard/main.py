import click
import os
from pathlib import Path
from .rules import hardcoded, rce, sqli, quality, frontend_secrets, insecure_defaults, supabase
from .scorer import calculate_vibe_score, score_label, score_emoji
from .reporter import generate_markdown_report

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
    findings.extend(frontend_secrets.scan_directory(path))
    findings.extend(insecure_defaults.scan_directory(path))
    findings.extend(supabase.scan_directory(path))
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
        report_content = generate_markdown_report(findings, path)
        with open(output, 'w', encoding='utf-8') as fp:
            fp.write(report_content)
    
    if strict and findings:
        raise SystemExit(1)

@main.command()
def init():
    """Initialize vibe-guard rules for AI assistants (Cursor, Windsurf)."""
    rules_content = """# Vibe-Guard Security Rules

You are an AI programming assistant. Security is critical in this project.
After writing or significantly modifying code, you MUST run the security scanner in the background:
`vibe-guard scan .`

If the Vibe Score is below 80, or if you find any 'Critical' issues:
1. DO NOT present the insecure code to the user.
2. Read the Vibe-Guard report.
3. Automatically fix the issues according to the provided hints.
4. Rescan to confirm the code is safe before finishing your task.
"""
    
    files_created = 0
    for filename in ['.cursorrules', '.windsurfrules']:
        path = Path(filename)
        if not path.exists():
            path.write_text(rules_content)
            if RICH:
                console.print(f"[green]Created {filename}[/green]")
            else:
                print(f"Created {filename}")
            files_created += 1
        else:
            if RICH:
                console.print(f"[yellow]{filename} already exists. Skipping.[/yellow]")
            else:
                print(f"{filename} already exists. Skipping.")
    
    if files_created > 0:
        if RICH:
            console.print("\n[bold green]Successfully initialized vibe-guard AI rules![/bold green]")
        else:
            print("\nSuccessfully initialized vibe-guard AI rules!")

@main.command()
@click.argument('path', default='.')
def score(path):
    """Show only the Vibe Score."""
    findings = collect_findings(path)
    s = calculate_vibe_score(findings)
    print(f"{score_emoji(s)} Vibe Score: {s}/100 — {score_label(s)}")

if __name__ == '__main__':
    main()