"""vibe-guard — security scanner for AI-generated code."""
import typer
from rich.console import Console

app = typer.Typer(help="Security scanner for vibe-coded (AI-generated) code")
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(".", help="Directory or file to scan"),
    output: str = typer.Option(None, help="Save report to file"),
):
    """Scan code for security vulnerabilities and calculate Vibe Score."""
    console.print("[bold green]vibe-guard v0.0.1[/bold green]")
    console.print(f"[dim]Scanning: {path}[/dim]")
    console.print("[yellow]Scanner coming in v0.0.2+[/yellow]")


if __name__ == "__main__":
    app()
