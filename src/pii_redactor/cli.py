"""
Command-line interface for the Privacy PII Redactor.

Usage:
    pii-redactor redact "Contact John at john@example.com"
    pii-redactor redact-file input.txt --output sanitized.txt
    pii-redactor detect input.txt --json
    pii-redactor serve
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="pii-redactor",
    help=(
        "Privacy-First PII Redactor — detect and redact sensitive information "
        "from text before it reaches external AI providers."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
err_console = Console(stderr=True)


def _make_redactor(
    language: str = "en",
    presidio: bool = False,
    spacy: bool = False,
):
    """Create a PrivacyRedactor configured for CLI use."""
    from pii_redactor import PrivacyRedactor
    from pii_redactor.config import Settings

    settings = Settings(
        enable_presidio=presidio,
        enable_spacy=spacy,
        enable_regex=True,
        default_language=language,
    )
    return PrivacyRedactor(config=settings)


# ── Commands ──────────────────────────────────────────────────────────────────


@app.command()
def redact(
    text: str = typer.Argument(..., help="Text to redact"),
    language: str = typer.Option("en", "--language", "-l", help="ISO 639-1 language code"),
    show_mapping: bool = typer.Option(
        False, "--show-mapping", "-m", help="Print placeholder→type mapping to stderr"
    ),
    presidio: bool = typer.Option(False, "--presidio", hidden=True, help="Enable Presidio"),
    spacy: bool = typer.Option(False, "--spacy", hidden=True, help="Enable spaCy"),
) -> None:
    """
    [bold]Redact PII[/bold] from a text string.

    Prints the redacted text to stdout. Original values are never printed unless
    [cyan]--show-mapping[/cyan] is supplied.

    Examples:

        pii-redactor redact "Email me at alice@example.com"
        pii-redactor redact "4111 1111 1111 1111" --show-mapping
    """
    r = _make_redactor(language, presidio, spacy)
    result = r.redact(text, language=language)
    console.print(result.redacted_text)

    if show_mapping and result.mapping:
        err_console.print("\n[dim]Placeholder mapping (placeholder → entity type):[/dim]")
        for placeholder in result.mapping:
            err_console.print(f"  [cyan]{placeholder}[/cyan]")


@app.command("redact-file")
def redact_file(
    input_file: Path = typer.Argument(..., help="Path to the input text file"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Path to write the redacted output (default: stdout)"
    ),
    language: str = typer.Option("en", "--language", "-l", help="ISO 639-1 language code"),
    show_mapping: bool = typer.Option(
        False, "--show-mapping", "-m", help="Print placeholder count to stderr"
    ),
    presidio: bool = typer.Option(False, "--presidio", hidden=True),
    spacy: bool = typer.Option(False, "--spacy", hidden=True),
) -> None:
    """
    [bold]Redact PII from a file[/bold].

    Reads *INPUT_FILE*, redacts all detected PII, and either writes the result
    to *OUTPUT* (if provided) or prints it to stdout.

    Examples:

        pii-redactor redact-file prompt.txt
        pii-redactor redact-file prompt.txt --output sanitized.txt
    """
    if not input_file.exists():
        err_console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(1)

    try:
        text = input_file.read_text(encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[red]Error reading file:[/red] {exc}")
        raise typer.Exit(1) from exc

    r = _make_redactor(language, presidio, spacy)
    result = r.redact(text, language=language)

    if output:
        try:
            output.write_text(result.redacted_text, encoding="utf-8")
            console.print(f"[green]✓[/green] Redacted output written to [bold]{output}[/bold]")
        except OSError as exc:
            err_console.print(f"[red]Error writing output:[/red] {exc}")
            raise typer.Exit(1) from exc
    else:
        console.print(result.redacted_text)

    if show_mapping:
        err_console.print(
            f"\n[dim]{len(result.mapping)} placeholder(s) allocated.[/dim]"
        )


@app.command()
def detect(
    source: str = typer.Argument(
        ..., help="Text string or path to a text file to analyse"
    ),
    language: str = typer.Option("en", "--language", "-l", help="ISO 639-1 language code"),
    output_json: bool = typer.Option(
        False, "--json", help="Output detected entities as JSON"
    ),
    presidio: bool = typer.Option(False, "--presidio", hidden=True),
    spacy: bool = typer.Option(False, "--spacy", hidden=True),
) -> None:
    """
    [bold]Detect PII entities[/bold] in text without redacting.

    The source can be a literal text string or a file path.

    Examples:

        pii-redactor detect "Call me at +1-555-123-4567"
        pii-redactor detect report.txt --json
    """
    source_path = Path(source)
    if source_path.exists():
        try:
            text = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            err_console.print(f"[red]Error reading file:[/red] {exc}")
            raise typer.Exit(1) from exc
    else:
        text = source

    r = _make_redactor(language, presidio, spacy)
    entities = r.detect(text, language=language)

    if output_json:
        data = [
            {
                "entity_type": e.entity_type,
                "start": e.start,
                "end": e.end,
                "confidence": round(e.confidence, 4),
                "source": e.source,
                "span_length": e.span_length,
            }
            for e in entities
        ]
        console.print_json(json.dumps(data))
        return

    if not entities:
        console.print("[green]No PII entities detected.[/green]")
        return

    table = Table(title="Detected PII Entities", show_header=True, header_style="bold")
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Start", justify="right")
    table.add_column("End", justify="right")
    table.add_column("Confidence", justify="right")
    table.add_column("Source", style="dim")

    for e in entities:
        table.add_row(
            e.entity_type,
            str(e.start),
            str(e.end),
            f"{e.confidence:.2f}",
            e.source,
        )

    console.print(table)
    console.print(
        f"\n[bold]{len(entities)}[/bold] entity/entities detected in "
        f"[bold]{len(text)}[/bold] characters"
    )


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-H", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (development)"),
    log_level: str = typer.Option("info", "--log-level", help="uvicorn log level"),
) -> None:
    """
    [bold]Start the FastAPI HTTP server[/bold].

    Launches a uvicorn server hosting the PII Redactor REST API on
    [cyan]http://HOST:PORT[/cyan]. Documentation available at [cyan]/docs[/cyan].

    Example:

        pii-redactor serve --port 8080
    """
    try:
        import uvicorn
    except ImportError:
        err_console.print("[red]uvicorn is not installed.[/red] Install it with: pip install uvicorn")
        raise typer.Exit(1)

    console.print(
        f"[green]Starting PII Redactor API[/green] on [bold]http://{host}:{port}[/bold]"
    )
    uvicorn.run(
        "pii_redactor.api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level,
    )


if __name__ == "__main__":
    app()
