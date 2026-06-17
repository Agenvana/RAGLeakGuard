"""vectorscan CLI — point it at a vector store and scan for exposed sensitive data."""
import typer
from rich import print

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Scan your AI's vector database for exposed sensitive data.")


@app.callback()
def main():
    """vectorscan — find sensitive data exposed in your AI's vector store."""


@app.command()
def scan(
    source: str = typer.Option(..., "--source", help="Vector store type: chroma | pinecone"),
    path: str = typer.Option(None, "--path", help="Path or connection string for the store"),
    report: str = typer.Option("report.md", "--report", help="Where to write the report"),
):
    """Scan a vector store and report exposed sensitive data.

    Pipeline (being built): connector -> extract text -> detect -> risk-score -> report.
    """
    source = source.lower()
    if source == "chroma":
        from vectorscan.connectors import read_chroma

        if not path:
            print("[red]--path is required for chroma (the store directory).[/]")
            raise typer.Exit(2)
        items = list(read_chroma(path))
    else:
        print(f"[red]Source '{source}' isn't supported yet (try: chroma).[/]")
        raise typer.Exit(2)

    print(f"[bold]vectorscan[/] read [bold green]{len(items)}[/] item(s) from [bold]{source}[/] at '{path}'.")
    if not items:
        raise typer.Exit(0)

    from collections import Counter

    by_type: Counter = Counter()
    total = flagged = 0
    try:
        from vectorscan.detect import detect

        for it in items:
            found = detect(it["text"])
            if found:
                flagged += 1
            total += len(found)
            by_type.update(f["type"] for f in found)
    except ImportError:
        print("[dim]Detection extras missing — run: pip install 'vectorscan[detect]'[/]")
        raise typer.Exit(0)
    except OSError:
        print("[dim]spaCy model missing — run: python -m spacy download en_core_web_sm[/]")
        raise typer.Exit(0)

    print(f"\n[bold red]⚠  {total}[/] sensitive item(s) found across [bold]{flagged}/{len(items)}[/] records:")
    for entity, count in by_type.most_common():
        print(f"   [yellow]{entity:<16}[/] {count}")

    s = items[0]
    print(f"\n[dim]e.g. record '{s['id']}':[/] {(s['text'] or '')[:120]}…")
    print("\n[dim]Next: a risk-scored report (Week 2) — severity, regulatory mapping, erasure proof.[/]")
    raise typer.Exit(0)


if __name__ == "__main__":
    app()
