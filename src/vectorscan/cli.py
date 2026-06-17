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
    if items:
        s = items[0]
        text = s["text"] or ""
        print(f"\n[dim]sample — collection '{s['collection']}', id '{s['id']}':[/]")
        print(f"  {text[:160]}{'…' if len(text) > 160 else ''}")
    print("\n[yellow]Next:[/] detection (Day 4) — find the sensitive data inside these items.")
    raise typer.Exit(0)


if __name__ == "__main__":
    app()
