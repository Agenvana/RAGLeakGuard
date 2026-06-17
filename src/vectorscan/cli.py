"""vectorscan CLI — point it at a vector store and scan for exposed sensitive data."""
import typer
from rich import print

app = typer.Typer(add_completion=False, help="Scan your AI's vector database for exposed sensitive data.")


@app.command()
def scan(
    source: str = typer.Option(..., "--source", help="Vector store type: chroma | pinecone"),
    path: str = typer.Option(None, "--path", help="Path or connection string for the store"),
    report: str = typer.Option("report.md", "--report", help="Where to write the report"),
):
    """Scan a vector store and report exposed sensitive data.

    Pipeline (being built): connector -> extract text -> detect -> risk-score -> report.
    """
    print(f"[bold yellow]vectorscan[/] — scanning [bold]{source}[/] …")
    print("[dim]Pipeline not implemented yet — see the build plan. (Day 3–5)[/]")
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
