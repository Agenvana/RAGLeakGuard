"""ragleakguard CLI — point it at a vector store and scan for exposed sensitive data."""
import typer
from rich import print

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Scan your AI's vector database for exposed sensitive data.")


@app.callback()
def main():
    """ragleakguard — find sensitive data exposed in your AI's vector store."""


@app.command()
def scan(
    source: str = typer.Option(..., "--source", help="Vector store type: chroma | pinecone"),
    path: str = typer.Option(None, "--path", help="Path or connection string for the store"),
    report: str = typer.Option("report.md", "--report", help="Where to write the report"),
    locale: str = typer.Option(None, "--locale", help="Locale pack: au | uk | sg | in (adds country recognisers)"),
):
    """Scan a vector store and report exposed sensitive data.

    Pipeline (being built): connector -> extract text -> detect -> risk-score -> report.
    """
    source = source.lower()
    if source == "chroma":
        from ragleakguard.connectors import read_chroma

        if not path:
            print("[red]--path is required for chroma (the store directory).[/]")
            raise typer.Exit(2)
        items = list(read_chroma(path))
    else:
        print(f"[red]Source '{source}' isn't supported yet (try: chroma).[/]")
        raise typer.Exit(2)

    print(f"[bold]ragleakguard[/] read [bold green]{len(items)}[/] item(s) from [bold]{source}[/] at '{path}'.")
    if not items:
        raise typer.Exit(0)

    from collections import Counter

    by_type: Counter = Counter()
    total = flagged = 0
    try:
        from ragleakguard.detect import detect

        for it in items:
            found = detect(it["text"], locale=locale)
            if found:
                flagged += 1
            total += len(found)
            by_type.update(f["type"] for f in found)
    except ImportError:
        print("[dim]Detection extras missing — run: pip install 'ragleakguard[detect]'[/]")
        raise typer.Exit(0)
    except OSError:
        print("[dim]spaCy model missing — run: python -m spacy download en_core_web_sm[/]")
        raise typer.Exit(0)

    print(f"\n[bold red]⚠  {total}[/] sensitive finding(s) across [bold]{flagged}/{len(items)}[/] records:")
    for entity, count in by_type.most_common():
        print(f"   [yellow]{entity:<16}[/] {count}")

    from ragleakguard.report import build_report

    md = build_report(dict(by_type), len(items), flagged, source=source, path=path)
    with open(report, "w", encoding="utf-8") as fh:
        fh.write(md)
    print(f"\n[green]✓[/] Risk-scored report written to [bold]{report}[/].")
    raise typer.Exit(0)


@app.command()
def monitor(
    source: str = typer.Option(..., "--source", help="Vector store type: chroma | pinecone"),
    path: str = typer.Option(None, "--path", help="Path or connection string for the store"),
    locale: str = typer.Option(None, "--locale", help="Locale pack: au (adds country recognisers)"),
    state: str = typer.Option(".rlg-state.json", "--state", help="State file from the last run (fingerprints only — never raw data)"),
    webhook: str = typer.Option(None, "--webhook", help="POST a JSON alert here when findings change (Slack/Discord/Zapier/n8n)"),
    once: bool = typer.Option(True, "--once", help="Run a single check (cron-friendly; the only mode in v1)"),
):
    """Re-scan a store and alert on NEW or CHANGED sensitive findings since the last run.

    First run writes a baseline. Schedule it, e.g.:  0 * * * *  ragleakguard monitor --source chroma --path ./store --state /var/lib/rlg/state.json --webhook https://hooks.example/...

    Exit codes: 0 = no new exposure · 1 = new/changed findings (alert!) · 2 = usage error.
    """
    source = source.lower()
    if source == "chroma":
        from ragleakguard.connectors import read_chroma

        if not path:
            print("[red]--path is required for chroma (the store directory).[/]")
            raise typer.Exit(2)
        items = list(read_chroma(path))
    else:
        print(f"[red]Source '{source}' isn't supported yet (try: chroma).[/]")
        raise typer.Exit(2)

    try:
        from ragleakguard.detect import detect
    except ImportError:
        print("[dim]Detection extras missing — run: pip install 'ragleakguard[detect]'[/]")
        raise typer.Exit(2)

    from ragleakguard import monitor as mon

    try:
        current = mon.build_snapshot(items, detect, locale=locale)
    except OSError:
        print("[dim]spaCy model missing — run: python -m spacy download en_core_web_sm[/]")
        raise typer.Exit(2)

    exposed = sum(1 for r in current.values() if r["n"] > 0)
    total = sum(r["n"] for r in current.values())

    previous = mon.load_state(state)
    if previous is None:
        mon.save_state(state, current, source=source, store_path=path or "")
        print(f"[bold]ragleakguard monitor[/] — baseline saved to [bold]{state}[/]: "
              f"{len(items)} record(s), [bold red]{total}[/] finding(s) in {exposed} record(s).")
        print("[dim]Next runs will diff against this baseline and alert on changes.[/]")
        raise typer.Exit(0)

    delta = mon.diff(previous.get("records", {}), current)
    mon.save_state(state, current, source=source, store_path=path or "")

    n_new, n_chg, n_res = len(delta["new"]), len(delta["changed"]), len(delta["resolved"])
    if n_new == 0 and n_chg == 0:
        print(f"[green]✓[/] No new exposure. {len(items)} record(s) checked, "
              f"{total} known finding(s), {n_res} resolved since last run.")
        raise typer.Exit(0)

    print(f"[bold red]⚠  Exposure change detected[/] — new: [bold]{n_new}[/] · changed: [bold]{n_chg}[/] · resolved: {n_res}")
    for key in delta["new"]:
        types = ", ".join(f"{t}×{c}" for t, c in current[key]["types"].items())
        print(f"   [red]NEW[/]      {key}  [yellow]{types}[/]")
    for key in delta["changed"]:
        types = ", ".join(f"{t}×{c}" for t, c in current[key]["types"].items())
        print(f"   [yellow]CHANGED[/]  {key}  [yellow]{types}[/]")

    if webhook:
        payload = mon.build_webhook_payload(delta, current, source=source, store_path=path or "")
        try:
            status = mon.post_webhook(webhook, payload)
            print(f"[green]✓[/] Webhook alert sent ({status}).")
        except Exception as exc:  # loud failure, never silent
            print(f"[red]Webhook failed:[/] {exc}")

    raise typer.Exit(1)


if __name__ == "__main__":
    app()
