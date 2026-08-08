"""ragleakguard CLI — point it at a vector store and scan for exposed sensitive data."""
from typing import Optional

import typer
from rich import print

from ragleakguard.detect import (
    DetectionError,
    DetectionRuntimeError,
    MalformedLocaleError,
    MissingDetectionDependencyError,
    MissingDetectionModelError,
    UnsupportedLocaleError,
    validate_detection_runtime,
)


EXIT_USAGE = 2
EXIT_DETECTION_RUNTIME = 3

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Scan your AI's vector database for exposed sensitive data.")


@app.callback()
def main():
    """ragleakguard — find sensitive data exposed in your AI's vector store."""


def _abort_detection(error: DetectionError) -> None:
    """Print a static, privacy-safe failure and exit with the documented code."""
    if isinstance(error, MalformedLocaleError):
        print("[red]Invalid locale.[/] Use a two-letter code such as 'au'.")
        raise typer.Exit(EXIT_USAGE)
    if isinstance(error, UnsupportedLocaleError):
        print("[red]Unsupported locale.[/] Available locale packs: au.")
        raise typer.Exit(EXIT_USAGE)
    if isinstance(error, MissingDetectionDependencyError):
        print("[red]Detection unavailable.[/] Install the optional detection dependencies.")
        raise typer.Exit(EXIT_DETECTION_RUNTIME)
    if isinstance(error, MissingDetectionModelError):
        print("[red]Detection unavailable.[/] Install the required spaCy model 'en_core_web_sm'.")
        raise typer.Exit(EXIT_DETECTION_RUNTIME)
    if isinstance(error, DetectionRuntimeError):
        print("[red]Detection unavailable.[/] The detection runtime could not be initialized.")
        raise typer.Exit(EXIT_DETECTION_RUNTIME)
    print("[red]Detection configuration is invalid.[/]")
    raise typer.Exit(EXIT_USAGE)


def _validated_locale(locale: Optional[str]) -> Optional[str]:
    try:
        return validate_detection_runtime(locale)
    except DetectionError as error:
        _abort_detection(error)


@app.command()
def scan(
    source: str = typer.Option(..., "--source", help="Vector store type: chroma | pinecone"),
    path: str = typer.Option(None, "--path", help="Path or connection string for the store"),
    report: str = typer.Option("report.md", "--report", help="Where to write the report"),
    locale: str = typer.Option(
        None,
        "--locale",
        help="Locale pack: au (case-insensitive; surrounding whitespace ignored)",
    ),
):
    """Scan a vector store and report exposed sensitive data.

    Pipeline (being built): connector -> extract text -> detect -> risk-score -> report.

    Exit codes: 0 = completed · 2 = usage/locale error · 3 = detection unavailable.
    """
    source = source.lower()
    if source == "chroma":
        from ragleakguard.connectors import read_chroma

        if not path:
            print("[red]--path is required for chroma (the store directory).[/]")
            raise typer.Exit(EXIT_USAGE)
        locale = _validated_locale(locale)
        items = list(read_chroma(path))
    else:
        print(f"[red]Source '{source}' isn't supported yet (try: chroma).[/]")
        raise typer.Exit(EXIT_USAGE)

    if not items:
        print(f"[bold]ragleakguard[/] read [bold green]0[/] item(s) from [bold]{source}[/] at '{path}'.")
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
    except DetectionError as error:
        _abort_detection(error)

    print(f"[bold]ragleakguard[/] read [bold green]{len(items)}[/] item(s) from [bold]{source}[/] at '{path}'.")
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
    locale: str = typer.Option(
        None,
        "--locale",
        help="Locale pack: au (case-insensitive; surrounding whitespace ignored)",
    ),
    state: str = typer.Option(".rlg-state.json", "--state", help="State file from the last run (fingerprints only — never raw data)"),
    webhook: str = typer.Option(None, "--webhook", help="POST a JSON alert here when findings change (Slack/Discord/Zapier/n8n)"),
    once: bool = typer.Option(True, "--once", help="Run a single check (cron-friendly; the only mode in v1)"),
):
    """Re-scan a store and alert on NEW or CHANGED sensitive findings since the last run.

    First run writes a baseline. Schedule it, e.g.:  0 * * * *  ragleakguard monitor --source chroma --path ./store --state /var/lib/rlg/state.json --webhook https://hooks.example/...

    Exit codes: 0 = no new exposure · 1 = new/changed findings (alert!) ·
    2 = usage/locale error · 3 = detection unavailable.
    """
    source = source.lower()
    if source == "chroma":
        from ragleakguard.connectors import read_chroma

        if not path:
            print("[red]--path is required for chroma (the store directory).[/]")
            raise typer.Exit(EXIT_USAGE)
        locale = _validated_locale(locale)
        items = list(read_chroma(path))
    else:
        print(f"[red]Source '{source}' isn't supported yet (try: chroma).[/]")
        raise typer.Exit(EXIT_USAGE)

    from ragleakguard.detect import detect

    from ragleakguard import monitor as mon

    try:
        current = mon.build_snapshot(items, detect, locale=locale)
    except DetectionError as error:
        _abort_detection(error)

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
