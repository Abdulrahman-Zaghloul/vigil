"""Command-line interface: ``vigil scan``, ``vigil db upgrade`` and ``vigil serve``.

Exit codes follow the Unix convention used by tools like grep, so scripts and cron jobs
can react without parsing any output: 0 = no alerts, 1 = alerts found, 2 = error.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import TextIO

from vigil import __version__
from vigil.alerts import Alert, Severity
from vigil.attack import TECHNIQUES
from vigil.detection.engine import DetectionEngine, default_rules
from vigil.events import AuthEvent
from vigil.parsers.ssh import parse_lines

EXIT_OK = 0
EXIT_NO_ALERTS = EXIT_OK
EXIT_ALERTS = 1
EXIT_ERROR = 2
_INDENT = " " * 10
DATABASE_URL_VARIABLE = "VIGIL_DATABASE_URL"
API_TOKEN_VARIABLE = "VIGIL_API_TOKEN"  # noqa: S105 - the variable's name, not a secret
_NO_DB_EXTRA = "vigil: database support is not installed; run: pip install 'vigil[db]'"


class LogReadError(Exception):
    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"cannot read {path}: {reason}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigil", description="Detect attacks in security logs.")
    parser.add_argument("--version", action="version", version=f"vigil {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = commands.add_parser(
        "scan",
        help="scan SSH authentication logs for attacks",
        description="Scan SSH authentication logs and report attacks.",
    )
    scan.add_argument(
        "paths",
        nargs="+",
        metavar="LOG",
        help="log files to read; .gz files are decompressed; '-' reads standard input",
    )
    scan.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="text for people (default), or json: one JSON object per alert, per line",
    )
    scan.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default=Severity.LOW.value,
        help="only report alerts at or above this severity (default: low)",
    )
    scan.add_argument(
        "--evidence",
        action="store_true",
        help="print the log lines behind each alert (text format)",
    )
    scan.add_argument(
        "--save",
        action="store_true",
        help="also store every event and alert in PostgreSQL (needs the db extra)",
    )
    _add_database_url_option(scan)
    scan.set_defaults(handler=_scan)

    db = commands.add_parser("db", help="manage the PostgreSQL database")
    db_commands = db.add_subparsers(dest="db_command", required=True, metavar="ACTION")
    upgrade = db_commands.add_parser("upgrade", help="create or update the database tables")
    _add_database_url_option(upgrade)
    upgrade.set_defaults(handler=_db_upgrade)

    serve = commands.add_parser(
        "serve",
        help="run the web API",
        description=f"Run the web API. The API token is read from ${API_TOKEN_VARIABLE} only, "
        "never from the command line, so it cannot leak into process lists.",
    )
    serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="address to listen on (default: 127.0.0.1, this machine only; "
        "0.0.0.0 accepts connections from the network)",
    )
    serve.add_argument("--port", type=int, default=8000, help="port to listen on (default: 8000)")
    _add_database_url_option(serve)
    serve.set_defaults(handler=_serve)
    return parser


def _add_database_url_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database-url",
        metavar="URL",
        help=(
            f"PostgreSQL URL; defaults to ${DATABASE_URL_VARIABLE}. Prefer the variable: "
            "command-line arguments show up in process lists and shell history"
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    return handler(args)


def _scan(args: argparse.Namespace) -> int:
    line_count = 0

    def counted(lines: Iterable[str]) -> Iterator[str]:
        nonlocal line_count
        for line in lines:
            line_count += 1
            yield line

    try:
        events = list(parse_lines(counted(_read_lines(args.paths, sys.stdin))))
    except LogReadError as error:
        print(f"vigil: {error}", file=sys.stderr)
        return EXIT_ERROR

    all_alerts = DetectionEngine(default_rules()).run(events)
    minimum = Severity(args.min_severity)
    alerts = [alert for alert in all_alerts if alert.severity.rank >= minimum.rank]
    if args.format == "json":
        for alert in alerts:
            print(json.dumps(alert_to_dict(alert)))
    else:
        _print_report(alerts, lines=line_count, events=events, evidence=args.evidence)

    # --min-severity only filters what is shown; the database keeps every alert.
    if args.save and not _save(args, events, all_alerts):
        return EXIT_ERROR
    return EXIT_ALERTS if alerts else EXIT_NO_ALERTS


def _database_url(args: argparse.Namespace) -> str | None:
    url = args.database_url or os.environ.get(DATABASE_URL_VARIABLE)
    if not url:
        print(
            f"vigil: no database configured; set {DATABASE_URL_VARIABLE} or pass --database-url",
            file=sys.stderr,
        )
    return url


def _database_error(error: Exception) -> str:
    """The driver's own first line, which names the problem but never the password."""
    original = getattr(error, "orig", None) or error
    first_line = str(original).strip().splitlines()[0] if str(original).strip() else ""
    return f"vigil: database error: {type(original).__name__}: {first_line}"


def _save(args: argparse.Namespace, events: list[AuthEvent], alerts: list[Alert]) -> bool:
    url = _database_url(args)
    if url is None:
        return False
    try:
        from sqlalchemy.exc import SQLAlchemyError

        from vigil.storage.store import Store
    except ImportError:
        print(_NO_DB_EXTRA, file=sys.stderr)
        return False
    try:
        store = Store.connect(url)
        try:
            result = store.save(events, alerts)
        finally:
            store.close()
    except SQLAlchemyError as error:
        print(_database_error(error), file=sys.stderr)
        return False
    # Status messages go to stderr, so stdout stays pure data (e.g. JSON for other tools).
    print(
        f"vigil: saved {result.events_added} new events and {result.alerts_added} new alerts",
        file=sys.stderr,
    )
    return True


def _db_upgrade(args: argparse.Namespace) -> int:
    url = _database_url(args)
    if url is None:
        return EXIT_ERROR
    try:
        from sqlalchemy.exc import SQLAlchemyError

        from vigil.storage.migrate import upgrade
    except ImportError:
        print(_NO_DB_EXTRA, file=sys.stderr)
        return EXIT_ERROR
    try:
        upgrade(url)
    except SQLAlchemyError as error:
        print(_database_error(error), file=sys.stderr)
        return EXIT_ERROR
    print("vigil: database is up to date")
    return EXIT_OK


def _read_lines(paths: Iterable[str], stdin: TextIO) -> Iterator[str]:
    """Yield every line of every file, in the order given, without loading whole files.

    Logs may contain bytes that are not valid UTF-8 (attackers choose usernames), so
    undecodable bytes are replaced instead of crashing the scan.
    """
    for path in paths:
        if path == "-":
            yield from stdin
            continue
        try:
            with _open_text(path) as handle:
                yield from handle
        except OSError as error:  # missing file, no permission, corrupt .gz, ...
            raise LogReadError(path, error.strerror or str(error)) from error


def _open_text(path: str) -> TextIO:
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def alert_to_dict(alert: Alert) -> dict[str, object]:
    known = TECHNIQUES.get(alert.technique)
    return {
        "rule_id": alert.rule_id,
        "severity": alert.severity.value,
        "title": alert.title,
        "technique": alert.technique,
        "technique_name": known.name if known else None,
        "tactic": known.tactic if known else None,
        "source_ip": str(alert.source_ip),
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "event_count": alert.event_count,
        "evidence": [event.raw for event in alert.evidence],
    }


def safe(text: str) -> str:
    """Make untrusted text safe for a terminal: keep printable ASCII, escape the rest.

    Log lines can smuggle terminal control codes that clear, rewrite or hide what an
    analyst sees, and look-alike letters (Cyrillic U+0430 posing as a Latin "a").
    Escaping both shows exactly what is really there.
    """
    return "".join(
        char if " " <= char <= "~" else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def _print_report(
    alerts: list[Alert], *, lines: int, events: list[AuthEvent], evidence: bool
) -> None:
    plural = "" if len(alerts) == 1 else "s"
    print(
        f"vigil {__version__}: scanned {lines} lines, "
        f"{len(events)} login attempts, {len(alerts)} alert{plural}"
    )
    if not alerts:
        print("No alerts.")
        return
    for alert in alerts:
        known = TECHNIQUES.get(alert.technique)
        name = f" {known.name}" if known else ""
        print()
        print(f"{alert.severity.value.upper():<10}{_time_range(alert)}  {alert.rule_id}")
        print(f"{_INDENT}{safe(alert.title)}")
        print(f"{_INDENT}ATT&CK {alert.technique}{name} - {alert.event_count} events")
        if evidence:
            for event in alert.evidence:
                print(f"{_INDENT}  {safe(event.raw)}")


def _time_range(alert: Alert) -> str:
    start, end = alert.first_seen, alert.last_seen
    end_format = "%H:%M:%S" if start.date() == end.date() else "%Y-%m-%d %H:%M:%S"
    return f"{start:%Y-%m-%d %H:%M:%S} -> {end:{end_format}} UTC"


def _serve(args: argparse.Namespace) -> int:
    url = _database_url(args)
    if url is None:
        return EXIT_ERROR
    try:
        import uvicorn

        from vigil.api.app import MIN_TOKEN_LENGTH, create_app
        from vigil.storage.store import Store
    except ImportError:
        print("vigil: the web API is not installed; run: pip install 'vigil[api]'", file=sys.stderr)
        return EXIT_ERROR

    token = os.environ.get(API_TOKEN_VARIABLE, "")
    if len(token) < MIN_TOKEN_LENGTH:
        print(
            f"vigil: set {API_TOKEN_VARIABLE} to a random secret of at least "
            f"{MIN_TOKEN_LENGTH} characters, for example:\n"
            '  python -c "import secrets; print(secrets.token_urlsafe(32))"',
            file=sys.stderr,
        )
        return EXIT_ERROR

    uvicorn.run(
        create_app(store=Store.connect(url), api_token=token), host=args.host, port=args.port
    )
    return EXIT_OK
