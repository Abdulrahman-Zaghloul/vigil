"""Command-line interface: ``vigil scan /var/log/auth.log``.

Exit codes follow the Unix convention used by tools like grep, so scripts and cron jobs
can react without parsing any output: 0 = no alerts, 1 = alerts found, 2 = error.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections.abc import Iterable, Iterator, Sequence
from typing import TextIO

from vigil import __version__
from vigil.alerts import Alert, Severity
from vigil.attack import TECHNIQUES
from vigil.detection.engine import DetectionEngine, default_rules
from vigil.events import AuthEvent
from vigil.parsers.ssh import parse_lines

EXIT_NO_ALERTS = 0
EXIT_ALERTS = 1
EXIT_ERROR = 2
_INDENT = " " * 10


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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

    minimum = Severity(args.min_severity)
    alerts = [
        alert
        for alert in DetectionEngine(default_rules()).run(events)
        if alert.severity.rank >= minimum.rank
    ]
    if args.format == "json":
        for alert in alerts:
            print(json.dumps(alert_to_dict(alert)))
    else:
        _print_report(alerts, lines=line_count, events=events, evidence=args.evidence)
    return EXIT_ALERTS if alerts else EXIT_NO_ALERTS


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
