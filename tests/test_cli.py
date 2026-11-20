import gzip
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from vigil import __version__
from vigil.cli import main

DATA = Path(__file__).parent / "data"
SCENARIO = str(DATA / "attack_scenario.log")
ORDINARY = str(DATA / "sample_auth.log")
ATTACK_ORDER = ["ssh-password-spray", "ssh-brute-force", "ssh-success-after-failures"]


def json_records(output: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in output.splitlines()]


def test_a_scan_reports_each_attack_and_exits_with_1(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["scan", SCENARIO])
    out = capsys.readouterr().out

    assert exit_code == 1
    assert "29 lines, 19 login attempts, 3 alerts" in out
    assert [out.index(rule) for rule in ATTACK_ORDER] == sorted(out.index(r) for r in ATTACK_ORDER)
    assert "CRITICAL" in out
    assert "ATT&CK T1110.003 Brute Force: Password Spraying" in out


def test_a_clean_log_exits_with_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", ORDINARY]) == 0
    assert "No alerts." in capsys.readouterr().out


def test_json_output_has_one_object_per_alert(capsys: pytest.CaptureFixture[str]) -> None:
    main(["scan", SCENARIO, "--format", "json"])
    records = json_records(capsys.readouterr().out)

    assert [r["rule_id"] for r in records] == ATTACK_ORDER
    compromise = records[2]
    assert compromise["severity"] == "critical"
    assert compromise["technique"] == "T1110"
    assert compromise["technique_name"] == "Brute Force"
    assert compromise["source_ip"] == "198.51.100.23"
    assert compromise["first_seen"] == "2026-11-17T03:10:00+00:00"
    assert compromise["event_count"] == 7
    evidence = compromise["evidence"]
    assert isinstance(evidence, list)
    assert "Accepted password for root" in evidence[-1]


def test_min_severity_hides_lesser_alerts(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", SCENARIO, "--min-severity", "critical", "--format", "json"]) == 1
    assert [r["rule_id"] for r in json_records(capsys.readouterr().out)] == [ATTACK_ORDER[2]]


def test_evidence_flag_prints_the_original_log_lines(capsys: pytest.CaptureFixture[str]) -> None:
    main(["scan", SCENARIO, "--evidence"])
    assert "Accepted password for root from 198.51.100.23" in capsys.readouterr().out


def test_rotated_and_compressed_logs_are_read_as_one_timeline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lines = Path(SCENARIO).read_text(encoding="utf-8").splitlines(keepends=True)
    older = tmp_path / "auth.log.1.gz"
    with gzip.open(older, "wt", encoding="utf-8") as handle:
        handle.writelines(lines[:15])  # the spray starts in the old, compressed file...
    newer = tmp_path / "auth.log"
    newer.write_text("".join(lines[15:]), encoding="utf-8")  # ...and ends in the new one

    assert main(["scan", str(older), str(newer), "--format", "json"]) == 1
    assert [r["rule_id"] for r in json_records(capsys.readouterr().out)] == ATTACK_ORDER


def test_reads_standard_input_when_given_a_dash(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(Path(SCENARIO).read_text(encoding="utf-8")))
    assert main(["scan", "-"]) == 1
    assert "3 alerts" in capsys.readouterr().out


def test_a_missing_file_is_a_clear_error_not_a_crash(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "no/such/auth.log"]) == 2
    err = capsys.readouterr().err
    assert "no/such/auth.log" in err
    assert "Traceback" not in err


def test_a_corrupt_compressed_file_is_a_clear_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = tmp_path / "auth.log.2.gz"
    broken.write_bytes(b"this is not gzip data")
    assert main(["scan", str(broken)]) == 2
    assert "auth.log.2.gz" in capsys.readouterr().err


def test_invalid_utf8_bytes_do_not_stop_the_scan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "auth.log"
    log.write_bytes(Path(ORDINARY).read_bytes() + b"\xff\xfe\x00 binary junk\n")
    assert main(["scan", str(log)]) == 0


def test_terminal_control_codes_and_look_alike_letters_are_escaped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # "\x1b[2J" clears an analyst's screen; Cyrillic U+0430 looks exactly like Latin "a".
    hostile = (
        "2026-11-17T03:14:09+00:00 web-01 sshd[9]: Failed password for invalid user "
        "\x1b[2J\u0430dmin from 203.0.113.9 port 40000 ssh2\n"
    )
    log = tmp_path / "auth.log"
    log.write_text(hostile * 5, encoding="utf-8")

    assert main(["scan", str(log), "--evidence"]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\\x1b[2J\\u0430dmin" in out


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_a_command_is_required() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main([])
    assert exit_info.value.code == 2


def test_runs_as_a_python_module() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "vigil", "--version"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert __version__ in result.stdout
