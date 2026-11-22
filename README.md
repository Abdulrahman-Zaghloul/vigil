# Vigil

[![CI](https://github.com/Abdulrahman-Zaghloul/vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/Abdulrahman-Zaghloul/vigil/actions/workflows/ci.yml)

A lightweight threat-detection engine. Vigil reads security logs, spots attacks
such as SSH brute-force and password spraying, and raises alerts mapped to
[MITRE ATT&CK](https://attack.mitre.org/).

> **Status:** early development, built in public one part at a time.

## Detections

| Rule | Fires when | ATT&CK | Severity |
| --- | --- | --- | --- |
| `ssh-brute-force` | One address fails 5+ logins within 1 minute | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Medium |
| `ssh-password-spray` | One address fails against 10+ different accounts within 10 minutes | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Medium |
| `ssh-success-after-failures` | An address logs in after 5+ failures within 15 minutes | [T1110](https://attack.mitre.org/techniques/T1110/) | High, Critical for `root` |

Every threshold is configurable, and each alert carries the exact log lines that triggered it.

## Roadmap

- [x] Repository foundation
- [x] Python project skeleton and first test
- [x] Continuous integration on every push
- [x] SSH authentication log parser
- [x] Brute-force detection
- [x] Rule engine with MITRE ATT&CK mapping
- [x] Command-line scanner
- [x] PostgreSQL storage
- [x] Ingestion and alerts API
- [ ] API hardening: keys, signatures, rate limits
- [ ] Continuous detection worker
- [ ] Alert notifications
- [ ] Web attack detection
- [ ] Docker and attack-replay demo
- [ ] Threat model and design records

## Usage

```bash
vigil scan /var/log/auth.log                    # human-readable report
vigil scan auth.log.2.gz auth.log.1 auth.log    # rotated logs (oldest first), .gz included
vigil scan auth.log --format json               # one JSON object per alert, for other tools
vigil scan auth.log --min-severity high --evidence

# With the database extra (pip install "vigil[db]") and VIGIL_DATABASE_URL set:
vigil db upgrade                                # create or update the tables
vigil scan auth.log --save                      # also store every event and alert
```

Saving is idempotent: scanning the same log twice never stores anything twice.

Exit codes: `0` no alerts, `1` alerts found, `2` error, so Vigil drops straight into
scripts and cron jobs. Running it on the bundled attack scenario:

```console
$ vigil scan tests/data/attack_scenario.log
vigil 0.1.0: scanned 29 lines, 19 login attempts, 3 alerts

MEDIUM    2026-11-17 03:00:00 -> 03:03:00 UTC  ssh-password-spray
          Password spraying from 203.0.113.77: 10 different accounts tried within 10 min
          ATT&CK T1110.003 Brute Force: Password Spraying - 10 events

MEDIUM    2026-11-17 03:10:00 -> 03:10:20 UTC  ssh-brute-force
          SSH brute force from 198.51.100.23: 5 failed logins within 60s
          ATT&CK T1110.001 Brute Force: Password Guessing - 5 events

CRITICAL  2026-11-17 03:10:00 -> 03:10:40 UTC  ssh-success-after-failures
          Possible compromise: 'root' logged in from 198.51.100.23 after 6 failed attempts
          ATT&CK T1110 Brute Force - 7 events
```

## Web API

```bash
pip install "vigil[api]"
# Windows PowerShell: $env:VIGIL_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
export VIGIL_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
vigil serve                    # http://127.0.0.1:8000 - interactive documentation at /docs
```

| Endpoint | Purpose |
| --- | --- |
| `GET /health`, `GET /health/ready` | Is it running? Can it reach the database? (no token needed) |
| `POST /v1/events` | Send up to 1,000 raw log lines; SSH login attempts are parsed and stored |
| `GET /v1/alerts?min_severity=high&limit=50` | Alerts, newest first |
| `GET /v1/alerts/{id}` | One alert with the exact log lines behind it |

Data endpoints require `Authorization: Bearer <VIGIL_API_TOKEN>`, and the server refuses
to start with a token shorter than 32 characters. It listens on 127.0.0.1 unless told
otherwise. Per-client keys, request signing and rate limits are next on the roadmap; until
then, keep the API on a trusted network.

## Development

Requires Python 3.12 or newer, and Docker for the database and API features.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev,api]"

docker compose up -d db    # PostgreSQL on localhost:5432 (local development credentials)

# Point the tests at the test database:
#   Windows PowerShell: $env:VIGIL_TEST_DATABASE_URL = "postgresql+psycopg://vigil:vigil@localhost:5432/vigil_test"
#   macOS/Linux:        export VIGIL_TEST_DATABASE_URL=postgresql+psycopg://vigil:vigil@localhost:5432/vigil_test

pytest          # run the tests (database tests are skipped if the variable is unset)
ruff check .    # lint: style and common bugs
mypy            # static type checking
```

## License

[MIT](LICENSE)
