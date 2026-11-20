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
- [ ] Command-line scanner
- [ ] PostgreSQL storage
- [ ] Ingestion and alerts API
- [ ] API hardening: keys, signatures, rate limits
- [ ] Continuous detection worker
- [ ] Alert notifications
- [ ] Web attack detection
- [ ] Docker and attack-replay demo
- [ ] Threat model and design records

## Development

Requires Python 3.12 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"

pytest          # run the tests
ruff check .    # lint: style and common bugs
mypy            # static type checking
```

## License

[MIT](LICENSE)
