# Vigil

[![CI](https://github.com/Abdulrahman-Zaghloul/vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/Abdulrahman-Zaghloul/vigil/actions/workflows/ci.yml)

A lightweight threat-detection engine. Vigil reads security logs, spots attacks
such as SSH brute-force and password spraying, and raises alerts mapped to
[MITRE ATT&CK](https://attack.mitre.org/).

> **Status:** early development, built in public one part at a time.

## Roadmap

- [x] Repository foundation
- [x] Python project skeleton and first test
- [x] Continuous integration on every push
- [x] SSH authentication log parser
- [x] Brute-force detection
- [ ] Rule engine with MITRE ATT&CK mapping
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
