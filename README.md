# Vigil

A lightweight threat-detection engine. Vigil reads security logs, spots attacks
such as SSH brute-force and password spraying, and raises alerts mapped to
[MITRE ATT&CK](https://attack.mitre.org/).

> **Status:** early development, built in public one part at a time.

## Roadmap

- [x] Repository foundation
- [ ] Python project skeleton and first test
- [ ] Continuous integration on every push
- [ ] SSH authentication log parser
- [ ] Brute-force detection
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

## License

[MIT](LICENSE)
