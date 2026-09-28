# Changelog

All notable changes to **klahack-portscope** are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-09-28

### Added

- Portable Python 3.8+ TCP connect scanner with no runtime dependencies.
- IPv4, IPv6, hostname, literal address, CIDR, and comma-separated target support.
- Mixed port ranges and a built-in prevalence-ordered top-100 port list.
- Bounded concurrent scanning, throttling, timeouts, and partial Ctrl+C results.
- Cross-platform open, closed, and filtered socket-state normalization.
- Sanitized passive and HTTP-fallback service banner collection.
- Terminal tables and stable JSON and CSV output formats.
- Public-target authorization gate and bounded host expansion.
- Linux, Termux, macOS, and per-user Windows installers with SHA256 verification.
- Bilingual Arabic/English documentation and dependency-free project website.
- Loopback-only unit tests and multi-platform CI, binary builds, and tagged releases.
