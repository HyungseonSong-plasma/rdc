# rdc

Runtime Dependency Collector — standalone Python tool for building auditable Linux runtime filesystem closures.

Development design only; no collector implementation or release yet.

- [Architecture Contract](docs/architecture-contract.md) — proposed normative design
- [Testing Contract](docs/testing-contract.md) — Work test-only framework reuse
- [Roadmap and review gates](https://github.com/HyungseonSong-plasma/rdc/issues/1)

Correctness, explicit dependency evidence and isolation precede size reduction. Physics is the first intended consumer; the core remains application-independent.
