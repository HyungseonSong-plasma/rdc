# Testing Contract

Status: Proposed (P0). Normative after merge. Tracking: [#1](https://github.com/HyungseonSong-plasma/rdc/issues/1).

## Rules

| ID | Requirement |
|---|---|
| T01 | Ordinary suites extend public `TestSuite`. |
| T02 | Explicit imports, `SuiteRegistry`, ordered RDC TOML; reject unknown, missing, duplicate, empty or unexpected suites. |
| T03 | One final runner: `run_cases`, `run_contract` or `run_scenario`; enforce grammar; no lifecycle override/exemption. |
| T04 | Independent RDC fixtures/expectations; fresh contexts, cleanup; expected exceptions apply to action only; no suppressed failures. |
| T05 | No Work/tests/fixtures in production imports or metadata dependencies. |
| T06 | Public Work APIs only; grammar enforced through registry. |
| T07 | Pin provider SHA; review updates with compatibility evidence. |
| T08 | Offline tests: no Docker, network, credentials or system changes. |
| T09 | Separate complete integration registries/groups; missing prerequisite or skipped required gate fails. |
| T10 | Enforce import DAG and registration coverage; AST is not a sandbox or assertion proof. |

## Wiring and CI

RDC owns `tests/{__main__,wiring,fixtures,architecture,work_contract}.py`, `tests.toml`, explicit `suites/` and `integration/`; no empty speculative files. Run `python -m tests`, not `work test`.

| Gate | Evidence |
|---|---|
| Provider | Installed wheel, SHA/hash/path; standalone `work_contract.py`: three runners + rejection |
| RDC offline | Fresh installed RDC + Work; complete suite/case results, architecture, nonzero counts; production import/CLI without Work |
| Integration | Real ELF, compiler, cold-cache JIT, Docker; separate prerequisites |
| Physics | Numerical regression in Physics repository |

Provider pins and workflow constraints: [ADR 0002](adr/0002-reuse-work-testing.md). P1 records exact caller/provider SHAs, wheel hashes, installed paths and results.

**Regression minimum (P2+):** graph cycles/duplicates/unresolved edges; traversal, links, collisions, unreadable/privileged files; drift/rollback; deterministic manifests; missing dependencies; cold-cache JIT. Reproduce broad-copy failures with temporary synthetic fixtures, not privileged system changes. Report failure and gate; no masking retries.
