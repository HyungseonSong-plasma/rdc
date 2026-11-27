# Testing Contract — RDC v0.1
Status: proposed for adoption (P0). Authority: this document after merge. Tracking: #1.

## Provider boundary
Reuse the installed `work-framework` package (development version 0.1.0.dev0) as test-only infrastructure.
- Provider: HyungseonSong-plasma/work exact source SHA `c21f73ae8f1bd1f8d80f1ae3955c57607cf85896`.
- Reusable workflow revision: `314b81ec2b4a72210646787135cd77801d7fb01e`.
- The two revisions are intentionally distinct. The latter adds consumer workflow/docs/tests, not framework implementation changes.
- Install reviewed provider wheel into isolated test environment; verify exact provider commit, artifact hash and installed module location. No editable provider checkout, floating main, vendoring or sys.path hacks. No Work dependency in RDC production metadata or imports. No stable release/license grant implied.

## T01–T10 — Test rules
T01. Ordinary test suites extend public `work.libs.testing.TestSuite`.
T02. Explicit imports and `SuiteRegistry` registration, ordered RDC-owned TOML manifest. Unknown, duplicate, omitted, empty or unexpected suites fail.
T03. One final framework runner per test: `run_cases(cases, check)`, `run_contract(act, check, ...)` or compact `run_contract(check=check)`, or `run_scenario(steps, check, ...)`. Follow provider grammar, no lifecycle override or self-test exemption for RDC.
T04. RDC owns fixtures and assertions, including independent expected values, fresh contexts and temporary filesystem cleanup. Expected exceptions apply only to the action; cleanup must not suppress failure.
T05. Production modules cannot import Work, tests or test fixtures.
T06. Use public Work APIs only; private grammar is enforced transitively by SuiteRegistry.
T07. Provider revision updates require compatibility evidence and review.
T08. Offline unit tests do not require Docker, external networks, actual system changes or GitHub credentials.
T09. Integration tests run as explicitly selected complete suite groups with separate prerequisites; skipped required gates are not a pass.
T10. Architecture tests enforce reviewed import graph and registry coverage; reject unregistered tests. AST checks are structural, not a security sandbox or proof of assertion adequacy.

## Test layout
```
tests/
  __init__.py
  __main__.py             # python -m tests; RDC-owned, no work test command
  wiring.py               # independent registry and ordered group selection
  tests.toml
  fixtures.py
  architecture.py
  work_contract.py        # standalone installed-provider smoke
  suites/                 # explicit imports and named offline contracts
  integration/            # separately registered ELF/JIT/Docker suites
  fixtures/               # static fixture data where needed
```
The wiring must use separate SuiteRegistry instances or explicit complete per-group registries so selecting integration groups does not weaken registry completeness. Final layout may be refined in P1; no empty speculative suite files.

## CI boundary
- Work consumer gate uses pinned `.github/workflows/reusable_test.yml` and standalone `tests/work_contract.py`. It runs in isolated Python outside caller checkout, with no RDC install, so must test only provider compatibility, including all three runner forms and rejection behavior.
- RDC offline gate builds/installs RDC and Work in a fresh environment and runs RDC-owned full offline registry and architecture checks. Verify actual installed paths, dependency separation and nonzero test counts. Also test production import/CLI in environment without Work.
- RDC integration gate separately validates real ELF/compiler/JIT/Docker fixtures; fail on missing required prerequisites.
- Physics numerical regression belongs to Physics, not the generic RDC package.
- Work's existing consumer workflow supports trusted owner push/dispatch only, fresh run attempt, no secrets inheritance or write permissions. Follow its event constraints and own repository policy. Do not modify Work workflow to execute arbitrary caller commands.

## Required evidence
P1: exact provider/caller SHAs, wheel hashes, installed paths, suite/case outcomes, verified grammar rejection, production import without Work. P2+: deterministic graph duplicates/cycles/unresolved evidence, path traversal/symlink chains/collisions, inaccessible/privileged files, source mutation/rollback, manifest determinism, missing dependencies and actual cold-cache JIT. Include regression for Physics broad /usr copy failure without reproducing privileged system changes. Use temporary synthetic fixtures; do not use production validators as expected-value oracles. Record failing test and gate, do not mask with retries.
