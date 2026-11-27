# 0002 — Reuse Work testing

Status: Proposed

## Context
RDC needs regulated tests without duplicating test lifecycle code.

## Decision
Use installed `work-framework` 0.1.0.dev0 for tests only.
- Provider: `HyungseonSong-plasma/work@c21f73ae8f1bd1f8d80f1ae3955c57607cf85896`.
- Consumer workflow: `reusable_test.yml@314b81ec2b4a72210646787135cd77801d7fb01e`.

## Consequences
- Reviewed wheel in isolated environment; verify SHA/hash/path; no editable provider, vendoring, floating ref or sys.path hacks.
- Workflow checks provider only: trusted owner push/dispatch, first attempt, read-only, no inherited secrets or arbitrary caller commands. No RDC install.
- RDC owns full suite and CI; Work production dependency prohibited.
- Development version; no release/license grant. See [Testing Contract](../testing-contract.md).
