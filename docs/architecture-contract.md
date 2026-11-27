# Architecture Contract

Status: Proposed (P0). Normative after merge. Changes require review ([#1](https://github.com/HyungseonSong-plasma/rdc/issues/1)).

**Scope:** Python 3.12+, Linux ELF/x86_64, pinned trusted inputs, resource profiles, optional JIT. Docker is integration-only. Rust, other platforms and release are deferred.

## A01–A02 · Structure

```text
discover → graph → plan → collect → verify
                    ↓         ↓
                  policy    manifest
```

| Module | Responsibility |
|---|---|
| models, graph | Immutable typed records; deterministic closure, no I/O |
| discovery/ | ELF, resource, JIT and trace observations; writes only in disposable workspaces |
| policy, planner | Allowed roots/resources/privilege; validated immutable plan, no writes |
| collector, manifest | Plan-only materialization; canonical provenance |
| validator | Structural checks and isolated execution |
| config, pipeline, cli | Strict TOML; orchestration; arguments/reporting |

CLI → config/pipeline; pipeline → discovery/planner/collector/validator/manifest; planner → policy/graph/models; graph/discovery/collector/manifest/validator → models; validator → manifest. Narrow I/O adapters where needed. No cycles, reverse core imports, concrete profiles, tests, Work or dynamic plugin imports. P2 fixes the exact import allowlist; exceptions require review.

## A03–A06 · Invariants

- **A03 Graph:** Canonical source path in declared root, absolute target path, file kind, requester/analyzer/relation/status evidence. Preserve aliases, link edges and all evidence; deduplicate identities, terminate cycles. Block required unresolved/denied edges. Explicit resources remain required; traces distinguish successful opens/execs, failed probes, generated files and mounts. Coverage is workload-specific.
- **A04 Safety:** No implicit broad directory copies; explicit bounded inventories only. Reject path escapes, special files, unsafe/cyclic links, collisions and privileged files (unless reviewed). Preserve links; never follow untrusted destination links, blanket chmod, copy secrets or mutate source/existing root. Check source type/hash/mode/identity before copy and read back; publish new staging root only after validation. Fail closed; trusted input is not a sandbox.
- **A05 Evidence:** Versioned canonical UTF-8 JSON, stable path order; profile hash, build identity, tool versions, ABI, file type/mode/hash/link, provenance and coverage. Keep timestamps/durations and temporary paths out of canonical identity. Report rootfs bytes separately from OCI size; test reproducibility; never overwrite verified ELF files silently.
- **A06 CLI:** discover, plan, inspect, collect, verify, build. Explicit inputs/outputs; dry-run/inspect do not write rootfs; build composes stages. Nonzero failures with stable category, stage and path/edge (no secrets). No hidden retries or broad-copy fallback. Stdlib first; evaluate pinned ELF/compiler/loader/trace tools with explicit argv.

## A07 · Gates

| Gate | Required evidence |
|---|---|
| Core | Graph, plan, paths, manifest; no Docker |
| ELF | Interpreter, transitive deps, loader, aliases; dynamic loading/MPI/NSS separate |
| JIT | Tool queries/traces; cold-cache AD JIT vs pinned full environment |
| Runtime | Isolated rootfs/image; hashes; no host fallback |
| Physics | Same binary/database/inputs/mesh/rates; 1 ns spatial + CSV comparison; longer science gate separate |

MOOSE monolithic headers belong to the Physics profile, not core. Image build alone is not science acceptance.

**A08 Quality:** src layout, typed dataclasses/enums, explicit errors, composition and injection. No speculative modules. Ruff/mypy strict proposed; pin in P1. Reviewed P1–P8 gates; no publication/license decision or controller.
