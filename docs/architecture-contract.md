# Architecture Contract — RDC v0.1
Status: proposed for adoption (P0). Authority: this document after merge; README is an overview. Changes to normative rules require review. Tracking: #1.

## Scope
RDC is a standalone Python 3.12+ Linux runtime filesystem collector for trusted, explicitly pinned build environments. Correctness and evidence precede size reduction. v0.1 targets Linux/ELF, initially x86_64, with explicit resource profiles and optional JIT discovery. Docker is an integration boundary, not a core dependency. Rust, public release and cross-platform support are out of scope. A collected closure is valid only for its declared environment, inputs, workloads and validation coverage; no universal completeness claim.

## A01 — Layer ownership
- `models.py`: immutable typed records, enums, IDs; no I/O.
- `graph.py`: directed dependency edges, provenance, closure, deterministic ordering; pure logic.
- `discovery/`: independent analyzers for ELF, explicit resources, compiler/JIT and traces. Read source files or invoke explicitly configured tools; emit observations, not copy operations. Workloads that create files run only in disposable isolated workspaces.
- `policy.py`: explicit allowed roots, resource selections, privilege and unresolved-dependency policy.
- `planner.py`: normalize/map paths, resolve conflicts, link chains, required edges, and produce immutable collection plans; no writes.
- `collector.py`: materialize a validated plan only; no discovery or implicit additions.
- `manifest.py`: versioned canonical serialization, hashes and provenance.
- `validator.py`: structural/manifest verification; isolated execution adapters for smoke and integration tests.
- `config.py`: strict TOML schema and profile loading; no arbitrary imports or executable config.
- `pipeline.py`: compose stages and stop on failure.
- `cli.py`: parse arguments, invoke pipeline, render exit/report; no domain policy.
- Infrastructure adapters (filesystem/process/ELF/tool calls) may be factored when their boundaries are established, not as empty speculative modules.

## A02 — Dependency direction
CLI -> config/pipeline; pipeline -> analyzers/planner/collector/validator/manifest. Planner -> policy/graph/models; graph -> models; analyzers -> models (and narrow I/O adapters); collector -> validated plan/models and filesystem adapter; manifest -> models; validator -> manifest/models and explicit I/O adapters. Shared core must not import CLI, pipeline, concrete profiles, tests or Work. No dependency cycles. The initial P2 implementation must freeze the exact module import allowlist and add static architecture tests; exceptions require documented approval. Prefer composition, small typed functions and explicit dependency injection; no dynamic plugin discovery in v0.1.

## A03 — Dependency semantics
Distinguish node identity (canonical absolute POSIX source path in a declared source root), destination path (absolute POSIX path within target root), kind (executable, ELF library, interpreter, header, data, config, symlink, directory), and directed edge evidence (requester, analyzer, observed relation, resolution status). Keep aliases and link edges rather than merging distinct path semantics by content hash. Deduplicate identical node/edge identities, preserve all independent evidence. Handle cycles without repeated traversal. Distinguish required, optional, unresolved and denied dependencies. Required unresolved/denied dependencies block collection. A failed lookup or an observed path alone is not proof of necessity. Trace evidence is workload-specific; include successful file opens/execs and distinguish generated files, failed probes and external mounts. Explicit resources remain required even if a workload does not read them.

## A04 — Safety and plan contract
No implicit copy of whole /usr, /lib, home, virtual filesystems or compiler distribution. Resource trees require an explicit bounded selection and per-file inventory. Resolve source and destination paths without host escape; reject traversal, unsupported special files, unexpected symlink cycles/escapes, destination collisions and privilege-bearing files unless a future reviewed policy explicitly authorizes them. Preserve link semantics; do not follow untrusted destination symlinks. Do not blanket chmod or copy host secrets/credentials. Use a new staging root, never modify source or an existing validated runtime. Record source type, content hash, mode and identity; revalidate before copying and read back materialized files. Fail closed on drift or conflicts. Publish the completed staging root only after validation; no partial success. Explicit trusted source snapshot is a prerequisite, not a sandbox guarantee.

## A05 — Determinism and evidence
Use versioned JSON graph, plan and manifest schemas with canonical UTF-8 encoding, explicit order and stable path sorting. Record profile hash, source/build identity, tool versions, target ABI, file type/mode/hash/link target, provenance and validation coverage. Keep timestamps and execution durations in a separate evidence report, not content identity. No absolute temporary workspace names in canonical identity. Distinguish collected bytes from final OCI image size. Do not silently overwrite existing ELF closure files; report conflicts. Reproducibility is measured for equivalent pinned inputs, not assumed from one run.

## A06 — CLI and failures
Proposed commands: discover, plan, inspect, collect, verify, build. Each stage has explicit inputs/outputs and nonzero exit for errors. Inspect/dry-run never writes runtime files. Build composes stages rather than duplicating them. Stable error codes/categories must be defined at implementation; include failing path/edge and stage without secret values. No automatic retry of failed collection or hidden fallback to broad copy. Python stdlib first; evaluate pyelftools and external compiler/loader/strace adapters at the relevant implementation gate. Pin versions in test evidence; invoke tools with explicit argv, not shell interpolation.

## A07 — Validation gates
1. Core graph/plan/path/manifest tests without Docker.
2. Real ELF fixture with interpreter, transitive deps, loader resolution and aliases; distinguish static ELF metadata from dynamic dlopen/MPI/NSS.
3. Compiler/linker closure from actual tool queries and traces; test fresh-cache AD JIT and compare to pinned full environment. Evaluate MOOSE's monolithic ADReal header only in Physics profile.
4. Isolated rootfs/image smoke with no host dependency fallback, structural and hash verification.
5. Physics integration: preserve exact physics executable/database/input/mesh/rates; compare known-good 1 ns case and spatial/CSV outputs, then separate longer science gate. No physical acceptance from image build alone.

## A08 — Delivery and quality
Use src layout, typed dataclasses/enums and explicit errors. No Work imports in production. Keep profiles independent of core and Physics-specific implementation outside core. Ruff and mypy strict are proposed quality tools; exact versions/configurations selected in P1. No license/publication decision implied. Implementation changes proceed through reviewed gates P1–P8 in #1; no scheduled controller.
