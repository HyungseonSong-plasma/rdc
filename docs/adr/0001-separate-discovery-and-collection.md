# 0001 — Separate discovery and collection

Status: Proposed

## Context
Physics's broad runtime copies caused permission failures and included unrelated system files ([RCA](https://github.com/HyungseonSong-plasma/physics/issues/3#issuecomment-7229155456)).

## Decision
Use a standalone Python collector with explicit discovery, graph, planning and materialization stages.

## Consequences
- Validate the plan before writing files; preserve dependency evidence.
- Prefer correctness to size reduction; validate against pinned workloads.
- [Architecture Contract](../architecture-contract.md) defines the rules.
