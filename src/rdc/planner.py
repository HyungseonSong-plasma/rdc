"""Build a complete immutable plan without writing any runtime files."""

import posixpath
from collections.abc import Iterable
from functools import partial
from pathlib import PurePosixPath

from rdc.filesystem import snapshot
from rdc.graph import DependencyGraph
from rdc.models import (
    BuildIdentity, Closure, CollectionPlan, CollectionPolicy, DependencyKind,
    PlannedEntry, Resolution, canonical_path,
)
from rdc.policy import check_mode, check_path


class PlanError(ValueError):
    """Dependency closure cannot be safely materialized."""


def _resolve_link(path: str, link: str, root: str) -> str:
    # Permit leading ../ components, but reject ambiguous interior traversal.
    if not link or "\x00" in link or link.startswith("//"):
        raise PlanError(f"Invalid link: {path}")
    parts = link.split("/")
    if link.startswith("/"):
        parts = parts[1:]
        if any(p in ("", ".", "..") for p in parts):
            raise PlanError(f"Noncanonical absolute link: {path}")
        result = posixpath.join(root, *parts)
    else:
        depth = len(PurePosixPath(path).parent.relative_to(root).parts)
        while parts and parts[0] == "..":
            if depth == 0:
                raise PlanError(f"Link escapes root: {path}")
            depth -= 1
            parts.pop(0)
        if not parts or any(p in ("", ".", "..") for p in parts):
            raise PlanError(f"Ambiguous relative link: {path}")
        result = posixpath.normpath(posixpath.join(posixpath.dirname(path), link))
    if not PurePosixPath(result).is_relative_to(root):
        raise PlanError(f"Link escapes root: {path}")
    return result


def _check_layout(plan: CollectionPlan) -> None:
    sources = {entry.node.source: entry for entry in plan.entries}
    targets = {entry.node.target: entry for entry in plan.entries}
    if len(targets) != len(plan.entries):
        raise PlanError("Destination collision.")
    for path in targets:
        for parent in PurePosixPath(path).parents:
            other = targets.get(str(parent))
            if other is not None and other.node.kind is not DependencyKind.DIRECTORY:
                raise PlanError(f"Non-directory destination ancestor: {parent}")

    links: dict[str, str] = {}
    for entry in plan.entries:
        link = entry.snapshot.link
        if link is None:
            continue
        source = _resolve_link(entry.node.source, link, plan.source_root)
        target = _resolve_link(entry.node.target, link, "/")
        other = sources.get(source)
        if other is None or other.node.target != target:
            raise PlanError(f"Missing or mismapped link target: {entry.node.target}")
        if not any(edge.requester == entry.node.source
                   and edge.dependency == source and edge.required
                   and edge.status is Resolution.RESOLVED
                   and edge.evidence.relation == "symlink" for edge in plan.closure.edges):
            raise PlanError(f"Missing required link evidence: {entry.node.target}")
        links[entry.node.target] = target
    done: set[str] = set()
    for start in links:
        seen: set[str] = set()
        path = start
        while path in links and path not in done:
            if path in seen:
                raise PlanError(f"Link cycle: {path}")
            seen.add(path)
            path = links[path]
        done.update(seen)


def plan_closure(source_root: str, closure: Closure, policy: CollectionPolicy,
                 build: BuildIdentity) -> CollectionPlan:
    """Revalidate graph structure, policy, snapshots and complete link mapping."""
    canonical_path(source_root)
    graph = DependencyGraph(source_root)
    for node in closure.nodes:
        graph.add_node(node)
    for edge in closure.edges:
        graph.add_edge(edge)
    if graph.closure(closure.roots) != closure:
        raise PlanError("Closure is not the canonical reachable graph.")
    if closure.blockers:
        edge = closure.blockers[0]
        raise PlanError(f"Required {edge.status}: {edge.requester} ({edge.evidence.relation})")
    entries = []
    for node in sorted(closure.nodes, key=lambda item: item.target):
        check_path(source_root, policy, node)
        item = snapshot(node.source, guard=partial(check_mode, node))
        entries.append(PlannedEntry(node, item))
    snapshots = {entry.node.source: entry.snapshot for entry in entries}
    for edge in closure.edges:
        if edge.evidence.analyzer == "elf" and edge.evidence.relation == "elf-sha256":
            if (edge.dependency != edge.requester or edge.status is not Resolution.RESOLVED
                    or snapshots[edge.requester].sha256 != edge.evidence.request):
                raise PlanError(f"ELF changed after discovery: {edge.requester}")
    plan = CollectionPlan(source_root, policy, build, closure, tuple(entries))
    _check_layout(plan)
    return plan


def plan_collection(graph: DependencyGraph, roots: Iterable[str],
                    policy: CollectionPolicy, build: BuildIdentity) -> CollectionPlan:
    return plan_closure(graph.source_root, graph.closure(roots), policy, build)
