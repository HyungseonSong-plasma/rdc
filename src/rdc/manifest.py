"""Canonical versioned collection manifest, independent of local inode identity."""

import json
from pathlib import PurePosixPath

from rdc.models import CollectionPlan


def manifest_bytes(plan: CollectionPlan) -> bytes:
    """Serialize root-relative provenance; omit local timestamps and inode IDs."""
    root = PurePosixPath(plan.source_root)

    def relative(path: str) -> str:
        return str(PurePosixPath("/") / PurePosixPath(path).relative_to(root))

    def request(value: str) -> str:
        if value.startswith("/") and PurePosixPath(value).is_relative_to(root):
            return relative(value)
        return value

    data = {
        "schema": "rdc.collection.v1",
        "build": plan.build.build,
        "abi": plan.build.abi,
        "profile_sha256": plan.build.profile_sha256,
        "tools": dict(sorted(plan.build.tools)),
        "coverage": sorted(set(plan.build.coverage)),
        "allowed_roots": sorted({relative(p) for p in plan.policy.allowed_roots}),
        "roots": [relative(p) for p in plan.closure.roots],
        "files": [
            {"source": relative(e.node.source), "target": e.node.target,
             "kind": e.node.kind.value, "mode": e.snapshot.mode,
             "size": e.snapshot.size, "sha256": e.snapshot.sha256,
             "link": e.snapshot.link}
            for e in plan.entries
        ],
        "edges": [
            {"requester": relative(e.requester), "dependency": (
                relative(e.dependency) if e.dependency is not None else None),
             "analyzer": e.evidence.analyzer, "relation": e.evidence.relation,
             "request": request(e.evidence.request), "status": e.status.value,
             "required": e.required}
            for e in plan.closure.edges
        ],
        "collected_bytes": sum(e.snapshot.size for e in plan.entries),
        "validation": "structural-and-content-only",
    }
    return (json.dumps(data, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
