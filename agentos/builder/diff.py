"""Structural diff between two flows (4.0 D11, "Edit with AI"): added / removed / changed nodes and edges."""

from __future__ import annotations

from typing import Any


def _edge_key(e: dict[str, Any]) -> str:
    return f"{e['source']}->{e['target']}" + (f" [{e['branch']}]" if e.get("branch") else "")


def flow_diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    on, nn = old.get("nodes") or {}, new.get("nodes") or {}
    changed = []
    for nid in sorted(set(on) & set(nn)):
        a, b = on[nid], nn[nid]
        fields = [f for f in ("type", "config", "pinned_args") if (a.get(f) or {}) != (b.get(f) or {})]
        if fields:
            changed.append({"id": nid, "fields": fields})
    oe = {_edge_key(e): e for e in old.get("edges") or []}
    ne = {_edge_key(e): e for e in new.get("edges") or []}
    edges_changed = [{"key": k, "from": oe[k].get("arg_mapping") or {}, "to": ne[k].get("arg_mapping") or {}}
                     for k in sorted(set(oe) & set(ne))
                     if (oe[k].get("arg_mapping") or {}) != (ne[k].get("arg_mapping") or {})]
    out = {
        "nodes_added": sorted(set(nn) - set(on)),
        "nodes_removed": sorted(set(on) - set(nn)),
        "nodes_changed": changed,
        "edges_added": sorted(set(ne) - set(oe)),
        "edges_removed": sorted(set(oe) - set(ne)),
        "edges_changed": edges_changed,
        "entrypoint_changed": old.get("entrypoint") != new.get("entrypoint"),
    }
    out["empty"] = not any(out[k] for k in out)
    return out
