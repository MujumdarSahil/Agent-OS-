"""Review storage (3.6a): File and Mongo implementations.

File backend: ``<project>/.agentos/state/review_items.json`` and ``review_sampling.json``.
Mongo backend: ``review_items`` and ``review_sampling_configs`` collections.
"""

from __future__ import annotations

import collections
import hashlib
import time
from pathlib import Path
from typing import Any, Optional, Union

from agentos.notify.store import FileDocs
from agentos.review.models import (
    ReviewItem,
    ReviewMetrics,
    ReviewReasonCount,
    ReviewSamplingConfig,
)


def _redact_value(
    val: Any,
    labels: list[str],
    labels_dict: Optional[dict[str, Any]] = None,
    include_secrets: bool = False,
) -> Any:
    """Omit or redact values labelled SECRET unless include_secrets is True."""
    if include_secrets:
        return val
    if "SECRET" in labels or "secret" in labels:
        return "[SECRET redacted]"
    if isinstance(val, dict):
        out = {}
        for k, v in val.items():
            lbl = (labels_dict or {}).get(k)
            is_sec = False
            if lbl and isinstance(lbl, dict) and lbl.get("confidentiality") == "secret":
                is_sec = True
            elif "secret" in k.lower():
                is_sec = True
            if is_sec:
                out[k] = "[SECRET redacted]"
            else:
                out[k] = _redact_value(v, labels, labels_dict=None, include_secrets=include_secrets)
        return out
    return val


class ReviewStore:
    def __init__(self, items: Any, sampling: Any) -> None:
        self.items = items
        self.sampling = sampling

    # ------------------------------------------------------------------ items

    @staticmethod
    def deterministic_item_id(run_id: str, node_id: str) -> str:
        """Return a stable, collision-resistant item id for a (run_id, node_id) pair.

        Part 0d (3.6b): saving the same run+node twice must not create duplicates.  Using a
        deterministic id lets the storage layer's put() (which is an upsert-by-id) silently
        overwrite the previous record instead of inserting a second one.
        """
        raw = f"{run_id}\0{node_id}".encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()[:24]
        return f"rev_{digest}"

    async def put_item(self, item: ReviewItem) -> ReviewItem:
        """Persist a review item, deduplicating by (run_id, node_id).

        Part 0d (3.6b): at most one item per (run_id, node_id): saving the same run twice must not
        create duplicates (deterministic id or an upsert). If an item with the same run_id and node_id
        already exists, we update that existing record.
        """
        raw_list = await self.items.list()
        existing = next(
            (ReviewItem.model_validate(d) for d in raw_list
             if d.get("run_id") == item.run_id and d.get("node_id") == item.node_id),
            None,
        )
        if existing is not None:
            # Upsert: reuse existing id so saving the same run+node twice never creates duplicates
            item = item.model_copy(update={"id": existing.id, "item_id": existing.id})
        elif not item.id:
            det_id = self.deterministic_item_id(item.run_id, item.node_id)
            item = item.model_copy(update={"id": det_id, "item_id": det_id})
        doc = item.model_dump(mode="json")
        await self.items.put(doc)
        return item

    async def get_item(self, item_id: str) -> Optional[ReviewItem]:
        raw = await self.items.get(item_id)
        return ReviewItem.model_validate(raw) if raw else None

    async def list_items(
        self,
        flow_id: Optional[str] = None,
        status: Optional[str] = None,
        verdict: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[ReviewItem], int]:
        raw_list = await self.items.list()
        items = [ReviewItem.model_validate(d) for d in raw_list]

        if flow_id:
            items = [it for it in items if it.flow_id == flow_id]
        if status:
            items = [it for it in items if it.status == status]
        if verdict:
            items = [it for it in items if it.verdict == verdict]

        # Newest items first
        items.sort(key=lambda it: it.created_at, reverse=True)
        total = len(items)
        page = items[offset : offset + limit]
        return page, total

    async def update_verdict(
        self,
        item_id: str,
        verdict: str,
        reasons: Optional[list[str]] = None,
        corrected_output: Optional[str] = None,
        note: Optional[str] = None,
        reviewer_id: str = "",
    ) -> Optional[ReviewItem]:
        now = time.time()

        def _apply(doc: dict[str, Any]) -> dict[str, Any]:
            doc["verdict"] = verdict
            doc["reasons"] = list(reasons or [])
            doc["corrected_output"] = corrected_output
            doc["note"] = note
            doc["reviewer_id"] = reviewer_id
            doc["status"] = "reviewed"
            doc["reviewed_at"] = now
            return doc

        updated = await self.items.update(item_id, _apply)
        return ReviewItem.model_validate(updated) if updated else None

    async def skip_item(
        self,
        item_id: str,
        reviewer_id: str,
        note: Optional[str] = None,
    ) -> Optional[ReviewItem]:
        now = time.time()

        def _apply(doc: dict[str, Any]) -> dict[str, Any]:
            doc["status"] = "skipped"
            doc["reviewer_id"] = reviewer_id
            if note is not None:
                doc["note"] = note
            doc["reviewed_at"] = now
            return doc

        updated = await self.items.update(item_id, _apply)
        return ReviewItem.model_validate(updated) if updated else None

    # ------------------------------------------------------------------ sampling configs
    async def get_sampling_config(self, flow_id: str) -> ReviewSamplingConfig:
        raw = await self.sampling.get(flow_id)
        if raw:
            return ReviewSamplingConfig.model_validate(raw)
        return ReviewSamplingConfig(flow_id=flow_id, mode="off")

    async def put_sampling_config(self, config: ReviewSamplingConfig) -> ReviewSamplingConfig:
        doc = config.model_dump(mode="json")
        doc["id"] = config.flow_id
        await self.sampling.put(doc)
        return config

    # ------------------------------------------------------------------ metrics
    async def get_metrics(
        self,
        flow_id: str,
        flow_version: Optional[Union[int, str]] = None,
    ) -> ReviewMetrics:
        raw_list = await self.items.list()
        items = [
            ReviewItem.model_validate(d)
            for d in raw_list
            if d.get("flow_id") == flow_id
        ]
        if flow_version is not None:
            items = [it for it in items if str(it.flow_version) == str(flow_version)]

        reviewed = [it for it in items if it.status == "reviewed"]
        good_count = sum(1 for it in reviewed if it.verdict == "good")
        bad_count = sum(1 for it in reviewed if it.verdict == "bad")
        total_decided = good_count + bad_count
        good_pct = round((good_count / total_decided) * 100, 1) if total_decided > 0 else 0.0

        reason_counts: collections.Counter[str] = collections.Counter()
        for it in reviewed:
            if it.verdict == "bad":
                for r in it.reasons:
                    reason_counts[r] += 1

        top_reasons = [
            ReviewReasonCount(reason=r, count=c)
            for r, c in reason_counts.most_common()
        ]

        return ReviewMetrics(
            flow_id=flow_id,
            flow_version=flow_version,
            reviewed_count=len(reviewed),
            good_count=good_count,
            bad_count=bad_count,
            good_percentage=good_pct,
            top_bad_reasons=top_reasons,
        )

    # ------------------------------------------------------------------ export
    async def export_items(
        self,
        flow_id: Optional[str] = None,
        include_secrets: bool = False,
    ) -> list[dict[str, Any]]:
        raw_list = await self.items.list()
        items = [
            ReviewItem.model_validate(d)
            for d in raw_list
            if d.get("status") == "reviewed"
        ]
        if flow_id:
            items = [it for it in items if it.flow_id == flow_id]

        items.sort(key=lambda it: it.created_at)

        exported: list[dict[str, Any]] = []
        for it in items:
            inp = it.inputs if it.inputs else it.input_data
            outp = it.outputs if it.outputs else it.output_data
            exported.append({
                "flow_id": it.flow_id,
                "flow_version": it.flow_version,
                "node_id": it.node_id,
                "input": _redact_value(inp, it.labels, labels_dict=it.input_labels, include_secrets=include_secrets),
                "output": _redact_value(outp, it.labels, labels_dict=it.output_labels, include_secrets=include_secrets),
                "verdict": it.verdict,
                "reasons": it.reasons,
                "corrected_output": it.corrected_output,
            })
        return exported


def review_store_for(storage: Any) -> ReviewStore:
    if getattr(storage, "backend", "file") == "mongo":
        from agentos.storage.mongo.review import MongoReviewDocs

        db = storage.runs._c.database
        return ReviewStore(MongoReviewDocs(db.review_items), MongoReviewDocs(db.review_sampling_configs))

    base = Path(storage.location) / ".agentos" / "state"
    return ReviewStore(FileDocs(base / "review_items.json"), FileDocs(base / "review_sampling.json"))


async def enqueue_run_for_review(
    storage: Any,
    run_id: str,
    node_id: Optional[str] = None,
) -> ReviewItem:
    """Manually enqueue a run or specific node for review ("Send to review" button)."""
    run = await storage.runs.get(run_id)
    if not run:
        raise ValueError(f"Run {run_id!r} not found")

    flow_id = getattr(run, "flow_id", None) or getattr(run, "mission_name", "unknown")
    events = await storage.events.list(run_id, after_seq=0)

    # Reconstruct node inputs, outputs, labels
    node_inputs: dict[str, Any] = {}
    node_outputs: dict[str, Any] = getattr(run, "outputs", {}) or {}
    node_labels: dict[str, list[str]] = {}
    flow_version: Union[int, str] = getattr(run, "flow_version", None) or 1

    for ev in events:
        d = ev.data or {}
        if ev.type == "flow_started":
            flow_version = d.get("flow_version", flow_version)
        elif ev.type == "node_started":
            nid = d.get("node_id")
            if nid and "inputs" in d:
                node_inputs[nid] = d["inputs"]
        elif ev.type in ("node_succeeded", "node_finished"):
            nid = d.get("node_id")
            if nid:
                if "inputs" in d and nid not in node_inputs:
                    node_inputs[nid] = d["inputs"]
                if "outputs" in d:
                    node_outputs[nid] = d["outputs"]
                lbls = set()
                raw_labels = d.get("output_labels") or {}
                for k, v in raw_labels.items():
                    if isinstance(v, dict):
                        if v.get("integrity") == "untrusted":
                            lbls.add("UNTRUSTED")
                        if v.get("confidentiality") == "secret":
                            lbls.add("SECRET")
                        elif v.get("confidentiality") == "confidential":
                            lbls.add("CONFIDENTIAL")
                node_labels[nid] = sorted(lbls)

    target_node = node_id
    if not target_node:
        # Use last output node or first available
        if node_outputs:
            target_node = list(node_outputs.keys())[-1]
        elif node_inputs:
            target_node = list(node_inputs.keys())[-1]
        else:
            target_node = "output"

    labels = node_labels.get(target_node, [])
    # Also check input labels if output labels empty
    if not labels:
        # If any input has UNTRUSTED, mark UNTRUSTED
        in_data = node_inputs.get(target_node)
        if isinstance(in_data, dict) and any("untrusted" in str(v).lower() for v in in_data.values()):
            labels.append("UNTRUSTED")

    item = ReviewItem(
        run_id=run_id,
        flow_id=flow_id,
        flow_version=flow_version,
        node_id=target_node,
        status="pending",
        input_data=node_inputs.get(target_node),
        output_data=node_outputs.get(target_node),
        labels=labels,
    )
    store = review_store_for(storage)
    await store.put_item(item)
    return item
