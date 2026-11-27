"""4.2 D13: JUnit XML for CI pipelines (one testcase per test case; failures carry the readable diff)."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from agentos.flowtests.models import SuiteRun


def junit_xml(suite: SuiteRun) -> str:
    c = suite.counts
    root = ET.Element("testsuites")
    ts = ET.SubElement(root, "testsuite", {
        "name": f"agentos.flow.{suite.flow_id}", "tests": str(c.get("total", 0)), "failures": str(c.get("fail", 0)),
        "errors": str(c.get("error", 0)), "time": f"{suite.duration_ms / 1000:.3f}",
    })
    props = ET.SubElement(ts, "properties")
    for k, v in (("target", suite.target), ("version", suite.version), ("model", suite.model),
                 ("suite_run_id", suite.id)):
        ET.SubElement(props, "property", {"name": k, "value": "" if v is None else str(v)})
    for r in suite.results:
        tc = ET.SubElement(ts, "testcase", {"classname": f"agentos.flow.{suite.flow_id}", "name": r.name,
                                            "time": f"{r.duration_ms / 1000:.3f}"})
        if r.status == "error":
            ET.SubElement(tc, "error", {"message": (r.error or "error")[:500]}).text = r.error or ""
        elif r.status == "fail":
            lines = [f"- {f.message}\n  expected: {json.dumps(f.expected, default=str)}\n"
                     f"  actual:   {json.dumps(f.actual, default=str)}" for f in r.failures]
            msg = r.failures[0].message if r.failures else "failed"
            ET.SubElement(tc, "failure", {"message": msg[:500]}).text = "\n".join(lines)
        out = f"run_id={r.run_id} cost_usd={r.cost_usd} model_calls={r.model_calls}"
        if r.nondeterministic:
            out += " (includes a non-deterministic judge check)"
        ET.SubElement(tc, "system-out").text = out
    return ET.tostring(root, encoding="unicode", xml_declaration=True)
