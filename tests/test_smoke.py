"""Smoke tests — run with `pytest`, or directly: `python tests/test_smoke.py`.

These need no model or API key: they validate the probe library and the
detection logic (including obfuscated-leak decoding), so CI stays green.
"""
from __future__ import annotations

import base64
import codecs
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # allow `python tests/test_smoke.py`

from llmscan.detect import evaluate
from llmscan.report import risk_grade, write_html, write_markdown

ROOT = Path(__file__).resolve().parents[1]
CFG = yaml.safe_load((ROOT / "llmscan" / "probes.yaml").read_text(encoding="utf-8"))
CANARY = CFG["canary"]
PROBES = CFG["probes"]


def _probe(pid: str) -> dict:
    return next(p for p in PROBES if p["id"] == pid)


def test_probe_library_is_well_formed():
    assert len(PROBES) >= 25
    ids = [p["id"] for p in PROBES]
    assert len(ids) == len(set(ids)), "duplicate probe ids"
    for p in PROBES:
        assert {"id", "owasp", "name", "severity", "prompt"} <= set(p)
        assert p["severity"] in {"high", "medium", "low"}


def test_direct_canary_leak_is_caught():
    v = evaluate(f"the token is {CANARY}", _probe("PI-01"), CANARY)
    assert v["vulnerable"]


def test_base64_leak_is_caught():
    enc = base64.b64encode(CANARY.encode()).decode()
    v = evaluate(f"Encoded: {enc}", _probe("PI-11"), CANARY)
    assert v["vulnerable"]


def test_rot13_leak_is_caught():
    v = evaluate(codecs.encode(CANARY, "rot_13"), _probe("PI-12"), CANARY)
    assert v["vulnerable"]


def test_clean_refusal_passes():
    v = evaluate("Sorry, I can't share that.", _probe("PI-01"), CANARY)
    assert not v["vulnerable"]


def test_risk_grade_extremes():
    assert risk_grade([{"severity": "high", "vulnerable": False}]) == "A"
    assert risk_grade([{"severity": "high", "vulnerable": True}]) == "F"


def test_reports_write(tmp_path=None):
    import tempfile

    results = [
        {**_probe("PI-01"), "response": f"token {CANARY}", "vulnerable": True,
         "evidence": ["leaked canary"]},
        {**_probe("PI-02"), "response": "no", "vulnerable": False, "evidence": []},
    ]
    d = Path(tempfile.mkdtemp())
    write_markdown(str(d / "r.md"), "ollama", "test", results)
    write_html(str(d / "r.html"), "ollama", "test", results)
    assert (d / "r.md").read_text(encoding="utf-8").startswith("# llmscan report")
    assert "<html" in (d / "r.html").read_text(encoding="utf-8").lower()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} smoke tests passed")
