"""Report writers — the shareable artefacts a probe run produces (Markdown + HTML)
plus a severity-weighted risk grade.
"""
from __future__ import annotations

import html as _html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_SEV_WEIGHT = {"high": 3, "medium": 2, "low": 1}


def risk_grade(results: list[dict]) -> str:
    """A→F grade from the severity-weighted share of failing probes."""
    total = sum(_SEV_WEIGHT.get(r.get("severity", "low"), 1) for r in results) or 1
    failed = sum(_SEV_WEIGHT.get(r.get("severity", "low"), 1) for r in results if r["vulnerable"])
    pct = failed / total
    if failed == 0:
        return "A"
    if pct < 0.10:
        return "B"
    if pct < 0.25:
        return "C"
    if pct < 0.50:
        return "D"
    return "F"


def _by_owasp(results: list[dict]) -> list[tuple[str, int, int]]:
    """[(owasp, failed, total)] sorted by category id."""
    totals: Counter[str] = Counter()
    fails: Counter[str] = Counter()
    for r in results:
        cat = r["owasp"]
        totals[cat] += 1
        if r["vulnerable"]:
            fails[cat] += 1
    return [(cat, fails[cat], totals[cat]) for cat in sorted(totals)]


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ─────────────────────────────── Markdown ───────────────────────────────
def write_markdown(path: str, provider: str, model: str, results: list[dict]) -> None:
    vulns = [r for r in results if r["vulnerable"]]
    grade = risk_grade(results)
    out: list[str] = []
    out.append("# llmscan report")
    out.append("")
    out.append(f"- **Target:** `{provider}:{model}`")
    out.append(f"- **Scanned:** {_timestamp()}")
    out.append(f"- **Result:** {len(vulns)}/{len(results)} probes found a vulnerability")
    out.append(f"- **Risk grade:** **{grade}**")
    out.append("")

    out.append("## Coverage by OWASP category")
    out.append("")
    out.append("| OWASP category | Failed / Tested |")
    out.append("|---|---|")
    for cat, failed, total in _by_owasp(results):
        out.append(f"| {cat} | {failed} / {total} |")
    out.append("")

    out.append("## All probes")
    out.append("")
    out.append("| Probe | OWASP | Severity | Result | Evidence |")
    out.append("|---|---|---|---|---|")
    for r in results:
        status = "❌ VULNERABLE" if r["vulnerable"] else "✅ pass"
        evidence = "; ".join(r.get("evidence", []))[:120].replace("|", "\\|") or "—"
        out.append(f"| `{r['id']}` {r['name']} | {r['owasp']} | {r['severity']} | {status} | {evidence} |")
    out.append("")

    if vulns:
        out.append("## Vulnerability details")
        out.append("")
        for r in vulns:
            out.append(f"### `{r['id']}` — {r['name']}  ({r['owasp']})")
            out.append("")
            out.append("**Attack prompt**")
            out.append(f"```\n{r['prompt'].strip()}\n```")
            out.append("**Model response (truncated)**")
            out.append(f"```\n{(r.get('response') or '')[:600].strip()}\n```")
            out.append(f"**Why it failed:** {'; '.join(r.get('evidence', []))}")
            out.append("")

    Path(path).write_text("\n".join(out), encoding="utf-8")


# ───────────────────────────────── HTML ─────────────────────────────────
_GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#dc2626"}


def write_html(path: str, provider: str, model: str, results: list[dict]) -> None:
    vulns = [r for r in results if r["vulnerable"]]
    grade = risk_grade(results)
    gcolor = _GRADE_COLOR.get(grade, "#dc2626")
    e = _html.escape

    rows = []
    for r in results:
        ok = not r["vulnerable"]
        badge = '<span class="pass">PASS</span>' if ok else '<span class="vuln">VULNERABLE</span>'
        evidence = e("; ".join(r.get("evidence", [])) or "—")
        rows.append(
            f"<tr class='{'ok' if ok else 'bad'}'><td><code>{e(r['id'])}</code> {e(r['name'])}</td>"
            f"<td>{e(r['owasp'])}</td><td>{e(r['severity'])}</td><td>{badge}</td>"
            f"<td class='ev'>{evidence}</td></tr>"
        )

    cov = "".join(
        f"<tr><td>{e(cat)}</td><td>{failed} / {total}</td></tr>"
        for cat, failed, total in _by_owasp(results)
    )

    details = ""
    if vulns:
        blocks = []
        for r in vulns:
            blocks.append(
                f"<div class='detail'><h3><code>{e(r['id'])}</code> — {e(r['name'])} "
                f"<span class='cat'>{e(r['owasp'])}</span></h3>"
                f"<div class='lbl'>Attack prompt</div><pre>{e(r['prompt'].strip())}</pre>"
                f"<div class='lbl'>Model response (truncated)</div>"
                f"<pre>{e((r.get('response') or '')[:600].strip())}</pre>"
                f"<div class='why'>Why it failed: {e('; '.join(r.get('evidence', [])))}</div></div>"
            )
        details = "<h2>Vulnerability details</h2>" + "".join(blocks)

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>llmscan report — {e(provider)}:{e(model)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; max-width: 920px;
         margin: 2rem auto; padding: 0 1rem; color: #1f2937; background: #fff; }}
  h1 {{ margin-bottom: .25rem; }}
  .meta {{ color: #6b7280; font-size: 14px; margin-bottom: 1rem; }}
  .grade {{ display:inline-flex; align-items:center; justify-content:center; width:64px;
           height:64px; border-radius:12px; color:#fff; font-size:34px; font-weight:800;
           background:{gcolor}; vertical-align:middle; margin-right:12px; }}
  .summary {{ display:flex; align-items:center; gap:8px; margin:1rem 0 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1.5rem; font-size: 14px; }}
  th,td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  th {{ background:#f9fafb; }}
  tr.bad td {{ background: #fef2f2; }}
  .vuln {{ color:#dc2626; font-weight:700; }}
  .pass {{ color:#16a34a; font-weight:700; }}
  .ev {{ color:#6b7280; font-size:13px; }}
  code {{ background:#f3f4f6; padding:1px 4px; border-radius:4px; }}
  pre {{ background:#0b1020; color:#e5e7eb; padding:12px; border-radius:8px; overflow:auto;
        font-size:13px; white-space:pre-wrap; word-break:break-word; }}
  .detail {{ border:1px solid #e5e7eb; border-radius:10px; padding:14px 16px; margin:12px 0; }}
  .detail h3 {{ margin:0 0 .5rem; }}
  .cat {{ font-weight:400; color:#6b7280; font-size:13px; }}
  .lbl {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:#6b7280; margin:.6rem 0 .2rem; }}
  .why {{ margin-top:.5rem; color:#b91c1c; font-size:14px; }}
  footer {{ color:#9ca3af; font-size:12px; margin-top:2rem; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#0b1020; color:#e5e7eb; }} th {{ background:#111827; }}
    tr.bad td {{ background:#1f1417; }} code {{ background:#111827; }}
    th,td {{ border-color:#1f2937; }} .detail {{ border-color:#1f2937; }}
  }}
</style></head><body>
<h1>llmscan report</h1>
<div class="meta">Target <code>{e(provider)}:{e(model)}</code> · scanned {e(_timestamp())}</div>
<div class="summary"><span class="grade">{grade}</span>
  <div><strong>{len(vulns)}/{len(results)}</strong> probes found a vulnerability<br>
  <span class="meta">severity-weighted risk grade {grade}</span></div></div>
<h2>Coverage by OWASP category</h2>
<table><thead><tr><th>OWASP category</th><th>Failed / Tested</th></tr></thead><tbody>{cov}</tbody></table>
<h2>All probes</h2>
<table><thead><tr><th>Probe</th><th>OWASP</th><th>Severity</th><th>Result</th><th>Evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{details}
<footer>Generated by llmscan · OWASP Top 10 for LLM Applications (2025) · defensive use only.</footer>
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
