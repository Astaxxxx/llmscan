llmscan v0.1.2 — an OWASP-LLM-Top-10 (2025) red-team scanner for LLM apps.

Point it at a model or your app's system prompt and it fires 29 adversarial probes, then
grades the result A–F and writes a report you can hand to a stakeholder.

**Changed since v0.1.1**
- Redesigned the HTML report. It now reads as a technical audit document — hairline rules
  instead of cards, a monospace metadata masthead, tabular figures, and colour used only to
  encode severity. Failing rows carry a single marker on the leading cell, and the grade is
  typographic rather than a coloured tile. Added print rules (findings no longer break across
  pages) and a small-screen layout.
- The Markdown report uses plain `FAIL` / `pass` instead of emoji, so it reads cleanly in a
  terminal, a diff, and on GitHub.

**Fixed in v0.1.1** — scans no longer crash on Windows. The run header and summary printed
`→` and `·` straight to the terminal, which raises `UnicodeEncodeError` on a default cp1252
console. Console output is ASCII-only now; report files were always utf-8 and unaffected.

**What it does**
- 29 probes across 6 OWASP LLM Top 10 (2025) categories — direct prompt-injection overrides,
  role-play/DAN jailbreaks, fake-audit social engineering, payload splitting, indirect
  (poisoned-document) injection, and encoded data exfiltration.
- Canary-based detection: a secret token is planted in the system prompt, and the detector
  decodes base64, ROT13 and reversed output before checking — so obfuscated leaks still get
  caught.
- Optional LLM-as-judge for nuanced cases (acrostics, "is this SQL injectable?").
- Reports in three formats: terminal, Markdown, and HTML with an A–F risk grade.
- Ships as a GitHub Action (`action.yml`) that fails the build on a finding, so it drops
  straight into CI.

**Running it**
Bring your own key, or run it free against a local Ollama model:
```
python -m llmscan scan -p ollama -m llama3.2 --html report.html
```

**Sample output:** [`docs/sample-report.md`](https://github.com/Astaxxxx/llmscan/blob/main/docs/sample-report.md)
— a real run against `llama3.2`: 7 of 29 probes found a vulnerability, risk grade C, with
4 of 5 system-prompt-leakage probes succeeding.

**Scope:** defensive use only — test systems you own or are authorised to test.

MIT licensed. Probe ideas and PRs welcome.
