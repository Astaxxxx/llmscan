llmscan v0.1.0 — first public release.

An OWASP-LLM-Top-10 (2025) red-team scanner for LLM apps. Point it at a model or your app's
system prompt and it fires 29 adversarial probes, then grades the result A–F and writes a
report you can hand to a stakeholder.

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
python -m llmscan scan -p ollama -m llama3.1 --html report.html
```

**Sample output:** `docs/sample-report.html`

**Scope:** defensive use only — test systems you own or are authorised to test.

MIT licensed. Probe ideas and PRs welcome.
