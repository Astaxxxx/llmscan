# llmscan — launch kit

Everything you need to ship it today. Replace `Astaxxxx` if your GitHub handle differs,
and paste your real repo URL where noted. **Post the demo report first** (run a scan,
commit `report.html`) so links have something to show.

---

## 0. Pre-flight (5 min)
```bash
cd C:\Users\malus\Documents\llmscan
# generate a demo artefact people can see (free, local):
ollama pull llama3.1
python -m llmscan scan -p ollama -m llama3.1 --html docs/sample-report.html
git add docs/sample-report.html && git commit -m "docs: sample report"
git push
```
Then make sure the repo is **public**, the description is set, and topics are added:
`llm-security`, `prompt-injection`, `owasp`, `ai-security`, `red-team`, `security-tools`.

---

## 1. GitHub repo "About"
> An OWASP-LLM-Top-10 red-team scanner for LLM apps — prompt injection, jailbreaks &
> system-prompt leaks, with an A–F report. nmap/Burp, but for AI apps.

---

## 2. Hacker News (Show HN)
**Title:**
`Show HN: llmscan – nmap/Burp for LLM apps (OWASP LLM Top 10 red-team scanner)`

**Body:**
> I built llmscan, a CLI that red-teams an LLM app for prompt injection, jailbreaks and
> system-prompt leakage, then grades it A–F against the OWASP Top 10 for LLM Apps (2025).
>
> It injects a secret "canary" into the system prompt and runs 29 probes that try to
> extract it or make the model misbehave — direct overrides, role-play/DAN, fake audits,
> payload-splitting, indirect (poisoned-document) injection, and **encoded exfiltration**
> (base64/ROT13/reversed), which it catches by decoding the response before checking. There's
> an optional LLM-as-judge for nuanced cases (acrostics, "is this SQL injectable?").
>
> It's bring-your-own-key and runs free against a local Ollama model, so you can test your
> own app's system prompt with one command and wire it into CI (the GitHub Action fails the
> build on a finding).
>
> I'm a cybersecurity grad who moved into AI engineering, and I kept seeing teams ship LLM
> features with zero adversarial testing. Comparable tools (garak, PyRIT, promptfoo) exist
> but felt heavy; I wanted something focused, OWASP-mapped, with a report you can hand to a
> stakeholder. Feedback very welcome — especially on probes I'm missing.
>
> Repo: <PASTE REPO URL>

*(Tip: post 8–10am ET on a weekday. Reply to every comment in the first 2 hours.)*

---

## 3. r/netsec (or r/cybersecurity / r/LLMDevs)
**Title:**
`llmscan – an open-source OWASP-LLM-Top-10 red-team scanner (prompt injection, jailbreaks, system-prompt leaks)`

**Body:**
> Open-sourced a tool I built: llmscan runs 29 prompt-injection / jailbreak / data-leak
> probes against an LLM app and reports pass/fail mapped to the OWASP LLM Top 10 (2025),
> with an A–F risk grade and an HTML report.
>
> Method is a canary in the system prompt + a layered detector that also base64/ROT13/reverse-
> decodes the response (so obfuscated exfiltration gets caught), plus an optional LLM judge.
> BYO-key, runs free on local Ollama, MIT-licensed, has a GitHub Action for CI gating.
>
> Defensive use only (test systems you own/are authorised to test). Would love probe ideas
> and PRs. Repo: <PASTE REPO URL>

*(r/netsec has a strict "no blogspam" culture — a tool repo with a clear README is fine. Read the rules; some subs require a self-post with detail, not just a link.)*

---

## 4. LinkedIn
> I kept seeing the same gap: teams shipping LLM features with no adversarial testing at all.
> So I built **llmscan** — an open-source red-team scanner for AI apps.
>
> Point it at a model or your app's system prompt and it fires 29 attacks — prompt injection,
> jailbreaks, system-prompt leaks, encoded data exfiltration — then grades you A–F against the
> OWASP Top 10 for LLM Applications. One command, runs free on a local model, and drops into CI.
>
> It sits right on the AI × security intersection — which is exactly where I want to work:
> cybersecurity background, now building with LLMs.
>
> It's MIT-licensed and live here 👉 <PASTE REPO URL>
>
> Probe ideas and PRs welcome. What's the worst prompt-injection you've seen in the wild?
>
> #AISecurity #LLM #CyberSecurity #OWASP #PromptInjection #OpenSource

---

## 5. X / Twitter
> built llmscan 🛡️ — nmap/Burp but for LLM apps.
>
> 29 probes for prompt injection, jailbreaks & system-prompt leaks → A–F report, mapped to
> the OWASP LLM Top 10. catches base64/ROT13-encoded data exfil. free on local Ollama, MIT,
> drops into CI.
>
> <PASTE REPO URL>

---

## 6. After launch
- Add the repo to your CV / portfolio as the headline AI×security project ("apply with the repo").
- Open 2–3 GitHub issues yourself (roadmap items: agent scanning, RAG leakage) so contributors see direction.
- DM it to 3 AI-security people whose work you follow, asking for one piece of feedback (not a job).
- When applying to roles, link a **specific** sample report, not just the repo root.
