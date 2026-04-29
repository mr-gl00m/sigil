# SIGIL v1.6.1 — License migration, project hygiene, documentation honesty

A maintenance release that fixes three credibility-bleeding gaps in SIGIL's documentation and adds the project hygiene that makes the repo look like a real open-source library instead of a one-off. No security-behavior changes; the test suite (310 passed, 2 skipped) is unchanged.

> **Note on versioning.** The previous tagged release on the GitHub remote is `v1.6.0`. This release skips a separate `v1.6.0` entry in the local CHANGELOG because local working-tree development continued from `v1.5.0`, and the `v1.6.0` notes live on the GitHub Releases page. `v1.6.1` is being shipped as the patch on top of `v1.6.0`. The `v1.5.0` code changes (encrypted state at rest, embedded encoding detection, file-lock coverage on state writes, bounded audit queue, sensitive-file permissions) are also included in this distribution; they were never separately tagged in local git history.

---

## License: CC0 → MIT

The repo previously carried a CC0 1.0 `LICENSE` file but described itself as MIT in every pitch document. That contradiction is fixed: SIGIL is now MIT licensed, with the MIT text propagated across `LICENSE`, README badge and footer, `CONTRIBUTING.md`, source-file headers in `sigil.py` / `sigil_audit_proxy.py` / `sigil_llm_adapter.py`, the demo banner, and historical release-notes footers.

The README's old "no attribution required, fork it sell it" line was CC0 phrasing and incorrect for MIT. Replaced with: **use it commercially or personally, modify it, ship it — the only requirement is that the copyright notice and license text travel with derivative works.**

Existing CC0 grants for code published under prior tags remain valid for what was distributed at the time. Going forward, every release is MIT.

## Project hygiene

- **`SECURITY.md`** — responsible-disclosure process, contact email, response-time targets (72h ack, 14-day fix for confirmed CRITICAL/HIGH, 90-day coordinated disclosure window), explicit safe-harbor language for good-faith research.
- **`pyproject.toml`** — PEP 621 metadata. After the first PyPI upload, `pip install sigil-security[all]` will pull SIGIL plus the optional LLM and token-counting dependencies. Optional dependency groups: `[llm]` for `httpx` + `python-dotenv`, `[tokens]` for `tiktoken`, `[all]` for both, `[dev]` for the test suite.
- **GitHub Actions CI** at `.github/workflows/ci.yml` — runs pytest on Python 3.10 / 3.11 / 3.12 across Ubuntu and Windows, plus a `python -m build` + `twine check` pass on every push and pull request. The README now carries a CI status badge.
- **`_cli_entry()`** added to `sigil.py` so the `sigil` console script registered in `pyproject.toml` reproduces the existing `__main__` dispatch (no-args → demo, args → CLI).
- **Project website** — single-page HTML at `docs/index.html`, no JavaScript, no external dependencies, dark theme. Deploys via GitHub Pages from `main` / `/docs`. `docs/.nojekyll` keeps the custom HTML untouched.

## Documentation honesty

The pitch documents (`paper-sigil_2026-04-17/00_SIGIL_Pitch.md`, `01_SIGIL_Overview.md`, `02_SIGIL_Whitepaper.md`) previously claimed *"five rounds of independent security review"* and *"two independent red team assessments."* Reframed every instance as **"structured red-team review, self-conducted by the author using adversarial prompting against frontier LLMs (Claude, GPT-4, Gemini)."** The 88-findings figure stands; the implication of external auditing did not match reality. If you intend to be the first external auditor, see [`SECURITY.md`](https://github.com/mr-gl00m/sigil/blob/main/SECURITY.md).

Every reference to the April 7, 2026 Anthropic *Claude Mythos Preview* announcement now links to the [official Anthropic post](https://red.anthropic.com/2026/mythos-preview/) so readers can verify the claim in one click.

For the full first-person write-up of the credibility-fix process — what the gaps were, how they were found, why they mattered — see [`BLOG_2026-04-28_credibility_fixes.md`](https://github.com/mr-gl00m/sigil/blob/main/BLOG_2026-04-28_credibility_fixes.md).

## Install

```bash
# Once published to PyPI:
pip install sigil-security[all]

# From source (today):
git clone https://github.com/mr-gl00m/sigil.git
cd sigil
git checkout v1.6.1
pip install -e ".[dev]"
python -m pytest tests/ -q   # 310 passed, 2 skipped
python sigil.py demo
```

## What didn't change

- **No security-behavior changes.** The cryptographic guarantees, the validator gate, the audit chain, the input normalizer, and the human-in-the-loop sign-off all behave identically to v1.6.0. Encrypted state files, capability-ID resolution, effect-class enforcement — all the prior hardening is preserved.
- **No API surface changes.** Existing `Architect.seal()`, `SigilRuntime.execute()`, `ContextArchitect.build_context()`, `HumanGate.request_approval()`, and the `@vow` decorator continue to work exactly as before.
- **No new external dependencies.** Required deps remain `pynacl`. Optional deps remain `httpx`, `python-dotenv`, `tiktoken`.

## Tag history

- `v1.6.1` — this release (license + hygiene + documentation honesty)
- `v1.6.0` — prior release, GitHub-only (notes on the Releases page)
- `v1.4.0` — Deterministic Validator Gate (tagged retroactively on 2026-04-28; commit dates from 2026-04-01)
- `v1.3.0` — Complete Red Team Remediation
- `v1.1.0` — Initial security remediation (53 findings)

`v1.5.0` and `v1.2.0` are not tagged in git history because the corresponding work never had clean isolated commit boundaries. Their changes are included in v1.6.1 and v1.3.0 respectively. See [`CHANGELOG.md`](https://github.com/mr-gl00m/sigil/blob/main/CHANGELOG.md) for full per-version remediation history.

## Links

- [README](https://github.com/mr-gl00m/sigil/blob/main/README.md)
- [Credibility-fix blog post](https://github.com/mr-gl00m/sigil/blob/main/BLOG_2026-04-28_credibility_fixes.md) — first-person write-up of why this release exists
- [Whitepaper — On the Necessity of a Structural Security Layer for Agentic AI Systems](https://github.com/mr-gl00m/sigil/blob/main/paper-sigil_2026-04-17/02_SIGIL_Whitepaper.md)
- [Overview — Security for AI Systems That Actually Do Things](https://github.com/mr-gl00m/sigil/blob/main/paper-sigil_2026-04-17/01_SIGIL_Overview.md)
- [Security Policy](https://github.com/mr-gl00m/sigil/blob/main/SECURITY.md)
- [Project Website](https://mr-gl00m.github.io/sigil/) (active once GitHub Pages is enabled)

---

*SIGIL is built and maintained by [Cid (mr-gl00m)](https://github.com/mr-gl00m). Independent developer, security researcher, MIT licensed.*
