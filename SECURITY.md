# Security Policy

SIGIL is a security project. Vulnerability reports are welcome and taken seriously.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email reports to: **thenathanseals@gmail.com**

Subject line: `[SIGIL SECURITY] <short summary>`

Useful contents:
- A description of the vulnerability and the impact you can demonstrate.
- A minimal reproducer — code, prompts, or steps. The shorter the better.
- The SIGIL version (`python sigil.py --version`) and Python version.
- Your preferred name (or pseudonym) for credit, or a request for anonymity.

A PGP key is not currently published. Plaintext email is acceptable for the threat model SIGIL targets — if you need an encrypted channel for an unusually sensitive report, mention it in your first email and I'll set up Signal or a one-time PGP key.

## What to Expect

| Stage | Target |
|-------|--------|
| Acknowledgement of receipt | Within 72 hours |
| Initial triage and severity assessment | Within 7 days |
| Fix in `main` for confirmed CRITICAL or HIGH issues | Within 14 days |
| Coordinated disclosure window | 90 days from acknowledgement, or sooner if a fix ships |

These are targets for a solo-maintained project. If a deadline slips, you'll get a status update — not silence.

## Scope

In scope:
- `sigil.py`, `sigil_audit_proxy.py`, `sigil_llm_adapter.py` and the test suite.
- The cryptographic guarantees the documentation claims (signature verification, audit chain integrity, encrypted state at rest, validator gate behavior, human gate signing).
- Anything that causes SIGIL's own code to behave differently than what the README, pitch documents, or whitepaper assert.

Out of scope:
- Vulnerabilities in `pynacl`, `httpx`, `tiktoken`, or other dependencies — report those upstream.
- LLM behaviors that are not SIGIL's responsibility (a model that ignores signed instructions is doing what models do; SIGIL is a flight recorder, not a force field, and the README says so).
- Issues that require an attacker who already has root on the host running SIGIL. The threat model assumes the host is not yet compromised.
- Theoretical issues with no demonstrable impact in the current codebase.

## Disclosure Policy

I prefer coordinated disclosure. After a fix ships, you're welcome to publish your findings — I'll typically link your write-up from the CHANGELOG entry.

If a vulnerability is being actively exploited, or if 90 days have passed without a fix, you're free to disclose publicly. Send a heads-up email so I can prepare a response.

## Safe Harbor

Good-faith security research against your own SIGIL deployments — fuzzing, prompt injection trials, audit chain probing, etc. — is welcome. Don't run experiments against systems you don't own or have explicit permission to test, and don't exfiltrate data beyond what's needed to demonstrate the issue.

## Past Reports

The remediation history of the project is in [CHANGELOG.md](CHANGELOG.md). Each prior round (v1.1.0 through v1.5.0) was self-conducted using adversarial LLM prompting; SIGIL has not yet been engaged with an external auditor. If your report would be the first external one, that fact will be acknowledged in the credit line.
