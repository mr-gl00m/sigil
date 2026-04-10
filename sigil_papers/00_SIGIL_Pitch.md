# SIGIL: Security Layer for Agentic AI Systems

**A document bundle prepared for technical and decision-making review**

*Nathan 'Cid' Seals — April 2026*  
---

## Who I Am

Independent developer and security researcher. I build and publish open-source tools across AI infrastructure, cryptographic security layers, and applied physics simulation. Recent public work includes the *Geometry of Nothing* QFT paper and the *Nothing Engine* simulator (both on GitHub under `mr-gl00m`). All work in this bundle is MIT licensed and publicly timestamped.

Contact: [thenathanseals@gmail.com](mailto:thenathanseals@gmail.com) · GitHub: [https://github.com/mr-gl00m](https://github.com/mr-gl00m)   
---

## What's In This Bundle

This bundle contains three documents covering **SIGIL**, an open-source structural security layer for agentic AI deployments (LLM-driven systems that take real-world actions on behalf of users).

| Document | Length | Audience |
| :---- | :---- | :---- |
| **1\. SIGIL: Security for AI Systems That Actually Do Things** | \~6 pages | Engineering leads, operations, anyone evaluating whether SIGIL fits a deployment |
| **2\. On the Necessity of a Structural Security Layer for Agentic AI Systems** | \~15 pages | Security architects, CTOs, researchers; technical whitepaper with threat model and design rationale |
| **3\. SIGIL v1.5.0 Security Hardening Report** | \~4 pages | Compliance, audit, legal; full per-round remediation history across 88 findings |

---

## Which One To Read First

- **If you're deciding whether SIGIL is relevant to your deployment:** Start with Document 1\. It explains what SIGIL does, how it integrates, and what it costs, in plain language with concrete examples.  
- **If you're evaluating the technical and architectural claims:** Start with Document 2\. It lays out the threat model, the seven structural design commitments, and the argument for why they should be the baseline for any agentic system post-Mythos.  
- **If you need evidence of security review rigor for compliance or procurement:** Start with Document 3\. It documents five independent review rounds, 88 findings, and full remediation across cryptographic hardening, red team assessment, architectural gap closure, and cross-reference against a leaked commercial agent codebase.

Most readers should begin with Document 1 and proceed to Document 2 only if they want the full technical argument. Document 3 is reference material.  
---

## Why This Matters Right Now

On April 7, 2026, Anthropic released Claude Mythos Preview... a model whose autonomous vulnerability-discovery capabilities have made ad-hoc security postures for agentic AI systems untenable. Similar capabilities will be in other frontier models within 6–18 months. Any organization running AI agents in production, particularly those serving multiple clients from shared infrastructure, will need a defensible answer to "how is our agent layer protected?" SIGIL is one such answer, freely available, with no vendor lock-in and no external dependencies beyond widely-audited open-source cryptography libraries.  
---

## Project Details

- **Repository:** github.com/mr-gl00m/sigil  
- **License:** MIT  
- **Dependencies:** `pynacl` (libsodium bindings), optional `httpx` and `tiktoken`  
- **Test suite:** 310 tests, 0 failures  
- **Security review history:** 5 rounds, 88 findings, all remediated  
- **Integration effort:** Hours, not weeks

---

*I'm happy to answer questions, walk through integration, or discuss threat modeling for specific deployment shapes. No sales process, no gatekeeping... the code is public and the documents are attached.*  
