# An AI code review found two lies in my own security project's documentation

I run a small open-source project called SIGIL. It is a cryptographic prompt security for agentic LLM systems, MIT licensed, single maintainer. Several weeks ago I asked Claude to do a comprehensive review of a different project of mine, and the review document came back with a "specific flags" section that contained three credibility-bleeding issues in SIGIL's *documentation*. None of them were technical bugs. The code was fine. The test suite was passing. The cryptographic guarantees held up.

What the documentation did was sell something I hadn't actually delivered.

I don't claim to be an expert by any means, but I am passionate about the work I do. I genuinely believe in my work and made them to help people in some of the toughest areas of tech right now. But I don't want to claim ignorance either. So, I'm publishing this. Honestly though? The meta-pattern is the interesting part. In security tools especially, documentation accuracy *is* the product. A library that does the right thing but describes itself dishonestly is worse than one that does less but describes it honestly. Buyers, contributors, and security researchers all triangulate on tone. The tone of my docs was selling something I hadn't actually delivered, and three different readers... A lawyer, an AI engineer, a CTO... Would each spot a different one of these on first contact and close the tab.

Here's what I had to fix.

## Lie #1: My LICENSE file contradicted my own marketing

The repo had:
- A README badge saying CC0
- A README footer saying CC0 ("do whatever you want, no attribution required, fork it sell it")
- A `LICENSE` file at the repo root containing the actual CC0 1.0 text
- A pitch document — the one I'd send to engineering leads evaluating the project, saying *MIT*
- A whitepaper saying *MIT*
- A second pitch saying *MIT*

So which was it? Whichever claim the reader hit first. They'd skim the README, see the CC0 badge, conclude "public domain, easy." Then they'd open the formal pitch and see "License: MIT" and have to mentally context-switch. Then they'd open the LICENSE file and see CC0 again. Three artifacts disagreeing inside a single repository is the kind of thing that takes a compliance person about six seconds to spot, and the conclusion they draw is not flattering.

The "no attribution required" footer was particularly bad. That phrasing is *CC0 phrasing*. MIT requires the license notice to travel with derivative works. Anyone who has read the actual text of the MIT license for thirty seconds knows this. Telling people they can use my MIT-licensed software with no attribution required is just... Wrong, in a way that reads as "the author doesn't understand his own license."

I picked MIT, since that was what the pitch documents had been claiming. Wrote the OSI-canonical MIT text into LICENSE. Scrubbed every CC0 reference across README, CONTRIBUTING.md, source-file headers, the demo banner, the historical release-notes footers. Replaced the "no attribution required" line with "use it commercially or personally, modify it, ship it, the only requirement is that the copyright notice and license text travel with derivative works."

Time to fix: just an evening and an energy drink. Time it'd been broken: every public release since v1.0. Ouch.

## Lie #2: "Five rounds of independent security review" implied something that wasn't true

This was the one that bothered me most.

The pitch documents said the project had been *"hardened across five rounds of independent security review."* They described two of them as *"two independent red team assessments."* A summary table at the bottom of one document listed the rounds, the findings per round, and a total: 88 findings identified, 88 remediated.

The number is real. There genuinely were five distinct review passes. All poised to absolutely obliterate SIGIL. They genuinely found 88 distinct issues. Each finding has a CHANGELOG entry pointing at the specific commit that fixed it. The remediation work is documented in detail and the test coverage that came out of it is real. None of that part is a lie.

But "independent." In English-as-spoken-by-anyone-evaluating-a-security-project, "independent security review" means a third party. An external auditor. A firm. Someone with no incentive to make the project look good. That is not what happened. Every one of the five rounds was self-conducted. They were structured red-team passes where I prompted frontier LLMs (Claude, GPT-4, Gemini) with adversarial regimens... Different prompt templates, different threat models, different attacker personas... And worked through the output finding-by-finding. Genuine work. Real findings, of the kind a real attacker would have found later. But not a third-party engagement.

To a CTO doing procurement diligence, *"five rounds of independent review"* reads as *"five external auditors said this thing was good."* That is a procurement-relevant claim. It implies external validation of the kind regulated industries actually require. And quietly trading on the ambiguity is dishonest, even if every individual word in the sentence is technically defensible.

I rewrote every instance. The new framing across all pitch documents: *"structured red-team review, self-conducted by the author using adversarial prompting against frontier LLMs (Claude, GPT-4, Gemini)."* The project history table got an explicit closer: *"All review rounds were self-conducted; no external auditor has been engaged at this time."* The first-row label *"Initial audit"* got changed to *"Self-audit"* so the framing carries through every reference, not just the prose.

Self-conducted LLM-assisted red-team review is a legitimate technique. It is *not* the same as third-party audit. The project is stronger for the work but the work needs to be characterized accurately. If you happen to be the first external auditor reading this and you'd like to be the first to engage with SIGIL formally, the SECURITY.md has my email. The credit line is open.

## The meta-pattern

These two issues had nothing to do with the code. The code is fine. The test suite is 310 tests, 0 failures. The cryptographic guarantees hold. The architectural claims about deterministic validation and Merkle-linked audit chains and capability-ID resolution are all real and verifiable in roughly 3,000 lines of auditable Python.

But the documentation around the code is what most people read. A buyer, a contributor, a researcher, a journalist... They hit README first, pitch second, paper third. Code maybe never. The documentation is the sales surface, the trust surface, and the credibility surface, all the same surface, and a single inconsistency on it can sink the credibility of all the work behind it.

The pattern I'd been falling into:

1. Draft a claim quickly, often with LLM help, in the flow of writing other prose.

2. The draft looks fine.

3. The draft becomes the core version because nothing forces me to revisit it.

4. Months later, a reader hits a mismatch, a license that disagrees with itself, a fact that turns out not to be sourced, a phrasing that implies something the project doesn't deliver, and the credibility hit lands. By that point the draft has propagated to three documents and the website footer.

There is no way to catch this from inside your own project. You wrote the draft. It looks fine to you because you remember what you meant. You don't remember what you wrote.

The thing that worked: I asked an outside LLM to do an adversarial review of the *documentation*, as well as the code. Specifically: pretend you're a CTO evaluating this project for procurement; what's the first thing that would make you close the tab? It came back with three issues. Three claims that didn't survive contact with a hostile reader. Three specific lies are not the fix. The fix is the discipline of having an outside reader look at the documentation adversarially before it ships, every time, especially when the documentation has been drafted with LLM assistance.

The interesting bit I realized: LLMs hallucinate, how can you trust the review? The LLM doesn't decide what's *true*. It generates a list of claims to *verify*. Some flags hold up; some don't. The Mythos reference in my pitch documents got flagged by the same review pass and turned out to be solid, I'd already sourced it. Pretty thoroughly. But it had no record of Mythos even *existing*. The discipline is using the LLM as a candidate generator, then verifying each candidate against the actual source. We can't get lazy with this technology, and we have to be transparent, with ourselves and with readers, about its limitations. It used to only be human error we had to worry about. Now we're entering an age where this applies to users, developers, and the machines we use to interact with them. It is genuinely interesting, terrifying, and exciting.

So, if you're shipping a security tool, your documentation has to clear the same bar your code does, even if that's the part that sucks to make. The cryptographic guarantees are formal claims; the prose around them is also a formal claim. Saying things accurately matters more than saying things impressively. If you can't say it accurately, don't say it at all.

## Where SIGIL is now

V1.6.1 shipped today with all three fixes plus the project hygiene that had been deferred (SECURITY.md with a real disclosure process, pyproject.toml so `pip install` will work as soon as it's on PyPI, GitHub Actions CI on Python 3.10/3.11/3.12 across Ubuntu and Windows, single-page project site at the repo's GitHub Pages URL).

License is MIT. Every reference is sourced. The review history is characterized as self-conducted, finding-by-finding. The 88-findings figure stands; what changed is what surrounds it.

Still solo-maintained. Still no external auditor (drop me a line if you want to be the first). Still a flight recorder, not a force field, see the SECURITY.md and the Limitations section of the whitepaper for the honest version of what SIGIL does and doesn't do.

Repository: [github.com/mr-gl00m/sigil](https://github.com/mr-gl00m/sigil)

Release notes: [v1.6.1](https://github.com/mr-gl00m/sigil/blob/main/release/RELEASE_NOTES_v1.6.1.md)

If you want to talk about LLM-assisted documentation review, or you spot a third thing I missed, the email's in the SECURITY.md.

- Cid

---

*Discussion: [Hacker News](#) · [Lobsters](#) · [r/netsec](#)* — links populated post-submission.
