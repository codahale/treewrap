---
name: adversarial-review
description: Run a multi-perspective adversarial review of the LaTeX paper manuscript in ./paper/ (or a specific section file within it). Fans out reviewers across a section x perspective grid in parallel, independently validates each raised finding with isolated subagents, and writes triaged surviving findings to review.tmp.md at the repo root.
---

# Adversarial review

Use when the user asks to "review" or "adversarially review" the paper manuscript in `./paper/`, or a specific section/appendix within it. The skill runs two parallel waves of subagents — reviewers (claim generators) then validators (claim checkers) — and writes the surviving findings to `./review.tmp.md`. Reviewers still raise the occasional false positive; the validator pass is what makes the report trustworthy regardless of how clean any given reviewer run is.

## Caller signature

`/adversarial-review [target]` — `<target>` is optional. It can be:

- omitted — review the full manuscript (`paper/main.tex` plus its `\input`-ed section and appendix files);
- a section file path (`paper/sections/06-privacy.tex`);
- a section keyword that maps to a file (`privacy`, `authenticity`, `cmtds3`, `appendix-lemmas`, etc.).

If the user names a section that doesn't map cleanly to a file, ask which one they mean before fanning out.

## Step 1 — Build the section x perspective grid

Read `paper/main.tex` for the manuscript's structure (which section/appendix files are `\input`-ed and in what order) and skim the candidate section files. Then pick:

- **Sections (3–6).**
  - For a full-manuscript run, pick from the proof-bearing files in `paper/sections/` — definitions (`02-preliminaries`, `03-tw128`, `04-security-model`), headline corollaries (`05-main-results`), the main reductions (`06-privacy`, `07-authenticity`, `08-cmtds3`), and the technical appendices (`appendix-lemmas`, `appendix-flat-sponge-lift`, `appendix-committing-transfer`). Skip pure-exposition files (introduction, performance, discussion, conclusion) unless the user asks otherwise.
  - For a single-file run, treat the file's top-level `\section`/`\subsection` blocks as sections.
  - Aim for chunks of roughly 50–200 source lines — avoid one reviewer per tiny subsection.
- **Perspectives,** drawn from this list. Each is deliberately tighter than a generic "find problems" framing — most define their own do-not-raise filter.
  - **Reduction tightness** — advantage terms, concrete bounds, factor-of-2 or log-factor losses, missing terms, asymptotic-vs-concrete confusion.
  - **Bound assembly** — walk every summand of the headline corollary back to its source in the per-game proofs and supporting lemmas. Catches dropped terms, lost factors of 2, hypotheses tightened in transit, mismatched supremum ranges. Most load-bearing issues live here.
  - **Citation accuracy** — every invocation of an external result (`\cite{BDPV11}` Thm 3, `\cite{BH22}` Lemma 4, etc.) must match what the cited paper actually states. Citation keys are resolved through `paper/refs.bib`; full PDFs live in `./refs/`. Verify hypotheses, bounds, and notational conventions against the source PDF.
  - **Load-bearing drift** — drift in a symbol, game, or oracle counts only if (i) it changes which adversary class a theorem quantifies over, (ii) a downstream proof substitutes one meaning where the other was defined, or (iii) it silently changes the value of a bound term. Pure naming inconsistency, label/synonym mismatches, and "symbol X used in §N not formally bound until §M" do *not* qualify.
  - **Attack synthesis** — for any apparent gap, missing case, or hand-waved step, sketch an adversary strategy that exploits the gap. If you cannot sketch one, do not raise it. Edge cases (empty messages, single-block, exactly at a rate boundary) only count if they enable an attack the headline theorem rules out.
  - **Interface audit** — pick a small set of lemma or section pairs that call each other (e.g. L7→L5, §6→§3, headline corollary→main reduction). Audit only the call sites: do the invoked hypotheses match what the callee actually requires? Are resource caps quantified compatibly? Are output-quantification ranges aligned?
  - **Copyedit and notation** — typos, a symbol used before it is defined, notation that is inconsistent between two locations (e.g. $\tauroot$ in one place and $\tau_{\mathrm{root}}$ in another), a broken or missing cross-reference, a definition stated two incompatible ways, a displayed equation whose intermediate step is arithmetically off even when the conclusion holds. Quote both locations when the issue is an inconsistency. Do *not* raise pure style preferences (spelling variant, comma placement, "we" vs. passive voice) or anything for which you cannot point to a specific incorrect token. This perspective is most useful on polish passes whose goal is the smaller stuff; it can fire on any section, and especially on dense-notation ones.

Match perspectives to section type rather than running every perspective everywhere:

- Definition sections (interfaces, games, resources — `02-preliminaries`, `03-tw128`, `04-security-model`): load-bearing drift, interface audit.
- Headline-corollary sections (`05-main-results`): bound assembly, reduction tightness.
- Main reductions (`06-privacy`, `07-authenticity`, `08-cmtds3`): reduction tightness, attack synthesis, interface audit.
- Sections that invoke external results: citation accuracy, bound assembly.
- Supporting-lemma blocks (`appendix-lemmas`, `appendix-flat-sponge-lift`, `appendix-committing-transfer`): interface audit, attack synthesis.
- Polish passes hunting the smaller stuff: add copyedit and notation to any section, and let citation accuracy back onto sections that invoke external results.

Not every section needs every applicable perspective — pick combinations where the perspective could plausibly fire. Target **4–8 reviewer cells** overall (the sharper perspectives mean fewer cells per section are needed).

**Signal-history routing.** If a prior `review.tmp.md` exists in the repo root, read it before building the grid. For each (section, perspective) combination that produced zero surviving findings in the prior run, downweight or skip it; a cell that surfaced even a cosmetic finding last round is worth re-running, both to confirm the fix landed and to catch adjacent issues. Reviewers reliably overproduce on perspectives where the proof has already been polished; reusing signal history is the cheap way to keep volume manageable across iterations. Bound assembly and interface audit, by contrast, get *more* valuable with each polish round and should be re-run. On a smaller-stuff pass the copyedit-prone perspectives (copyedit and notation, citation accuracy) also regain value and should not be permanently skipped just because earlier major-issue rounds found nothing there.

Print the chosen grid in one short message before fanning out. Format: `Reviewing <target> with N reviewers: [Section A x bound assembly, Section A x citation accuracy, Section B x interface audit, ...].`

## Step 2 — Fan out reviewers in parallel

Spawn one Agent per cell with `subagent_type: general-purpose`. Use a single message with all calls so they run concurrently.

Each reviewer prompt must:

1. Name the target section file (e.g. `paper/sections/06-privacy.tex`), the specific section/subsection, and its line range. Tell them the manuscript is multi-file LaTeX rooted at `paper/main.tex`, and that they may read sibling section files when a claim under review references one (but their findings must live in the assigned file).
2. Name the perspective and the failure modes to look for (paste the relevant bullet from the perspective list, tailored to the section). Include the perspective's own do-not-raise filter — most perspectives have one (e.g. attack synthesis requires a sketched attack; load-bearing drift excludes pure naming inconsistency).
3. Grant access to `./refs/` for citation checks and to `paper/refs.bib` for resolving `\cite{}` keys. Tell them full PDFs of all referenced works live in `./refs/` and that BibTeX keys map to filenames via `paper/refs.bib`.
4. Include the **calibration prompt** verbatim:

   > You are reviewing a paper that has already passed several rounds of review clean on its major issues; the goal of this pass is to surface the *smaller* stuff. Raise anything you can specifically point to that is genuinely true — down to the copyeditor level: a notational inconsistency, an imprecise phrasing, an arithmetic slip in a displayed step, a hypothesis the reader could infer but shouldn't have to, a missing forward reference. Each finding must quote real text and state a concrete, true problem. Do NOT invent findings to fill a quota, and do NOT raise something you only suspect or a mere style preference. NO FINDINGS is still legitimate for a cell that is genuinely clean — padding with non-issues produces noise, not signal.

5. Demand the finding schema below verbatim. **Problems only — no "confirmed valid" findings, no suggested fixes, no praise, no commentary.**
6. Tell them: if they find nothing in their cell, return exactly the line `NO FINDINGS` and stop.

The calibration prompt is load-bearing — it sets the floor at copyedit level (so the smaller stuff surfaces) while still forbidding fabricated, merely-suspected, or pure-style findings, so volume rises without the noise floor ballooning. Do not paraphrase it away when tailoring the per-cell prompt.

### Finding schema (reviewers MUST follow this)

```
### F<n>. <one-line problem statement>

**Location:** <file>:<line> (and any related lines; file path relative to repo root, e.g. paper/sections/06-privacy.tex)
**Perspective:** <perspective name>
**Quoted passage:** "<exact text from the file — LaTeX source verbatim, including macros and math markup>"
**Claim:** <what the document is asserting at that point, in your words>
**Problem:** <why the claim is wrong, unsupported, or imprecise — be specific>
**Reference check (if applicable):** <BibTeX key from paper/refs.bib, the ./refs/ PDF it points to, what it actually says, where>
```

Reviewers number locally (F1, F2, …); the orchestrator renumbers globally during aggregation.

## Step 3 — Aggregate raw findings

Collect every reviewer's output. Dedupe near-identical findings (same quoted passage and same problem) — keep the more specific one. If two reviewers raised overlapping but distinct issues at the same location, keep both. Renumber globally as F1…FN.

Do not write anything to disk yet. Hold the aggregated list in memory for Step 4, where it gets grouped by file location before validation.

## Step 4 — Validate, one validator per file group, in parallel

Group the aggregated findings by their cited file location (the file in each finding's `Location:` field). Split any group larger than 5 findings into batches of at most 5 (e.g. 8 findings in one file → two batches of 4). For each group, spawn one Agent with `subagent_type: general-purpose` and `model: sonnet`. Use a single message with all calls so they run concurrently.

**A validator gets ONLY the findings in its group — no other groups, no reviewer reasoning beyond the schema, no grid context.** Within a group, each finding must still be judged independently: verdict on one finding must not influence the verdict on another. Isolation across groups plus independence within a group is what makes "treat as a claim, not a fact" actually bite.

Each validator prompt must:

1. Quote every finding in the group verbatim — the whole F<n> block for each, nothing else.
2. Open with: "Treat each of these as an independent *claim*, not a fact. Your job is to determine whether each claim holds, on its own merits. Reviewers in the first pass have a high false-positive rate; be willing to refute. Judging one claim in this batch must not color your judgment of another — evaluate each from scratch."
3. Grant access to the manuscript (`paper/`, especially the cited section file), `paper/refs.bib`, and `./refs/`.
4. Require them to apply, per finding, in order:
   - **Quote check.** Verify the quoted passage exists at the cited location, **exactly as quoted** (LaTeX source matched verbatim — do not normalize macros or whitespace). If paraphrased, misquoted, or at a different line: **REFUTED**.
   - **Context check.** Verify the claimed problem actually follows from the text. If the reviewer misread the surrounding context: **REFUTED**.
   - **Reference check.** Verify any reference claim by resolving the BibTeX key through `paper/refs.bib` and reading the corresponding `./refs/` PDF at the cited location. If the external result supports the document's use of it: **REFUTED**.
   - **Severity gate.** If the claim survives the three checks above, the finding is true; now classify its impact. Ask: *what concrete bound, theorem statement, game definition, or adversary strategy changes if this finding is true and unfixed?* If a concrete consequence exists, the verdict is **CONFIRMED** (or **PARTIAL** with a corrected problem statement). If the answer is "nothing concrete — the reader can repair it locally, no bound moves, no theorem statement is invalidated, no proof step relies on it," the verdict is **COSMETIC**: the finding is true and its only cost is polish. COSMETIC is a *surfaced* verdict — this pass is hunting exactly these smaller findings, so it is kept and filed under the Cosmetic severity in Step 5, not dropped. Only REFUTED is discarded.
5. Forbid them from raising *additional* problems. They validate only the claims in their group.
6. Require one verdict block per finding in the group, in the same order, each tagged with its F<n>.

### Validator return format

One block per finding in the group:

```
F<n>
Verdict: CONFIRMED | REFUTED | PARTIAL | COSMETIC
Reasoning: <one short paragraph citing what was verified — quote the document and any reference if relevant>
Corrected problem (PARTIAL only): <revised problem statement>
Concrete impact (CONFIRMED or PARTIAL): <which bound, theorem, game definition, or adversary strategy changes if unfixed — one sentence>
Polish note (COSMETIC only): <what the local fix is — one sentence>
```

## Step 5 — Triage and write the report

Drop only REFUTED. For CONFIRMED, PARTIAL, and COSMETIC, assign a severity using the validator's stated impact:

- **Blocking** — the proof does not establish what it claims: a wrong or missing bound term, a miscited result whose hypotheses are not met, a quantifier mismatch that breaks the supremum, an undefined resource that appears in a headline.
- **Major** — the argument is sound in spirit but imprecise: missing case the reader could supply, citation hypothesis quietly elided, drift that downstream code substitutes through, an interface call site that requires reading the callee's proof to repair.
- **Minor** — true and worth fixing, but the reader's repair is mechanical and the bound/theorem stays exactly the same.
- **Cosmetic** — true, but its only cost is polish: a typo, a notational inconsistency, awkward phrasing, an off-by-a-term displayed step whose conclusion still holds, a missing-but-inferable forward reference. These are the findings the validator gated as COSMETIC. Earlier major-issue rounds dropped them; this pass surfaces them so they can be cleaned up.

Every surviving verdict is a true, specifically-located finding — the validation pass refuted the rest — so all four severities warrant the author's attention. The split is about scope of fix, not about whether to fix.

Write the final report to `./review.tmp.md`, overwriting any prior contents:

```
# Adversarial Review of <target> — Findings

_<N> findings (<b> blocking, <m> major, <n> minor, <c> cosmetic) surfaced out of <T> raised._

## Blocking

### 1. <title>

**Location:** ...
**Problem:** ...
**Concrete impact:** <one-sentence: which bound, theorem, game, or attack changes if unfixed; for a Cosmetic finding, what the local polish fix is>
**Evidence:** <quoted passage, plus reference check if any>

[repeat per finding, then `## Major`, then `## Minor`, then `## Cosmetic`]
```

Omit any severity section that has no findings. Do not include refuted findings, suggested fixes, praise, or "looks good" commentary.

## Gitignore

`review.tmp.md` is a working artifact. On the first run in a repo, check `.gitignore`; if `*.tmp.md` is not listed, append it.

## Operating notes

- Keep your own user-facing chatter to a minimum: announce the grid (Step 1), confirm the aggregate count after Step 3 (`Aggregated <T> raw findings, validating in <G> groups…`), and announce the final counts after writing `review.tmp.md`. Nothing else.
- Reviewers and validator groups are independent — never let a validator see findings or verdicts from another group. Within a group, findings are judged independently of each other; a validator's job is to avoid cross-contaminating verdicts within its own batch, not just across groups.
- If a reviewer returns malformed output (missing schema fields), do not retry — drop the malformed entries from the aggregate. The validator pass will catch missing schema fields anyway by failing to find the quoted passage.
- **Cost tuning.** Validators run on `model: sonnet` rather than inheriting the session model — their task (verify a quote against source, check context, check a reference PDF, classify impact) is closer to structured verification-against-ground-truth than the open-ended synthesis reviewers do, which is a better fit for a lighter model. Reviewers deliberately keep no model override: they inherit whatever model the session is running, since reviewer output quality is harder to backstop once findings are dropped from the pool entirely — a well-tuned reviewer pass can run high-precision (few spurious findings per run), so there's less slack to spend on a lighter model there than the skill's generic false-positive framing above might suggest. If a run's verdicts look off — too lenient, too harsh, or COSMETIC/REFUTED rates drift from what past sessions produced — revert the validator model override first before touching anything else; it's the single knob most likely to explain a quality regression.
- **Two prompts are load-bearing and must be passed through verbatim.** The reviewer calibration prompt in Step 2 and the severity gate in Step 4 are what keep the review *trustworthy* — every surfaced finding is true and specifically located, with no fabricated, merely-suspected, or pure-style noise. The current policy deliberately *surfaces* COSMETIC findings rather than dropping them: the proof has passed several rounds clean on its major issues, so this pass hunts the smaller stuff. Convergence across rounds is maintained by signal-history routing and dedup, not by discarding true findings. If a future round wants to raise the floor back to major-only, do it by an explicit policy change — restore the older calibration that excluded copyedit-level findings and have the severity gate drop COSMETIC again — not by quietly paraphrasing these prompts.
- The grid is intentionally smaller than it used to be (4–8 cells, not 6–12). Sharper perspectives plus signal-history routing replaces broadcast coverage. A run with two reviewers returning NO FINDINGS is a healthy outcome, not under-coverage — it means the proof has been polished where those perspectives bite.
