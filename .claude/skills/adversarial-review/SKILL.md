---
name: adversarial-review
description: Run a multi-perspective adversarial review of the LaTeX paper manuscript in ./paper/ (or a specific section file within it). Fans out reviewers across a section x perspective grid in parallel, independently validates each raised finding with isolated subagents, and writes triaged surviving findings to review.tmp.md at the repo root.
---

# Adversarial review

Use when the user asks to "review" or "adversarially review" the paper manuscript in `./paper/`, or a specific section/appendix within it. The skill runs two parallel waves of subagents — reviewers (claim generators) then validators (claim checkers) — inside a background `Workflow` (`.claude/workflows/adversarial-review.js`), and writes the surviving findings to `./review.tmp.md`. Running the fan-out as a workflow keeps intermediate reviewer output, aggregation, and validator verdicts out of the calling session's transcript — only the final report and counts return. Reviewers still raise the occasional false positive; the validator pass is what makes the report trustworthy regardless of how clean any given reviewer run is.

## Caller signature

`/adversarial-review [target]` — `<target>` is optional. It can be:

- omitted — review the full manuscript (`paper/main.tex` plus its `\input`-ed section and appendix files);
- a section file path (`paper/sections/04-security-model.tex`);
- a section keyword that maps to a file (`appendix-lemmas`, etc.).

If the user names a section that doesn't map cleanly to a file, ask which one they mean before fanning out.

## Step 1 — Build the section x perspective grid

Read `paper/main.tex` for the manuscript's structure (which section/appendix files are `\input`-ed and in what order) and skim the candidate section files. Then pick:

- **Sections (3–6).**
  - For a full-manuscript run, pick from the proof-bearing files in `paper/sections/` — definitions (`02-preliminaries`, `03-tw128`, `04-security-model`), the security analyses (`05-authenticated-encryption-security` for AE/INT-RUP, `06-root-tag-hash-security-committing-security` for hash and committing security), the concrete security summary (`07-concrete-security-summary`), and the technical appendices (`appendix-lemmas`, `appendix-flat-sponge-lift`). Skip pure-exposition files (introduction, performance, discussion, conclusion) and the non-proof appendices (`appendix-kernels`, `appendix-test-vectors`) unless the user asks otherwise.
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
- Security-analysis sections (the AE/INT-RUP reductions in `05-authenticated-encryption-security` and the hash and committing analysis in `06-root-tag-hash-security-committing-security`): reduction tightness, attack synthesis, interface audit.
- Concrete security summary (`07-concrete-security-summary`, where the concrete security claim corollary assembles the per-game bounds): bound assembly, reduction tightness.
- Sections that invoke external results: citation accuracy, bound assembly.
- Supporting-lemma blocks (`appendix-lemmas`, `appendix-flat-sponge-lift`): interface audit, attack synthesis.
- Polish passes hunting the smaller stuff: add copyedit and notation to any section, and let citation accuracy back onto sections that invoke external results.

Not every section needs every applicable perspective — pick combinations where the perspective could plausibly fire. Target **4–8 reviewer cells** overall (the sharper perspectives mean fewer cells per section are needed).

**Signal-history routing.** If a prior `review.tmp.md` exists in the repo root, read it before building the grid. For each (section, perspective) combination that produced zero surviving findings in the prior run, downweight or skip it; a cell that surfaced even a cosmetic finding last round is worth re-running, both to confirm the fix landed and to catch adjacent issues. Reviewers reliably overproduce on perspectives where the proof has already been polished; reusing signal history is the cheap way to keep volume manageable across iterations. Bound assembly and interface audit, by contrast, get *more* valuable with each polish round and should be re-run. On a smaller-stuff pass the copyedit-prone perspectives (copyedit and notation, citation accuracy) also regain value and should not be permanently skipped just because earlier major-issue rounds found nothing there.

Represent the chosen grid as an array of cell objects, one per (section, perspective) combination:

```json
{
  "id": "07-concrete:bound-assembly",
  "file": "paper/sections/07-concrete-security-summary.tex",
  "sectionLabel": "§7.1–7.2 Concrete TW128 Bounds and Concrete Security Claim corollary",
  "lineStart": 10,
  "lineEnd": 201,
  "perspective": "Bound assembly",
  "siblingFiles": ["paper/sections/05-authenticated-encryption-security.tex", "paper/sections/06-root-tag-hash-security-committing-security.tex"]
}
```

`perspective` must exactly match one of the seven names defined in `.claude/workflows/adversarial-review.js` (`Reduction tightness`, `Bound assembly`, `Citation accuracy`, `Load-bearing drift`, `Attack synthesis`, `Interface audit`, `Copyedit and notation`) — the workflow script owns the verbatim failure-mode text and do-not-raise filter for each, looked up by this name. `siblingFiles` is optional: list other section files a reviewer may read for cross-reference context; their findings must still be located in `file`.

Print the chosen grid in one short message before fanning out. Format: `Reviewing <target> with N reviewers: [Section A x bound assembly, Section A x citation accuracy, Section B x interface audit, ...].`

## Step 2 — Run the review workflow

Invoke the workflow with the grid built in Step 1, using `scriptPath` (not `name`) so a same-session edit to the script is always picked up rather than replaying a stale cached copy from an earlier invocation:

```
Workflow({ scriptPath: '.claude/workflows/adversarial-review.js', args: { target: '<target>', grid: [...], reviewerModel: undefined } })
```

- `target` — the human-readable target string for the report title (e.g. `full manuscript`, `paper/sections/06-root-tag-hash-security-committing-security.tex`).
- `grid` — the array of cells from Step 1.
- `reviewerModel` — optional. Omit to let reviewers inherit the session model (default policy — reviewer strength should scale with whatever model the session is running). Pass `'sonnet'` (or another model id) only when deliberately pinning reviewers to a specific model for a given run.

The workflow runs reviewers in parallel, aggregates and dedupes their findings, validates them in isolated per-file groups (always on `model: sonnet`, per the same cost-tuning rationale as before), and triages the survivors into Blocking/Major/Minor/Cosmetic. It returns `{ report, counts }`, where `report` is the fully-formatted markdown report and `counts` is `{ total, blocking, major, minor, cosmetic }`.

None of the intermediate reviewer output, aggregation, or validator verdicts enter this session's context — only the final `{ report, counts }` does.

## Step 3 — Write the report

Write `report` to `./review.tmp.md` at the repo root, overwriting any prior contents. Announce the final counts from `counts` — nothing else.

## Operating notes

- Keep your own user-facing chatter to a minimum: announce the grid (Step 1) and the final counts after writing `review.tmp.md` (Step 3). Nothing else — the workflow itself narrates reviewer/aggregate/validate/triage progress via its own `log()` calls, visible through `/workflows`.
- Isolation across reviewer cells and validator groups is enforced structurally by the workflow: each `agent()` call only receives its own cell's or group's data in its prompt, never another cell's reasoning or another group's findings. Within a validator group, findings are still judged independently of each other — the validator prompt says so explicitly.
- **Cost tuning.** Validators are hardcoded to `model: sonnet` inside the workflow script rather than inheriting the session model — their task (verify a quote against source, check context, check a reference PDF, classify impact) is closer to structured verification-against-ground-truth than the open-ended synthesis reviewers do, which is a better fit for a lighter model. Reviewers default to inheriting the session model (the `reviewerModel` arg left unset) — reviewer output quality is harder to backstop once findings are dropped from the pool entirely, so there's less slack to spend on a lighter model there than the skill's generic false-positive framing above might suggest. Pass `reviewerModel` explicitly only when deliberately trading reviewer strength for cost on a specific run. If a run's verdicts look off — too lenient, too harsh, or COSMETIC/REFUTED rates drift from what past sessions produced — check the validator model in `.claude/workflows/adversarial-review.js` first before touching anything else; it's the single knob most likely to explain a quality regression.
- **Load-bearing prompt text lives in the workflow script, not here.** `CALIBRATION_PROMPT` and `VALIDATOR_CHECKS` (the severity gate) in `.claude/workflows/adversarial-review.js` are what keep the review *trustworthy* — every surfaced finding is true and specifically located, with no fabricated, merely-suspected, or pure-style noise. The current policy deliberately *surfaces* COSMETIC findings rather than dropping them: the proof has passed several rounds clean on its major issues, so this pass hunts the smaller stuff. Convergence across rounds is maintained by signal-history routing (Step 1) and the workflow's own dedup step, not by discarding true findings. If a future round wants to raise the floor back to major-only, do it by an explicit policy change to those two constants — not by quietly paraphrasing them.
- The grid is intentionally smaller than it used to be (4–8 cells, not 6–12). Sharper perspectives plus signal-history routing replaces broadcast coverage. A run with two reviewers returning no findings is a healthy outcome, not under-coverage — it means the proof has been polished where those perspectives bite.
