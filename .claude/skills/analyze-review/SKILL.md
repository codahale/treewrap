---
name: analyze-review
description: Triage and resolve an adversarial review. Reads a review report file (default ./review.tmp.md, or a caller-supplied path), clusters findings by underlying cause, distinguishes design clusters from mechanical fixes, and walks the user through clusters one at a time. For each cluster, produces a plan via plan mode and then executes it before returning to the menu.
---

# Analyze review

Use after `/adversarial-review` has written a report file. The skill turns the punch list into a series of design decisions and a final mechanical cleanup. For each cluster, it produces a plan via plan mode and then executes it before returning to the menu.

## Caller signature

`/analyze-review [report-path]`

- `<report-path>` is the review report file to read. Optional; defaults to `./review.tmp.md`. Use the path passed to `/adversarial-review` if the user ran multiple reviews in parallel.

Throughout this skill, "the report file" means `<report-path>` (or `./review.tmp.md` if unspecified).

## Preconditions

- The report file exists and contains findings. If missing, tell the user to run `/adversarial-review <target> [output-path]` first and stop.
- If the report file exists but reports zero findings, say so and stop.

## Step 1 — Cluster the findings

Spawn one Agent (`subagent_type: general-purpose`) with this brief:

- Read the report file and the manuscript it references (named in the report title — typically `paper/` as a whole, or a specific `paper/sections/<file>.tex`). Read `paper/main.tex` first to understand which section files exist and how they fit together.
- Group findings by **underlying cause**, not by surface symptom. Two findings that both stem from, say, "L7 quietly assumes nonce-respecting queries" belong in one cluster even if they surface in different section files.
- For each cluster, return:
  - `name`: short kebab-case label (e.g. `l7-nonce-hypothesis`).
  - `root_cause`: one sentence describing the underlying issue.
  - `findings`: list of finding numbers from the report.
  - `severity_counts`: object `{blocking: <n>, major: <n>, minor: <n>, cosmetic: <n>}` tallying the cluster's findings by the report's severity headers. Used for menu display and ordering.
  - `kind`: `design` (resolution requires a judgment call about what the proof should say) or `mechanical` (typo, arithmetic slip, wrong citation, missing forward reference, notation inconsistency with an obvious right answer — including LaTeX-level fixes like a wrong `\cite{}` key or a missing `\label`).
  - `affected_scope`: which section files / lemmas / appendices of the manuscript are touched (use paths under `paper/sections/`).
  - `depends_on`: array of cluster `name`s whose resolution would plausibly shift this cluster's findings (e.g. fixing a resource-definition cluster may close downstream interface-mismatch findings). Empty array if no clear dependency. Be conservative — only list dependencies that materially change the right answer here.
- Mechanical findings should be lumped into a single `mechanical-cleanup` cluster unless they live in genuinely unrelated parts of the manuscript.
- Return a JSON array, nothing outside the JSON.

If the JSON is malformed, retry once with a stricter prompt; if it fails again, do the clustering inline from the review file.

## Step 2 — Present the menu

Print the clusters as a numbered list. Render each cluster's `severity_counts` as a compact tag using `B` for blocking, `M` for major, `m` for minor, `c` for cosmetic (e.g. `1B + 2M + 1m + 3c`, omit zero counts). If a cluster has a non-empty `depends_on`, show it under the cluster on a continuation line.

Substitute the report-file path in the heading:

```
Clusters from <N> findings in <report-path>:

  1. <name> [design, 1B + 2M]     — <root_cause>
  2. <name> [design, 3m]          — <root_cause>
     ↳ tackle after <other-name> if possible
  ...
  K. mechanical-cleanup [3m + 5c] — typos, citations, notation, polish

Verbs: <number> to tackle, "defer <number>" to skip for this round,
       "merge <a>,<b>" / "split <n>" to re-cluster, "done" to stop.
```

Order clusters by severity within their kind: design clusters first (sorted by blocking count, then major, then minor, then cosmetic, descending), then mechanical-cleanup. Within ties, respect `depends_on` — dependencies appear before dependents.

Then ask: `Which cluster would you like to tackle next?` Wait for the user's reply and interpret it according to the verbs above:

- A bare number → resolve that cluster (Step 3).
- `defer <number>` → move that cluster to the end of the queue; do not present again this round unless the user runs out of other choices. Reprint the menu.
- `merge <a>,<b>` → combine the two clusters' findings, regenerate a single `name`/`root_cause`/`severity_counts`/`kind`/`affected_scope` (kind is `design` if either input was design), and reprint the menu. The new cluster's `depends_on` is the union minus the merged-in names.
- `split <n>` → re-spawn the Step 1 agent on just cluster `n`'s findings with instructions to produce 2+ sub-clusters; reprint the menu with the split applied.
- `done` → Step 4 (summary and stop).

If only `mechanical-cleanup` remains, nudge: `Only mechanical-cleanup left — wrap up?`

## Step 3 — Resolve the chosen cluster

### If the user picks a `design` cluster

1. Spawn one Agent (`subagent_type: general-purpose`) with:
   - The cluster's name, root cause, affected scope, and the **full F<n> blocks** of its findings (copy them verbatim from the report file).
   - Access to the manuscript (`paper/`, especially the files listed in `affected_scope`), `paper/refs.bib`, and `./refs/`.
   - Task: propose **2–3 candidate proof modifications** that would resolve the cluster, plus one **leave-as-is** candidate. For each candidate, give:
     - a short name (≤6 words),
     - what changes in the proof (≤150 words),
     - the tradeoff against the other candidates.
   - **Candidate calibration.** Candidates must differ in *what the proof says*, not just *how it says it*. Two candidates that produce the same theorem statements with reshuffled prose are not two candidates — they are one. If you cannot come up with two substantively different modifications, return only one plus the leave-as-is option.
   - **The leave-as-is candidate** is always present. Name it `leave-as-is` and describe what is acknowledged but not changed (and why that might be the right call — e.g. fix would muddle the proof, finding is true but cosmetic in practice, finding is already covered by adjacent text the reader will find). This is a legitimate decision, not a cop-out.
   - **Recommendation.** After laying out the candidates, mark exactly one as `recommended: true`. Recommend the candidate that **makes the proof stronger** — strengthens a bound, removes a hypothesis, or closes a real gap. Tiebreaker 1: simplicity (fewer moving parts, smaller surface area, simpler bound expressions, fewer new lemmas). Tiebreaker 2: legibility (clearer prose, fewer cross-references, easier-to-follow proof flow). If no candidate strengthens the proof and the leave-as-is option is clearly defensible, recommend leave-as-is. Briefly justify the recommendation in one sentence.
   - Favor changes that **simplify or strengthen** the proof over changes that just patch the immediate finding.
   - No fixes, no edits, no plans. Candidates only.
2. Present the candidates to the user via `AskUserQuestion`. Put the recommended candidate first with `(Recommended)` appended to its label. The user picks one (or types "Other" to redirect).
3. If the user picks **leave-as-is**, do not enter plan mode. Instead, ask: `Record this disposition? (y/n, or supply a one-line rationale to include in a commit.)` If they assent, make an empty commit (`git commit --allow-empty`) whose message names the cluster and records the leave-as-is decision and rationale. This puts the dispositioning decision in git history so future review rounds have context. Print `Recorded leave-as-is for <cluster>. Returning to cluster menu.` and go back to Step 2.
4. Otherwise, enter plan mode (`EnterPlanMode`) and write the plan for the chosen candidate. The plan should specify:
   - which section files / lemmas / appendices under `paper/sections/` to modify,
   - what to add, remove, or rephrase (at the level of "split L7 into L7a and L7b" or "drop the K-independence claim and replace it with a marginal-distribution argument in `paper/sections/06-privacy.tex`"),
   - which `./refs/` results are newly invoked or stop being invoked (and any `paper/refs.bib` entries that need adding or removing),
   - which review findings (F<n>) the plan closes.
5. **Discarding during planning.** If planning reveals the cluster's findings don't actually need addressing (e.g. an earlier cluster's commit already closed them, or careful re-reading shows the finding was misread), exit plan mode and tell the user: `Cluster <name> appears to be already closed / non-actionable because <reason>. Discard? (y/n)`. If yes, treat as resolved without a commit and return to Step 2.
6. When the user approves the plan via `ExitPlanMode`, execute it in this turn — make the edits the plan describes. Trust the plan; do not re-run review machinery to confirm findings are closed. When the edits are done:
   - Print a one-line close-out: `Edits addressed F<a>, F<b>; F<c> already closed by an earlier commit; F<d> deferred to <cluster-name>.` Surface anything the executor noticed (already-closed findings, shifted plans) so later clusters benefit from the context.
   - Ask the user: `Commit these changes? (y/n, or supply a message)`. If they assent, create one commit for this cluster. **Commit message: describe the change in its own terms** (what the proof now says vs. before); name the cluster and the chosen candidate; do NOT cite F<n> numbers (they live in `review.tmp.md` which is gitignored, so the references rot). If the user supplies a message, use it as-is.
   - Print `Executed plan for <cluster>. Returning to cluster menu.` and go back to Step 2 with the resolved cluster removed.

### If the user picks the `mechanical-cleanup` cluster

1. Skip candidate brainstorming.
2. Enter plan mode directly. Write a batched plan: an ordered list of mechanical fixes, each with location (file path under `paper/sections/` plus line) and the exact change. Group by file.
3. When approved, execute the plan in this turn. Print a one-line close-out (same format as design clusters). Then ask the user: `Commit these changes? (y/n, or supply a message)`. If they assent, create one commit for the cleanup. Same commit-message rule: describe the changes in their own terms, do not cite F<n> numbers. Print `Executed mechanical-cleanup.` and return to the menu (or end if nothing remains).

### If the user replies `done`

Print a one-line summary: `Resolved <R> clusters; left-as-is <L>; deferred <D>.` End.

## Operating notes

- Plan and execute serially: each approved plan is executed in the same turn before returning to the menu. Findings closed by a prior cluster's execution may already be addressed when later clusters are tackled — that is expected and does not require re-running the review. The post-execution close-out line is where you surface this.
- One cluster at a time. Do not pre-spawn candidate brainstorming for clusters the user has not picked.
- Plans are not written to disk — they live in the conversation. If the user wants persistent plans, they will ask; do not preemptively save them.
- **Leave-as-is is a real outcome.** The brainstormer always offers it, the user is free to pick it, and picking it records a deliberate disposition in git history via an empty commit. This is not failure; it is the correct way to close out true-but-not-worth-fixing findings.
- **The recommendation is a hint, not a default.** The brainstormer marks one candidate as `recommended`, but the user picks. Do not auto-select the recommendation. Surface it via the `(Recommended)` label in the AskUserQuestion options and let the user decide.
- Keep your own user-facing text minimal. The cluster menu, the candidate question, the plans, and the per-cluster close-out line are the artifacts the user needs to see — nothing else.
