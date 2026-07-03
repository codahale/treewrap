export const meta = {
  name: 'adversarial-review',
  description: 'Reviewer fan-out, aggregation, validator fan-out, and triage for the adversarial-review skill',
  whenToUse: 'Called by the adversarial-review skill after it has built the section x perspective grid (Step 1). Keeps reviewer/validator/triage output out of the calling session\'s transcript — only the final report and counts return.',
  phases: [
    { title: 'Review' },
    { title: 'Aggregate' },
    { title: 'Validate', detail: 'sonnet, isolated per file group' },
    { title: 'Triage' },
  ],
}

// Perspective bullets, reproduced verbatim from .claude/skills/adversarial-review/SKILL.md Step 1.
// Grid cells reference these by name; keeping the text here (not in the caller) is the single
// source of truth for what each perspective is instructed to look for and its do-not-raise filter.
const PERSPECTIVES = {
  'Reduction tightness': {
    failureModes: 'Look for: advantage terms, concrete bounds, factor-of-2 or log-factor losses, missing terms, asymptotic-vs-concrete confusion.',
  },
  'Bound assembly': {
    failureModes: 'Walk every summand of the headline corollary back to its source in the per-game proofs and supporting lemmas. Catches dropped terms, lost factors of 2, hypotheses tightened in transit, mismatched supremum ranges. Most load-bearing issues live here.',
  },
  'Citation accuracy': {
    failureModes: 'Every invocation of an external result (\\cite{BDPV11} Thm 3, \\cite{BH22} Lemma 4, etc.) must match what the cited paper actually states. Citation keys are resolved through paper/refs.bib; full PDFs live in ./refs/. Verify hypotheses, bounds, and notational conventions against the source PDF.',
  },
  'Load-bearing drift': {
    failureModes: 'Drift in a symbol, game, or oracle counts only if (i) it changes which adversary class a theorem quantifies over, (ii) a downstream proof substitutes one meaning where the other was defined, or (iii) it silently changes the value of a bound term. Pure naming inconsistency, label/synonym mismatches, and "symbol X used in one place not formally bound until another" do NOT qualify — do not raise these.',
  },
  'Attack synthesis': {
    failureModes: 'For any apparent gap, missing case, or hand-waved step, sketch an adversary strategy that exploits the gap. If you cannot sketch one, do not raise it. Edge cases (empty messages, single-block, exactly at a rate boundary) only count if they enable an attack the headline theorem rules out.',
  },
  'Interface audit': {
    failureModes: 'Pick a small set of lemma or section pairs that call each other (e.g. L7→L5, §6→§3, headline corollary→main reduction). Audit only the call sites: do the invoked hypotheses match what the callee actually requires? Are resource caps quantified compatibly? Are output-quantification ranges aligned?',
  },
  'Copyedit and notation': {
    failureModes: 'Typos, a symbol used before it is defined, notation that is inconsistent between two locations (e.g. $\\tauroot$ in one place and $\\tau_{\\mathrm{root}}$ in another), a broken or missing cross-reference, a definition stated two incompatible ways, a displayed equation whose intermediate step is arithmetically off even when the conclusion holds. Quote both locations when the issue is an inconsistency. Do NOT raise pure style preferences (spelling variant, comma placement, "we" vs. passive voice) or anything for which you cannot point to a specific incorrect token.',
  },
}

const CALIBRATION_PROMPT = `You are reviewing a paper that has already passed several rounds of review clean on its major issues; the goal of this pass is to surface the *smaller* stuff. Raise anything you can specifically point to that is genuinely true — down to the copyeditor level: a notational inconsistency, an imprecise phrasing, an arithmetic slip in a displayed step, a hypothesis the reader could infer but shouldn't have to, a missing forward reference. Each finding must quote real text and state a concrete, true problem. Do NOT invent findings to fill a quota, and do NOT raise something you only suspect or a mere style preference. NO FINDINGS is still legitimate for a cell that is genuinely clean — padding with non-issues produces noise, not signal.`

const VALIDATOR_OPENING = `Treat each of these as an independent *claim*, not a fact. Your job is to determine whether each claim holds, on its own merits. Reviewers in the first pass have a high false-positive rate; be willing to refute. Judging one claim in this batch must not color your judgment of another — evaluate each from scratch.`

const VALIDATOR_CHECKS = `1. Quote check. Verify the quoted passage exists at the cited location, exactly as quoted (LaTeX source matched verbatim — do not normalize macros or whitespace). If paraphrased, misquoted, or at a different line: REFUTED.
2. Context check. Verify the claimed problem actually follows from the text. If the reviewer misread the surrounding context: REFUTED.
3. Reference check. Verify any reference claim by resolving the BibTeX key through paper/refs.bib and reading the corresponding ./refs/ PDF at the cited location. If the external result supports the document's use of it: REFUTED.
4. Severity gate. If the claim survives the three checks above, the finding is true; now classify its impact. Ask: what concrete bound, theorem statement, game definition, or adversary strategy changes if this finding is true and unfixed? If a concrete consequence exists, the verdict is CONFIRMED (or PARTIAL with a corrected problem statement). If the answer is "nothing concrete — the reader can repair it locally, no bound moves, no theorem statement is invalidated, no proof step relies on it," the verdict is COSMETIC: the finding is true and its only cost is polish. Only REFUTED is discarded — CONFIRMED, PARTIAL, and COSMETIC are all kept.`

const SEVERITY_DEFINITIONS = `- Blocking — the proof does not establish what it claims: a wrong or missing bound term, a miscited result whose hypotheses are not met, a quantifier mismatch that breaks the supremum, an undefined resource that appears in a headline.
- Major — the argument is sound in spirit but imprecise: missing case the reader could supply, citation hypothesis quietly elided, drift that downstream code substitutes through, an interface call site that requires reading the callee's proof to repair.
- Minor — true and worth fixing, but the reader's repair is mechanical and the bound/theorem stays exactly the same.`

const FINDING_ITEM_SCHEMA = {
  type: 'object',
  properties: {
    title: { type: 'string' },
    location: { type: 'string' },
    perspective: { type: 'string' },
    quotedPassage: { type: 'string' },
    claim: { type: 'string' },
    problem: { type: 'string' },
    referenceCheck: { type: 'string' },
  },
  required: ['title', 'location', 'perspective', 'quotedPassage', 'claim', 'problem'],
}

const REVIEW_SCHEMA = {
  type: 'object',
  properties: { findings: { type: 'array', items: FINDING_ITEM_SCHEMA } },
  required: ['findings'],
}

const DEDUPE_SCHEMA = {
  type: 'object',
  properties: { findings: { type: 'array', items: FINDING_ITEM_SCHEMA } },
  required: ['findings'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          verdict: { type: 'string', enum: ['CONFIRMED', 'REFUTED', 'PARTIAL', 'COSMETIC'] },
          reasoning: { type: 'string' },
          correctedProblem: { type: 'string' },
          concreteImpact: { type: 'string' },
          polishNote: { type: 'string' },
        },
        required: ['id', 'verdict', 'reasoning'],
      },
    },
  },
  required: ['verdicts'],
}

const TRIAGE_SCHEMA = {
  type: 'object',
  properties: {
    severities: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          severity: { type: 'string', enum: ['blocking', 'major', 'minor'] },
        },
        required: ['id', 'severity'],
      },
    },
  },
  required: ['severities'],
}

function reviewerPrompt(cell) {
  const p = PERSPECTIVES[cell.perspective]
  if (!p) throw new Error(`Unknown perspective: ${cell.perspective}`)
  const siblingNote = cell.siblingFiles && cell.siblingFiles.length
    ? `You may read these sibling section files when a claim under review references them: ${cell.siblingFiles.join(', ')}. Your findings must still be located in ${cell.file}.\n`
    : ''
  return `You are reviewing ${cell.file}, ${cell.sectionLabel} (lines ${cell.lineStart}-${cell.lineEnd}), part of a multi-file LaTeX manuscript rooted at paper/main.tex.
${siblingNote}
Perspective: ${cell.perspective}
${p.failureModes}

Full PDFs of all referenced works live in ./refs/ for citation checks. BibTeX keys are resolved via paper/refs.bib.

${CALIBRATION_PROMPT}

Report problems only — no "confirmed valid" findings, no suggested fixes, no praise, no commentary. For each genuine problem, produce one entry with: a one-line title, the exact location (file:line, plus related lines if any), the perspective name ("${cell.perspective}"), the exact quoted LaTeX source (verbatim, not paraphrased), the claim the document is making in your words, why it's wrong/unsupported/imprecise, and a reference check (BibTeX key, refs/ PDF, what it says, where) if applicable. If you find nothing in your cell, return an empty findings array — do not pad with non-issues.`
}

function dedupePrompt(findings) {
  const block = findings.map((f, i) => JSON.stringify({ n: i + 1, ...f }, null, 2)).join('\n\n')
  return `Below are raw findings from independent reviewer cells covering different sections/perspectives of the same manuscript. Dedupe near-identical findings — same quoted passage and same problem — keeping the more specific one. If two findings raised overlapping but distinct issues at the same location, keep both. Do not alter the content of surviving findings beyond trivial cleanup, do not invent new findings, and do not drop findings that are not near-duplicates of another.

Raw findings:

${block}

Return the deduped list, each finding with the same fields (title, location, perspective, quotedPassage, claim, problem, referenceCheck).`
}

function validatorPrompt(items) {
  const block = items.map(f => JSON.stringify({
    id: f.id,
    title: f.title,
    location: f.location,
    perspective: f.perspective,
    quotedPassage: f.quotedPassage,
    claim: f.claim,
    problem: f.problem,
    referenceCheck: f.referenceCheck || null,
  }, null, 2)).join('\n\n')

  return `${VALIDATOR_OPENING}

You have access to the manuscript (paper/, especially the cited section file(s)), paper/refs.bib, and ./refs/.

Findings to validate (JSON, one per finding — treat each independently):

${block}

Apply these checks, in order, to each finding:

${VALIDATOR_CHECKS}

Do not raise additional problems beyond what's listed above — validate only these claims. Return one verdict per finding, tagged with its id.`
}

function triagePrompt(items) {
  const block = items.map(it => JSON.stringify({
    id: it.id,
    title: it.finding.title,
    location: it.finding.location,
    problem: it.correctedProblem || it.finding.problem,
    concreteImpact: it.concreteImpact,
  }, null, 2)).join('\n\n')

  return `Every finding below has already been validated as true (CONFIRMED or PARTIAL) and carries the validator's stated concrete impact. Assign each one a severity using these definitions:

${SEVERITY_DEFINITIONS}

Findings:

${block}

Return one severity (blocking, major, or minor) per finding id.`
}

function groupByFileBatched(findings, maxSize) {
  const byFile = {}
  findings.forEach(f => {
    const file = (f.location || '').split(/[\s:]/)[0] || 'unknown'
    if (!byFile[file]) byFile[file] = []
    byFile[file].push(f)
  })
  const groups = []
  Object.keys(byFile).forEach(file => {
    const items = byFile[file]
    for (let i = 0; i < items.length; i += maxSize) {
      groups.push({ key: `${file}#${Math.floor(i / maxSize) + 1}`, items: items.slice(i, i + maxSize) })
    }
  })
  return groups
}

function renderReport(target, resolved, totalRaised) {
  const bySeverity = { blocking: [], major: [], minor: [], cosmetic: [] }
  resolved.forEach(r => { if (bySeverity[r.severity]) bySeverity[r.severity].push(r) })

  const section = (label, items) => {
    if (!items.length) return ''
    const body = items.map((r, i) => {
      const problem = r.correctedProblem || r.finding.problem
      const impact = r.concreteImpact || r.polishNote || ''
      const evidence = r.finding.referenceCheck
        ? `"${r.finding.quotedPassage}"\n\nReference check: ${r.finding.referenceCheck}`
        : `"${r.finding.quotedPassage}"`
      return `### ${i + 1}. ${r.finding.title}\n\n**Location:** ${r.finding.location}\n**Problem:** ${problem}\n**Concrete impact:** ${impact}\n**Evidence:** ${evidence}`
    }).join('\n\n')
    return `## ${label}\n\n${body}\n\n`
  }

  const counts = {
    total: resolved.length,
    blocking: bySeverity.blocking.length,
    major: bySeverity.major.length,
    minor: bySeverity.minor.length,
    cosmetic: bySeverity.cosmetic.length,
  }

  const report = (`# Adversarial Review of ${target} — Findings

_${counts.total} findings (${counts.blocking} blocking, ${counts.major} major, ${counts.minor} minor, ${counts.cosmetic} cosmetic) surfaced out of ${totalRaised} raised._

${section('Blocking', bySeverity.blocking)}${section('Major', bySeverity.major)}${section('Minor', bySeverity.minor)}${section('Cosmetic', bySeverity.cosmetic)}`).trim() + '\n'

  return { report, counts }
}

// The harness does not always parse the `args` tool-call value into an object for
// params typed to accept "any" (no declared JSON-schema type) — normalize defensively
// rather than depend on that.
const input = typeof args === 'string' ? JSON.parse(args) : (args || {})

if (!input || !Array.isArray(input.grid) || !input.grid.length) {
  throw new Error('adversarial-review workflow requires args.grid: a non-empty array of {id, file, sectionLabel, lineStart, lineEnd, perspective, siblingFiles?} cells')
}

phase('Review')
const rawResults = await parallel(input.grid.map(cell => () =>
  agent(reviewerPrompt(cell), { label: `review:${cell.id}`, phase: 'Review', schema: REVIEW_SCHEMA, model: input.reviewerModel })
    .then(r => (r && r.findings ? r.findings : []).map(f => ({ ...f, cellId: cell.id })))
))
const allFindings = rawResults.filter(Boolean).flat()
log(`${allFindings.length} raw findings from ${input.grid.length} reviewers`)

if (!allFindings.length) {
  return {
    report: `# Adversarial Review of ${input.target} — Findings\n\n_0 findings surfaced out of 0 raised._\n`,
    counts: { total: 0, blocking: 0, major: 0, minor: 0, cosmetic: 0 },
  }
}

phase('Aggregate')
const dedupeResult = await agent(dedupePrompt(allFindings), { phase: 'Aggregate', schema: DEDUPE_SCHEMA })
const deduped = (dedupeResult && dedupeResult.findings ? dedupeResult.findings : []).map((f, i) => ({ ...f, id: `F${i + 1}` }))
log(`Aggregated ${deduped.length} findings (from ${allFindings.length} raw), validating in groups…`)

phase('Validate')
const groups = groupByFileBatched(deduped, 5)
const verdictResults = await parallel(groups.map(g => () =>
  agent(validatorPrompt(g.items), { label: `validate:${g.key}`, phase: 'Validate', schema: VERDICT_SCHEMA, model: 'sonnet' })
    .then(r => (r && r.verdicts ? r.verdicts : []))
))
const verdicts = verdictResults.filter(Boolean).flat()

const byId = Object.fromEntries(deduped.map(f => [f.id, f]))
const resolved = verdicts
  .filter(v => v.verdict !== 'REFUTED')
  .map(v => ({ ...v, finding: byId[v.id] }))
  .filter(v => v.finding)

phase('Triage')
const toTriage = resolved.filter(v => v.verdict === 'CONFIRMED' || v.verdict === 'PARTIAL')
let severityById = {}
if (toTriage.length) {
  const triageResult = await agent(triagePrompt(toTriage), { phase: 'Triage', schema: TRIAGE_SCHEMA })
  severityById = Object.fromEntries((triageResult && triageResult.severities ? triageResult.severities : []).map(s => [s.id, s.severity]))
}

const finalResolved = resolved.map(v => ({
  ...v,
  severity: v.verdict === 'COSMETIC' ? 'cosmetic' : (severityById[v.id] || 'minor'),
}))

const result = renderReport(input.target, finalResolved, deduped.length)
log(`${result.counts.total} findings surfaced (${result.counts.blocking} blocking, ${result.counts.major} major, ${result.counts.minor} minor, ${result.counts.cosmetic} cosmetic)`)

return result
