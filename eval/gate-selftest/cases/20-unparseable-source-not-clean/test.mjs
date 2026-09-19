#!/usr/bin/env node
/**
 * WAVE 3 UNIT 1 -- "the tool could not read the source, and reported CLEAN"
 * is one class with two instances, fixed at the mechanism, never by
 * changing a rule file. BOUNCED once by INSPECT; this version pins the
 * re-measured, honest numbers rather than either side's first guess.
 *
 * U1: a whitespace-collapsed one-line module made parseModule()'s
 *     extractFunctions() return zero functions -- its signature regex was
 *     anchored to the START of a trimmed line, so a `module d::m { public
 *     fun f(...) { ... } }` packed onto one physical line never matched.
 *     Fixed by un-anchoring the regex (a strict superset: every existing
 *     multi-line signature still matches at the same position, since
 *     nothing precedes it there to try first).
 *
 *     RE-MEASURED against a 7-rule fixture (built once, below, and shared
 *     by both the multi-line and one-line forms so there is no hand-copy
 *     drift between them): the multi-line baseline fires 7 of 9 rules
 *     (MOV-001/002/003/004/005/008/011 -- MOV-006/012 don't apply to this
 *     fixture's content, not that they're broken). Pre-fix, the one-line
 *     form fired only 1 of those 7 (MOV-003, which has its own independent
 *     scanner unrelated to move-parser.mjs and happened to still catch this
 *     particular division). Post-fix: 5 of 7 (MOV-002/003/004/008/011).
 *     Still blind: MOV-001 AND MOV-005 -- BOTH have their own independent,
 *     separately-anchored line-scanners (confirmed: `grep -l move-parser
 *     rules/*.mjs` returns only 002/004/008/011), so a mechanism fix in
 *     move-parser.mjs cannot reach either. Fixing them needs their own rule
 *     files, out of this unit's scope by the dispatch's own rails --
 *     disclosed here, not silently dropped and not fixed.
 *
 *     MOV-008 is CONDITIONAL on a one-line module, not unconditionally
 *     fixed: parseBody()'s assert-condition capture (`assert!\s*\((.+)/`)
 *     is greedy to end of PHYSICAL line. On a real multi-line file that
 *     bound is invisible (each statement has its own line); on a one-line
 *     module the "line" is the whole file, so the captured condition can
 *     swallow everything after the assert, including a LATER `!=` on the
 *     same line -- which trips MOV-008's own `expr.includes('!=')` skip
 *     guard and silently suppresses the finding. This is a PRE-EXISTING
 *     quirk in move-parser.mjs's shared parseBody (not something this unit
 *     introduced), made newly REACHABLE by U1's own fix -- the same
 *     "pre-existing is not inert" shape this room has hit before. Pinned
 *     below with both shapes; not fixed (move-parser.mjs's parseBody is
 *     shared infra, and the dispatch's own rails ask for disclosure here,
 *     not a second fix riding along with the first).
 *
 * U2: an unterminated `/*` made strip-comments.mjs blank everything from
 *     there to EOF with no signal that anything was wrong -- the rules
 *     then scanned an effectively empty file and reported "No findings."
 *     Fixed by adding hasUnterminatedBlockComment() (sharing strip-
 *     comments.mjs's existing scan state machine, never duplicating it)
 *     and wiring lint.mjs's runLint() to report an `unreadable` entry per
 *     such file instead of running any rule against blanked garbage.
 *
 *     BOUNCED: the first version wired ONLY lint.mjs's own standalone CLI.
 *     `check-coverage.mjs` -- the entry point the GitHub Action actually
 *     runs -- destructured `{ findings, ruleCount, suppressed }` from the
 *     SAME `runLint()` and silently dropped `unreadable` on the floor, so
 *     the two entry points gave OPPOSITE verdicts on the identical
 *     directory: `lint.mjs` said exit 3 + named the file, `check-
 *     coverage.mjs --lint` said "No findings." exit 0. Fixed by
 *     destructuring `unreadable` there too, feeding it through the SAME
 *     `printLintResults`/`printUnreadable` (reused, not reimplemented),
 *     and folding it into check-coverage.mjs's OWN pre-existing
 *     EXIT_CANNOT_RUN=3 precedence (already used for "--mutate requested,
 *     no sui CLI" -- the same "no verdict reached" class, not a new code):
 *     a real finding (gateFailed) still outranks it, exactly as lint.mjs's
 *     own CLI already did.
 *
 *     Also fixed: `printLintResults` printed the bare "No findings." even
 *     when part of the corpus was unreadable -- the exact string a CI log
 *     grep matches for "clean", indistinguishable from an actually-clean
 *     run. It now prints "No findings in the files that could be scanned."
 *     when `unreadable.length > 0`, leaving the findings SECTION itself
 *     untouched (a genuinely scanned-and-clean subset is still reported as
 *     such, never hidden).
 */
import { spawnSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';

import { runLint } from '../../../../scripts/lint.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..', '..', '..', '..');
const LINT_CLI = join(repoRoot, 'scripts', 'lint.mjs');
const GATE_CLI = join(repoRoot, 'scripts', 'check-coverage.mjs');

const errs = [];
function assert(label, cond) {
  if (!cond) errs.push(label);
}

// ── U1: 7-rule fixture, one shared line array -> both forms ────────────
// (mechanical join, never a hand-retyped second copy that could drift)

const SEVEN_RULE_LINES = [
  'module d::m {',
  '    public(package) entry fun drain(v: &mut Vault, amount: u64, total: u64, required: u64, w: u128, list: &vector<address>, sender: address, ctx: &mut TxContext) {',
  '        let m = amount * total;',
  '        let q = amount / total;',
  '        let n = (w as u64);',
  '        vector::contains(list, &sender);',
  '        assert!(amount == required, 1);',
  '        v.bal = 0;',
  '    }',
  '}',
];
const MULTI_LINE_7 = SEVEN_RULE_LINES.join('\n');
const ONE_LINE_7 = SEVEN_RULE_LINES.map((l) => l.trim()).join(' ');

const RULE_FILES = [
  ['MOV-001', 'mov-001-missing-access-control'],
  ['MOV-002', 'mov-002-unchecked-arithmetic'],
  ['MOV-003', 'mov-003-division-without-zero-check'],
  ['MOV-004', 'mov-004-unsafe-downcast'],
  ['MOV-005', 'mov-005-unused-auth-result'],
  ['MOV-008', 'mov-008-exact-equality-assert'],
  ['MOV-011', 'mov-011-package-entry-bypass'],
];

const multiFired = [];
const oneFired = [];
for (const [label, file] of RULE_FILES) {
  const { check } = await import(`../../../../rules/${file}.mjs`);
  if (check(MULTI_LINE_7, 'm.move').length > 0) multiFired.push(label);
  if (check(ONE_LINE_7, 'm.move').length > 0) oneFired.push(label);
}

assert(
  `the multi-line baseline fires all 7 rules (got: ${multiFired.join(',')})`,
  multiFired.length === 7 && RULE_FILES.every(([label]) => multiFired.includes(label))
);
assert(
  `the one-line form fires exactly MOV-002/003/004/008/011, five of seven (got: ${oneFired.join(',')})`,
  oneFired.length === 5 &&
    ['MOV-002', 'MOV-003', 'MOV-004', 'MOV-008', 'MOV-011'].every((r) => oneFired.includes(r))
);
assert(
  'KNOWN LIMITATION: MOV-001 does NOT fire on the one-line form (own independent scanner, unreachable from move-parser.mjs)',
  !oneFired.includes('MOV-001')
);
assert(
  'KNOWN LIMITATION: MOV-005 does NOT fire on the one-line form (own independent scanner, unreachable from move-parser.mjs)',
  !oneFired.includes('MOV-005')
);

// ── MOV-008's conditional gap on a one-liner ────────────────────────────

{
  const { check: check008 } = await import('../../../../rules/mov-008-exact-equality-assert.mjs');
  const noTrailingNeq = `module d::a { public fun settle(payment: u64, required: u64) { assert!(payment == required, 1); } }`;
  const withTrailingNeq = `module d::b { public fun settle(payment: u64, required: u64, total: u64) { assert!(payment == required, 1); assert!(total != 0, 2); } }`;
  assert(
    'MOV-008 fires on a one-liner when nothing after the payment assert uses !=',
    check008(noTrailingNeq, 'a.move').length === 1
  );
  assert(
    'CONDITIONAL GAP, disclosed not fixed: MOV-008 does NOT fire on a one-liner when a LATER != shares the physical line (greedy assert-condition capture in move-parser.mjs\'s parseBody)',
    check008(withTrailingNeq, 'b.move').length === 0
  );
}

// ── U2: unterminated /* -- library level (runLint's `unreadable`) ─────

function makeDir(files) {
  const dir = mkdtempSync(join(tmpdir(), 'mtg-unparseable-'));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

const UNTERMINATED = `module d::m {
/* unterminated
    public fun f(a: u64, b: u64) { let z = a * b; }
}
`;

const EMPTY = '';

const COMMENT_ONLY = `/* a fully terminated block comment */
// and a line comment too
`;

const NORMAL_CLEAN = `module d::v {
    public fun total(p: &Pool): u64 {
        p.total
    }
}
`;

const NORMAL_FINDING = `module d::h {
    public fun drain(v: &mut Pool, amount: u64) {
        v.total = amount;
    }
}
`;

// A pre-fix runLint() has no `unreadable` field at all -- these calls are
// wrapped so that shape mismatch reports as a failed assertion (useful
// red-first signal) rather than an uncaught crash that hides every
// assertion after it.
async function runLintSafe(dir) {
  try {
    return await runLint(dir);
  } catch (e) {
    return { findings: [], unreadable: undefined, _crashed: e.message };
  }
}

{
  const dir = makeDir({ 'a.move': UNTERMINATED });
  const { findings, unreadable, _crashed } = await runLintSafe(dir);
  assert('an unterminated block comment produces zero fabricated findings', findings.length === 0);
  assert(
    `runLint() names the file as unreadable${_crashed ? ` (crashed: ${_crashed})` : ''}`,
    Array.isArray(unreadable) && unreadable.length === 1 && unreadable[0].file.endsWith('a.move')
  );
  assert(
    'the unreadable reason mentions the unterminated block comment',
    Array.isArray(unreadable) && unreadable.length === 1 && /unterminated/i.test(unreadable[0].reason || '')
  );
}

{
  const dir = makeDir({ 'a.move': EMPTY });
  const { unreadable } = await runLintSafe(dir);
  assert('a legitimately EMPTY file must NOT be called unreadable', Array.isArray(unreadable) && unreadable.length === 0);
}

{
  const dir = makeDir({ 'a.move': COMMENT_ONLY });
  const { unreadable } = await runLintSafe(dir);
  assert('a comment-only (fully terminated) file must NOT be called unreadable', Array.isArray(unreadable) && unreadable.length === 0);
}

// ── U2: exit codes + wording -- lint.mjs's own CLI ──────────────────────

const spawnLint = (dir) => spawnSync(process.execPath, [LINT_CLI, dir], { encoding: 'utf8', timeout: 30000 });

{
  const dir = makeDir({ 'a.move': UNTERMINATED });
  const r = spawnLint(dir);
  const out = (r.stdout || '') + (r.stderr || '');
  assert(`an unreadable-only run exits 3 (got ${r.status})`, r.status === 3);
  assert('the CLI names the unreadable file in its output', /a\.move/.test(out));
  assert(
    'the human-readable line distinguishes "unreadable present" from a genuine clean ("No findings in the files that could be scanned.", not bare "No findings.")',
    /No findings in the files that could be scanned\./.test(out)
  );
}

{
  const dir = makeDir({ 'a.move': NORMAL_CLEAN });
  const r = spawnLint(dir);
  const out = (r.stdout || '') + (r.stderr || '');
  assert(`a normal clean file still exits 0 (got ${r.status})`, r.status === 0);
  assert(
    'a genuinely clean run keeps the bare "No findings." (unchanged by this fix)',
    /(^|\n)No findings\.\n/.test(out) && !/No findings in the files/.test(out)
  );
}

{
  // Precedence: a real finding elsewhere in the SAME run outranks an
  // unreadable file -- README's own rule ("a defect outranks a missing
  // tool"), applied to this new path. Exit 1, never 3.
  const dir = makeDir({ 'clean.move': NORMAL_FINDING, 'broken.move': UNTERMINATED });
  const r = spawnLint(dir);
  assert(`a real finding outranks an unreadable file in the same run: exits 1, not 3 (got ${r.status})`, r.status === 1);
}

// ── U2, the BLOCKING fix: check-coverage.mjs must agree with lint.mjs ──
// on the SAME directory -- the GitHub Action runs check-coverage.mjs, not
// lint.mjs directly, so this is the entry point consumers actually hit.

function makeGateTree(sourceFiles) {
  const dir = mkdtempSync(join(tmpdir(), 'mtg-gate-unreadable-'));
  mkdirSync(join(dir, 'sources'), { recursive: true });
  mkdirSync(join(dir, 'tests'), { recursive: true });
  for (const [name, content] of Object.entries(sourceFiles)) {
    writeFileSync(join(dir, 'sources', name), content);
  }
  return dir;
}

const spawnGate = (dir, extraArgs = []) => spawnSync(
  process.execPath,
  [GATE_CLI, join(dir, 'sources'), join(dir, 'tests'), '--lint', ...extraArgs],
  { encoding: 'utf8', timeout: 30000 }
);

{
  const dir = makeGateTree({ 'a.move': UNTERMINATED });
  const r = spawnGate(dir);
  const out = (r.stdout || '') + (r.stderr || '');
  assert(
    `check-coverage.mjs --lint on an unreadable-only tree exits 3, same verdict class as lint.mjs (got ${r.status})`,
    r.status === 3
  );
  assert('check-coverage.mjs --lint also names the unreadable file', /a\.move/.test(out));
  assert(
    'check-coverage.mjs --lint also uses the "files that could be scanned" wording, not bare "No findings."',
    /No findings in the files that could be scanned\./.test(out)
  );
}

{
  // Same precedence check-coverage.mjs's own side: a real Layer-1 gate
  // failure (an unpaired assert) still outranks an unreadable lint file.
  const UNPAIRED_ASSERT_SOURCE = `module d::h {
    const ENotEnough: u64 = 1;
    public fun withdraw(amount: u64, balance: u64) {
        assert!(amount <= balance, ENotEnough);
    }
}
`;
  const dir = makeGateTree({ 'clean.move': UNPAIRED_ASSERT_SOURCE, 'broken.move': UNTERMINATED });
  const r = spawnGate(dir);
  assert(
    `check-coverage.mjs: a real gate failure outranks an unreadable lint file too -- exits 1, not 3 (got ${r.status})`,
    r.status === 1
  );
}

if (errs.length) {
  console.log('FAIL:');
  for (const e of errs) console.log(`  ✗ ${e}`);
  process.exit(1);
}
console.log('unparseable source no longer reads as clean, on BOTH entry points: one-line module 1->5 of 7 rules (MOV-001/005 stay a documented gap, MOV-008 conditional and disclosed), unterminated /* gets an unreadable verdict + exit 3 + honest wording from lint.mjs AND check-coverage.mjs --lint alike, empty/comment-only files stay clean, a real finding outranks an unreadable file on both entry points');
process.exit(0);
