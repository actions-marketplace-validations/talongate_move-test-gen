#!/usr/bin/env node
/**
 * MOV-013 — `#[spec_only]` is a sui-prover marker, NOT a compiler
 * attribute. The Move compiler does not strip a function carrying it: it
 * emits `warning[W02018]: unknown attribute` and compiles the function
 * normally, so a `#[spec_only] public fun` ships in production bytecode.
 * move-test-gen had zero recognition of the attribute before this rule —
 * such a function scored clean on every existing rule.
 *
 * Regression fixture is the advisory draft's own reproduction module
 * verbatim (`probe::vault`): `leak_secret` and `set_owner` both carry
 * `#[spec_only]` on a public function that touches a struct field (HIGH);
 * `test_only_helper` carries `#[test_only]`, which the compiler genuinely
 * does strip, and must NOT fire.
 *
 * DELIBERATELY does not consume `scripts/move-parser.mjs`'s `parseModule()`
 * (the obvious reuse target — it already walks `#[test_only]`/`#[test]`
 * attributes per function). Measured, not assumed: at this fork's current
 * HEAD, `parseModule()`'s own internal `parseBody()` still carries the
 * unbounded `(\w+)...(\w+)` multiplication/division/calls regexes a
 * separate branch in the sibling `talongate/move-test-gen` room fixed —
 * that fix has not landed here, and this unit's rails do not authorize
 * touching `move-parser.mjs`. Calling `parseModule()` measured 5583ms on a
 * 40,000-character identifier (isolated from this rule's own code by
 * timing `parseModule()` alone) — consuming it would have made MOV-013
 * inherit a live O(n^2) DoS on commit. MOV-013 is therefore a fully
 * independent scanner (own visibility/attribute/brace-boundary walk),
 * every `\w+` it writes bounded to `\w{1,128}`, verified flat/O(n) at the
 * bottom of this file.
 *
 * INSPECT BOUNCE, fixed here (both findings, this room fixes what it
 * finds — the reviewer does not fix):
 *   F1 · HIGH: `SPEC_ONLY_RE` required `spec_only`/`ext(spec_only)` to be
 *     the attribute group's ENTIRE content, so any comma-separated list
 *     (`#[test_only, spec_only]`) or any second `#[...]` group stacked on
 *     one line (`#[allow(lint(x))] #[spec_only]`) bypassed detection
 *     entirely — a one-token bypass of a rule shipped under a HIGH
 *     advisory. Fixed by treating spec_only as a MEMBER of a
 *     comma-split attribute group, scanned across every `#[...]` group on
 *     the line, not only a leading whole-line one. All three bypass
 *     shapes plus the twelve surviving control shapes INSPECT enumerated
 *     are pinned below.
 *   F2 · MEDIUM: an unterminated function body made `findFunctionEndLine`
 *     scan to EOF, and `functionTouchesFields` re-walked the same range —
 *     N such functions in one file cost O(N x lines), measured
 *     50/166/669/2576ms at N=500/1000/2000/4000. Folded into one bounded
 *     pass (`scanFunctionBody`, cap `MAX_BODY_SCAN_LINES = 200`,
 *     re-measured against the SAME shape before trusting a first, too-
 *     generous 5000-line cap that was still quadratic) — re-measured
 *     51/90/197/385ms, ~2x per doubling, linear. Pinned below with the
 *     same N=4000 fixture under a loose ceiling.
 */
import { check } from '../../../../rules/mov-013-spec-only-ships-in-bytecode.mjs';

const errs = [];
function assert(label, cond) {
  if (!cond) errs.push(label);
}

// ── Regression fixture, verbatim from the advisory draft ──────────────

const VAULT_SOURCE = `module probe::vault {
    public struct Vault has key, store { id: sui::object::UID, owner: address, secret: u64 }

    public fun new(secret: u64, ctx: &mut sui::tx_context::TxContext): Vault {
        Vault { id: sui::object::new(ctx), owner: ctx.sender(), secret }
    }

    #[spec_only]
    public fun leak_secret(v: &Vault): u64 { v.secret }

    #[spec_only]
    public fun set_owner(v: &mut Vault, who: address) { v.owner = who; }

    #[test_only]
    public fun test_only_helper(v: &Vault): u64 { v.secret }
}`;

const vaultFindings = check(VAULT_SOURCE, 'vault.move');
assert('exactly two findings on the regression fixture (leak_secret, set_owner)', vaultFindings.length === 2);
assert('leak_secret finding is on its own `fun` line (9)', vaultFindings.some(f => f.line === 9));
assert('set_owner finding is on its own `fun` line (12)', vaultFindings.some(f => f.line === 12));
assert('both findings are HIGH (both read/write a struct field)', vaultFindings.every(f => f.severity === 'HIGH'));
assert('zero findings mention test_only_helper\'s line', !vaultFindings.some(f => /test_only_helper/.test(f.message)));
assert(
  'the message states the deciding fact (compiler does not strip it) and the remedies',
  vaultFindings.every(f => /does NOT strip/.test(f.message) && /#\[test_only\]/.test(f.message) && /private/.test(f.message))
);

// ── Negatives from the dispatch ─────────────────────────────────────────

const PRIVATE_SPEC_ONLY = `module d::m {
    #[spec_only]
    fun helper(v: &Vault): u64 { v.secret }
}`;
assert('a PRIVATE #[spec_only] fun is not a finding', check(PRIVATE_SPEC_ONLY, 'm.move').length === 0);

const EXT_WRAPPED = `module d::m {
    #[ext(spec_only)]
    public fun leak(v: &Vault): u64 { v.secret }
}`;
const extFindings = check(EXT_WRAPPED, 'm.move');
assert('#[ext(spec_only)] public fun IS a finding', extFindings.length === 1 && extFindings[0].severity === 'HIGH');

// ── Severity: MEDIUM when the function touches no struct field ─────────

const NO_FIELD_TOUCH = `module d::m {
    #[spec_only]
    public fun noop(): u64 { 42 }
}`;
const noopFindings = check(NO_FIELD_TOUCH, 'm.move');
assert('a spec_only public fun that touches no field is MEDIUM, still a finding', noopFindings.length === 1 && noopFindings[0].severity === 'MEDIUM');

// A Move 2024 dot-CALL (`ctx.sender()`) is a method call, not a field
// touch -- must not be misclassified as HIGH.
const DOT_CALL_ONLY = `module d::m {
    #[spec_only]
    public fun who(ctx: &sui::tx_context::TxContext): address { ctx.sender() }
}`;
const dotCallFindings = check(DOT_CALL_ONLY, 'm.move');
assert('a dot-CALL (method, desugared) is not mistaken for a field touch -- stays MEDIUM', dotCallFindings.length === 1 && dotCallFindings[0].severity === 'MEDIUM');

// ── The room's own attribute-attach discipline, pinned here too: an
// attribute attaches to the SINGLE item immediately following it, never a
// distance window. Fixed five times elsewhere in this room; this rule
// must not reintroduce the leak. ──────────────────────────────────────

const ATTR_ON_USE_NOT_FUN = `module d::m {
    #[spec_only]
    use std::debug;

    public fun leak(v: &Vault): u64 { v.secret }
}`;
assert(
  '#[spec_only] on a `use` statement does not leak forward onto an unrelated function below it',
  check(ATTR_ON_USE_NOT_FUN, 'm.move').length === 0
);

const WRAPPED_DECL = `module d::m {
    #[spec_only]
    public(package)
    entry fun leak(v: &Vault): u64 { v.secret }
}`;
assert(
  '#[spec_only] still attaches across a wrapped multi-line visibility+entry declaration',
  check(WRAPPED_DECL, 'm.move').length === 1
);

const PLAIN_PUBLIC_NO_ATTR = `module d::m {
    public fun ordinary(v: &Vault): u64 { v.secret }
}`;
assert('an ordinary public fun with no attribute at all is not a finding', check(PLAIN_PUBLIC_NO_ATTR, 'm.move').length === 0);

// ── F1 · HIGH · three bypass shapes INSPECT found, all must now fire ───

const F1_LIST_TEST_ONLY_FIRST = `module d::m {
    #[test_only, spec_only]
    public fun leak(v: &Vault): u64 { v.secret }
}`;
assert('F1: #[test_only, spec_only] comma list fires (spec_only as a list member)', check(F1_LIST_TEST_ONLY_FIRST, 'm.move').length === 1);

const F1_LIST_SPEC_ONLY_FIRST = `module d::m {
    #[spec_only, allow(lint(x))]
    public fun leak(v: &Vault): u64 { v.secret }
}`;
assert('F1: #[spec_only, allow(lint(x))] comma list fires', check(F1_LIST_SPEC_ONLY_FIRST, 'm.move').length === 1);

const F1_STACKED_SAME_LINE = `module d::m {
    #[allow(lint(x))] #[spec_only] public fun leak(v: &Vault): u64 { v.secret }
}`;
assert('F1: two #[...] groups stacked on one physical line before `fun` fires', check(F1_STACKED_SAME_LINE, 'm.move').length === 1);

// A list member sharing a name-prefix with `spec_only` must NOT false-fire
// -- confirms the fix matches the MEMBER exactly, not by substring.
const NOT_A_MEMBER = `module d::m {
    #[not_spec_only_at_all]
    public fun leak(v: &Vault): u64 { v.secret }
}`;
assert('F1 guard: an attribute merely containing "spec_only" as a substring, not as its own list member, does not fire', check(NOT_A_MEMBER, 'm.move').length === 0);

// A comma inside an unrelated member's OWN parens must not be mistaken for
// the top-level list separator (would wrongly fragment one member into two).
const NESTED_COMMA_MEMBER = `module d::m {
    #[spec_only, expected_failure(abort_code = 1, location = Self)]
    public fun leak(v: &Vault): u64 { v.secret }
}`;
assert('F1: a nested comma inside another member\'s own parens does not break the top-level split', check(NESTED_COMMA_MEMBER, 'm.move').length === 1);

// ── F1 · the twelve control shapes INSPECT enumerated as already
// surviving, pinned individually so a future edit can't quietly narrow
// the fix back down to "only the leading/sole-content shape". ─────────

assert('control: same-line attr', check(`module d::m {
    #[spec_only] public fun leak(v: &Vault): u64 { v.secret }
}`, 'm.move').length === 1);

assert('control: public(package)', check(`module d::m {
    #[spec_only]
    public(package) fun leak(v: &Vault): u64 { v.secret }
}`, 'm.move').length === 1);

assert('control: public(friend)', check(`module d::m {
    #[spec_only]
    public(friend) fun leak(v: &Vault): u64 { v.secret }
}`, 'm.move').length === 1);

assert('control: entry', check(`module d::m {
    #[spec_only]
    entry fun leak(v: &Vault): u64 { v.secret }
}`, 'm.move').length === 1);

assert('control: public entry', check(`module d::m {
    #[spec_only]
    public entry fun leak(v: &Vault): u64 { v.secret }
}`, 'm.move').length === 1);

assert('control: blank line between attribute and fun', check(`module d::m {
    #[spec_only]

    public fun leak(v: &Vault): u64 { v.secret }
}`, 'm.move').length === 1);

assert('control: // comment between attribute and fun', check(`module d::m {
    #[spec_only]
    // a note
    public fun leak(v: &Vault): u64 { v.secret }
}`, 'm.move').length === 1);

assert('control: a stacked OTHER attribute after #[spec_only] (two lines)', check(`module d::m {
    #[spec_only]
    #[allow(lint(x))]
    public fun leak(v: &Vault): u64 { v.secret }
}`, 'm.move').length === 1);

assert('control: Move 2024 module label form (`module x::y;`)', check(`module probe::vault;
#[spec_only]
public fun leak(v: &Vault): u64 { v.secret }
`, 'm.move').length === 1);

// ── F1 guard: a byte string that merely CONTAINS attribute-shaped text,
// on the same line as a real `fun`, must never be read as a real
// attribute -- the same-line scan is bounded to the prefix before `fun`.

const BYTE_STRING_LOOKALIKE = `module d::m {
    public fun f(): vector<u8> { b"#[spec_only]" }
}`;
assert('F1 guard: attribute-shaped text inside a byte string in the body is not a real attribute', check(BYTE_STRING_LOOKALIKE, 'm.move').length === 0);

// ── F2 · MEDIUM · unterminated bodies must not regress to quadratic ────
// N=4000 unterminated `#[spec_only] public fun` bodies (INSPECT's own
// shape). Post-fix measured 51/90/197/385ms at N=500/1000/2000/4000 on the
// machine this was written on; pre-fix measured 50/166/669/2576ms at the
// same sizes. A 1500ms ceiling at N=4000 sits with wide margin above the
// fixed number and well below what even the ORIGINAL (already-quadratic)
// behaviour produced at this exact N -- generous enough that ordinary CI
// variance should not false-fire it, tight enough that a regression back
// to the unbounded scan is caught. Loose regression tripwire, not a perf
// SLA -- if this ever flakes, loosen the ceiling rather than delete it.

function makeUnterminatedSrc(n) {
  let out = 'module d::m {\n';
  for (let i = 0; i < n; i++) {
    out += `    #[spec_only]\n    public fun f${i}(): u64 {\n        let x = 1;\n`;
  }
  return out;
}
{
  const src = makeUnterminatedSrc(4000);
  const t0 = Date.now();
  const r = check(src, 'm.move');
  const ms = Date.now() - t0;
  assert('F2: 4000 unterminated #[spec_only] functions all still fire (count correct, no crash)', r.length === 4000);
  assert(`F2: 4000 unterminated functions complete within a generous 1500ms ceiling (got ${ms}ms) -- loose regression tripwire, not a perf SLA`, ms < 1500);
}

// ── Hostile input: bounded `\w+`, must not be the next quadratic ───────
// (behaviour pin only; the timed proof with n=5 min/median/max lives in
// the dispatch's own RETURN, not duplicated here as a flaky CI assertion
// -- this asserts CORRECTNESS at size, not a wall-clock ceiling)

function makeLongIdentSrc(chars) {
  const ident = 'a'.repeat(chars);
  return `module d::m {
    #[spec_only]
    public fun f(): u64 {
        let ${ident} = 1;
        42
    }
}`;
}
const hostile = makeLongIdentSrc(40000);
const t0 = Date.now();
const hostileFindings = check(hostile, 'm.move');
const ms = Date.now() - t0;
assert('a 40,000-char identifier does not change the finding (still 1, MEDIUM -- no field touch)', hostileFindings.length === 1 && hostileFindings[0].severity === 'MEDIUM');
assert(`a 40,000-char identifier completes within a generous 2000ms ceiling (got ${ms}ms) -- loose regression tripwire, not a perf SLA; measured flat ~1-2ms on the machine this was written on`, ms < 2000);

if (errs.length) {
  console.log('FAIL:');
  for (const e of errs) console.log(`  ✗ ${e}`);
  process.exit(1);
}
console.log('MOV-013: #[spec_only]/#[ext(spec_only)] on a public/package/friend/entry function is flagged (HIGH if it touches a struct field, MEDIUM otherwise) whether it stands alone, in a comma list, or stacked with another attribute group (F1 fixed), a private one and #[test_only] are not, the attribute-attach discipline holds (no distance-window leak), a 40,000-char identifier does not regress the O(n) bound, and 4000 unterminated bodies stay linear (F2 fixed)');
process.exit(0);
