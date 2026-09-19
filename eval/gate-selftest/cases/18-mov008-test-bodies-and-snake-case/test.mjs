#!/usr/bin/env node
/**
 * MOV-008 had two independent defects.
 *
 * DEFECT 1 (false positive): check() kept a private `inTest` flag, set on
 * a `#[test]`/`#[test_only]` attribute line and cleared on the NEXT `fun`
 * line -- but only when that line does NOT itself carry `#[test`. An
 * attribute on its own line (the normal Move shape) is followed by a bare
 * `fun t() {` line, which never carries `#[test`, so the flag cleared
 * exactly at the function signature and the whole test body was then
 * scanned as production code. This is defect-class #1 of this room (an
 * attribute/state flag evaluated at the wrong boundary), closed five
 * times before in five other places.
 *
 * DEFECT 2 (false negative): PAYMENT_NAMES was a `\b`-bounded word-list
 * regex, but `\b` does not break at `_` (underscore is a word character
 * in JS regex), so no snake_case compound identifier ever matched --
 * `payment_amount`/`fee_bps` were invisible while Move's own naming
 * convention is snake_case.
 *
 * Fixed by moving detection onto the shared Move parser
 * (scripts/move-parser.mjs) for defect 1 -- its #[test]/#[test_only]
 * attachment is item-boundary-based (the same fix MOV-002/MOV-004/MOV-011
 * already rely on) -- and by testing payment-relevance per WORD (split on
 * underscores and camelCase boundaries, exact membership) rather than by
 * substring-searching the whole identifier, for defect 2.
 */
import { check } from '../../../../rules/mov-008-exact-equality-assert.mjs';

const errs = [];
function assert(label, cond) {
  if (!cond) errs.push(label);
}

// ── defect 1: #[test] on its own line must not leak into the body ──
const testAttr = `module d::a {
    #[test]
    fun t() {
        assert!(amount == 100, 0);
    }
}`;
assert(
  '#[test] on its own line must not be scanned as production code',
  check(testAttr, 'a.move').length === 0
);

const testOnlyAttr = `module d::b {
    #[test_only]
    fun t2() {
        assert!(amount == 100, 0);
    }
}`;
assert(
  '#[test_only] on its own line must not be scanned as production code',
  check(testOnlyAttr, 'b.move').length === 0
);

// ── control: the identical body under plain public must still fire ──
const plainControl = `module d::c {
    public fun f() {
        assert!(amount == 100, 0);
    }
}`;
assert(
  'the identical body under plain public must still be flagged (control)',
  check(plainControl, 'c.move').length === 1
);

// ── defect 2: snake_case payment identifiers must be detected ──
const paymentAmount = `module d::d {
    public fun f(payment_amount: u64, required: u64) {
        assert!(payment_amount == required, 0);
    }
}`;
assert(
  'a snake_case payment_amount identifier must be flagged (was: invisible)',
  check(paymentAmount, 'd.move').length === 1
);

const feeBps = `module d::e {
    public fun f(fee_bps: u64, required: u64) {
        assert!(fee_bps == required, 0);
    }
}`;
assert(
  'a snake_case fee_bps identifier must be flagged (was: invisible)',
  check(feeBps, 'e.move').length === 1
);

// ── control: the bare, already-working spelling must still fire ──
const bareAmount = `module d::f {
    public fun f(amount: u64, required: u64) {
        assert!(amount == required, 0);
    }
}`;
assert(
  'the bare "amount" spelling must still be flagged (control)',
  check(bareAmount, 'f.move').length === 1
);

// ── negative controls: a word that merely contains a name must NOT match ──
const coffeeNeg = `module d::g {
    public fun f(coffee: u64, required: u64) {
        assert!(coffee == required, 0);
    }
}`;
assert(
  '"coffee" must not match on the "fee" substring',
  check(coffeeNeg, 'g.move').length === 0
);

const depositedAtNeg = `module d::h {
    public fun f(deposited_at: u64, required: u64) {
        assert!(deposited_at == required, 0);
    }
}`;
assert(
  '"deposited_at" must not match -- "deposited" shares only a stem with "deposit", not an exact word',
  check(depositedAtNeg, 'h.move').length === 0
);

// ── both existing exclusions must survive unchanged ──
const versionExclusion = `module d::i {
    public fun f(version: u64) {
        assert!(version == 5, 0);
    }
}`;
assert(
  'the version/type/kind/status/state/flag/mode/role exclusion must still fire',
  check(versionExclusion, 'i.move').length === 0
);

const zeroExclusion = `module d::j {
    public fun f(amount: u64) {
        assert!(amount == 0, 0);
    }
}`;
assert(
  'the == 0 exclusion must still fire',
  check(zeroExclusion, 'j.move').length === 0
);

if (errs.length) {
  console.log(`${errs.length} case(s) failed:`);
  for (const e of errs) console.log(`  - ${e}`);
  process.exit(1);
}
console.log('MOV-008: test bodies stay silent, snake_case payment names are detected, both exclusions hold');
process.exit(0);
