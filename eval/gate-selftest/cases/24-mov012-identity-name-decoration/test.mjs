#!/usr/bin/env node
/**
 * GHSA-vvr3-fhhp-wvhq — MOV-012's IDENTITY_NAMES was exact-anchored
 * (`^(?:sender|caller|...)$`), so it matched a BARE word only. Any
 * decoration on the name -- `sender_address`, `caller_addr`,
 * `owner_account`, `admin_id`, `the_sender`, `senderAddress` -- fell
 * outside the anchors, and the identical spoofable-identity function
 * scored clean. `sender_address` is the most natural way a Move author
 * actually writes this parameter -- the rule fired on the textbook
 * spelling and stayed silent on the everyday one.
 *
 * Same defect family PR #85 already fixed once for MOV-008's payment
 * names (`payment_amount`/`fee_bps` invisible because `\b` never breaks
 * at `_`). Fixed here the SAME shape, reused rather than re-invented:
 * IDENTITY_NAMES is now a Set of bare words, and a parameter name is
 * split on underscore and camelCase boundaries, each resulting word
 * tested for EXACT membership -- never a substring test, so a word that
 * only shares a stem with a name (`authorized` vs `authority`) does not
 * silently widen the set.
 *
 * MUST NOT REGRESS #86's own narrowing, which this fork's base already
 * contains: `recipient` stays clean (a destination the caller may
 * legitimately choose, not an identity claim); `from` still fires (a
 * claimed SOURCE is spoofable in a way a chosen destination is not); a
 * function with no TxContext parameter produces no finding (the
 * prescribed remedy `tx_context::sender(ctx)` is unavailable); and
 * `hasCtx` still resolves the LAST segment of a qualified path
 * (`ctx: &mut sui::tx_context::TxContext` must count) without becoming a
 * substring match (`MyTxContextWrapper` must not falsely count).
 */
import { check } from '../../../../rules/mov-012-sender-as-address-param.mjs';

const errs = [];
function assert(label, cond) {
  if (!cond) errs.push(label);
}

function withdrawSrc(paramName) {
  return `module demo::pay {
    use sui::tx_context::TxContext;
    public fun withdraw(${paramName}: address, amount: u64, ctx: &mut TxContext): u64 {
        assert!(${paramName} == ctx.sender(), 0);
        amount
    }
}`;
}

// ── The advisory's own control/bypass pair, verbatim ────────────────────

const control = check(withdrawSrc('sender'), 'control.move');
assert('control: sender: address fires (unchanged baseline)', control.length === 1);
assert('control finding is HIGH', control[0]?.severity === 'HIGH');

const bypass = check(withdrawSrc('sender_address'), 'bypass.move');
assert('bypass: sender_address: address now fires (was 0 findings pre-fix)', bypass.length === 1);
assert('bypass finding is HIGH', bypass[0]?.severity === 'HIGH');

// ── Compound + camelCase forms the dispatch named explicitly ───────────

for (const paramName of ['caller_addr', 'owner_account', 'admin_id', 'the_sender', 'senderAddress']) {
  const findings = check(withdrawSrc(paramName), 'x.move');
  assert(`${paramName}: address fires`, findings.length === 1);
}

// ── #86's negatives must survive unmodified ─────────────────────────────

const recipientFindings = check(withdrawSrc('recipient'), 'x.move');
assert('recipient stays clean (destination, not an identity claim) -- #86 unchanged', recipientFindings.length === 0);

const fromFindings = check(withdrawSrc('from'), 'x.move');
assert('from still fires (claimed source, spoofable) -- #86 unchanged', fromFindings.length === 1);

const NO_CTX = `module demo::pay {
    public fun verify(root: vector<u8>, proof: vector<u8>, sender: address): u256 {
        sender
    }
}`;
assert('no TxContext parameter -> no finding (prescribed fix is unactionable) -- #86 unchanged', check(NO_CTX, 'x.move').length === 0);

// hasCtx must still resolve the LAST segment of a qualified path, and
// must NOT become a substring match -- both #86 fail-open/fail-closed
// guards, re-verified here rather than assumed still true.
const QUALIFIED_CTX = `module demo::pay {
    public fun withdraw(sender_address: address, amount: u64, ctx: &mut sui::tx_context::TxContext): u64 {
        assert!(sender_address == ctx.sender(), 0);
        amount
    }
}`;
assert('a qualified sui::tx_context::TxContext still resolves as ctx (last-segment match)', check(QUALIFIED_CTX, 'x.move').length === 1);

const FAKE_CTX_TYPE = `module demo::pay {
    public fun withdraw(sender_address: address, amount: u64, ctx: MyTxContextWrapper): u64 {
        amount
    }
}`;
assert('MyTxContextWrapper must NOT substring-match as TxContext -> no finding', check(FAKE_CTX_TYPE, 'x.move').length === 0);

// ── Stem-sharing must NOT fire -- the exact-word-membership discipline,
// same as #85's own deposited != deposit guard, applied here. ─────────

const STEM_SHARE = `module demo::pay {
    use sui::tx_context::TxContext;
    public fun withdraw(authorized_by: address, amount: u64, ctx: &mut TxContext): u64 {
        amount
    }
}`;
assert('authorized_by does not match "authority" (stem-share only, exact-word test)', check(STEM_SHARE, 'x.move').length === 0);

// ── The original SuiTears false-positive fixtures #86 fixed must stay
// clean under the widened matching too (no TxContext still gates first).

const SUITEARS_USER = `module demo::airdrop {
    public fun has_account_claimed(list: &vector<address>, user: address): bool {
        vector::contains(list, &user)
    }
}`;
assert('SuiTears has_account_claimed(user: address), no ctx, stays clean', check(SUITEARS_USER, 'x.move').length === 0);

// ── Hostile input: bounded word-splitting, must not be the next
// quadratic -- this room has closed five already. ──────────────────────

function makeLongIdentSrc(chars) {
  const ident = 'a'.repeat(chars);
  return `module demo::pay {
    use sui::tx_context::TxContext;
    public fun f(${ident}: address, ctx: &mut TxContext): u64 {
        0
    }
}`;
}
{
  const src = makeLongIdentSrc(40000);
  const t0 = Date.now();
  const r = check(src, 'x.move');
  const ms = Date.now() - t0;
  assert('a 40,000-char identifier parameter name produces no finding (no identity word inside a plain a-run)', r.length === 0);
  assert(`a 40,000-char identifier parameter name completes within a generous 2000ms ceiling (got ${ms}ms) -- loose regression tripwire, not a perf SLA`, ms < 2000);
}

if (errs.length) {
  console.log('FAIL:');
  for (const e of errs) console.log(`  ✗ ${e}`);
  process.exit(1);
}
console.log('MOV-012 identity-name decoration bypass fixed: sender_address/caller_addr/owner_account/admin_id/the_sender/senderAddress all fire like their bare forms; recipient stays clean, from still fires, the no-TxContext gate and the qualified-path/substring hasCtx guards are unchanged; stem-sharing does not fire; a 40,000-char identifier does not regress the bound');
process.exit(0);
