#!/usr/bin/env node
/**
 * MOV-012 fired HIGH on the single most common signature in Sui: a plain
 * transfer to a caller-chosen destination.
 *
 * ```move
 * public fun send(c: Coin<SUI>, recipient: address, ctx: &mut TxContext) {
 *     transfer::public_transfer(c, recipient);
 * }
 * ```
 *
 * Measured on the real SuiTears corpus (eval/scenarios/08-suitears-oracle,
 * 09-suitears-farm), all three MOV-012 findings there were false
 * positives: airdrop.move's and linear_vesting_airdrop.move's
 * `has_account_claimed(..., user: address): bool` (a read-only view --
 * querying another address is the intended use) and airdrop_utils.move's
 * `verify(..., sender: address): u256` (a pure Merkle-leaf check where
 * `sender` is hashed into the leaf and validated against the root --
 * passing someone else's address proves only their membership, granting
 * the caller nothing). None of the three takes a TxContext at all, so
 * the rule's own prescribed fix, tx_context::sender(ctx), could not even
 * be applied to any of them.
 *
 * Fixed by narrowing to where the finding is actionable: (1) no
 * TxContext parameter, no finding -- the prescribed fix needs one; (2)
 * `recipient` is not an identity claim -- a destination names where
 * value is going, a target the caller is entitled to choose, unlike a
 * claimed SOURCE (`from`), which stays spoofable.
 *
 * FINDINGS-BACK follow-up: `hasCtx` tested `p.type === 'TxContext'`
 * against a type group that could not span `::`, so a fully-qualified
 * `ctx: &mut sui::tx_context::TxContext` parsed as type `sui` and
 * silenced the whole function -- a real fail-open even though the
 * corpus's own idiom is `use sui::tx_context::TxContext;` then the
 * bare form (84/84 occurrences bare, zero qualified there). Fixed by
 * capturing the qualified path whole and resolving to its LAST
 * segment, never a substring test (a substring test would re-admit
 * `MyTxContextWrapper` and defeat the narrowing this rule exists for).
 */
import { check } from '../../../../rules/mov-012-sender-as-address-param.mjs';

const errs = [];
function assert(label, cond) {
  if (!cond) errs.push(label);
}

// ── FP 1: the idiomatic transfer, recipient chosen by the caller ──
const transferFp = `module d::a {
    public fun send(c: Coin<SUI>, recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(c, recipient);
    }
}`;
assert(
  'a transfer to a caller-chosen recipient must not be flagged',
  check(transferFp, 'a.move').length === 0
);

// ── FP 2: no-ctx helper, verify()-shaped (Merkle-leaf check) ──
const noCtxVerifyFp = `module d::b {
    public fun verify(root: vector<u8>, proof: vector<u8>, amount: u64, sender: address): u256 {
        abort 0
    }
}`;
assert(
  'a no-TxContext helper (the prescribed fix cannot apply) must not be flagged',
  check(noCtxVerifyFp, 'b.move').length === 0
);

// ── FP 3: no-ctx view, has_account_claimed()-shaped ──
const noCtxViewFp = `module d::c {
    public fun has_account_claimed(self: &Registry, proof: vector<u8>, amount: u64, user: address): bool {
        abort 0
    }
}`;
assert(
  'a no-TxContext read-only view must not be flagged',
  check(noCtxViewFp, 'c.move').length === 0
);

// ── true positive: withdraw, WITH ctx, unchanged ──
const withdrawTp = `module d::d {
    public fun withdraw(sender: address, v: &mut Vault, ctx: &mut TxContext) {
        assert!(sender == v.owner, 0);
    }
}`;
assert(
  'withdraw(sender: address, ..., ctx: &mut TxContext) must still be flagged',
  check(withdrawTp, 'd.move').length === 1
);

// ── true positive: a different identity name, WITH ctx ──
const adminTp = `module d::e {
    public fun admin_action(admin: address, v: &mut Vault, ctx: &mut TxContext) {
        assert!(admin == v.admin, 0);
    }
}`;
assert(
  'a different identity name (admin) with ctx must still be flagged',
  check(adminTp, 'e.move').length === 1
);

// ── true positive: `caller`, WITH ctx ──
const callerTp = `module d::g {
    public fun caller_action(caller: address, v: &mut Vault, ctx: &mut TxContext) {
        assert!(caller == v.owner, 0);
    }
}`;
assert(
  'a different identity name (caller) with ctx must still be flagged',
  check(callerTp, 'g.move').length === 1
);

// ── true positive: `from` (a claimed SOURCE), WITH ctx -- this is the
// name the design deliberately keeps (unlike `recipient`); nothing else
// in this case pins that it still fires ──
const fromTp = `module d::h {
    public fun move_funds(from: address, v: &mut Vault, ctx: &mut TxContext) {
        assert!(from == v.owner, 0);
    }
}`;
assert(
  '`from` (a claimed source, kept in IDENTITY_NAMES) with ctx must still be flagged',
  check(fromTp, 'h.move').length === 1
);

// ── true positive: `owner`, WITH an immutable &TxContext (not &mut) ──
const ownerImmutTp = `module d::i {
    public fun read_owned(owner: address, v: &Vault, ctx: &TxContext) {
        assert!(owner == v.owner, 0);
    }
}`;
assert(
  'owner: address with an immutable &TxContext must still be flagged',
  check(ownerImmutTp, 'i.move').length === 1
);

// ── hasCtx must resolve a `::`-qualified TxContext to its last segment,
// never by substring -- FINDINGS-BACK regression pin, four rows ──
const qualifiedCtx = `module d::j {
    public fun act(sender: address, ctx: &mut sui::tx_context::TxContext) {
        abort 0
    }
}`;
assert(
  'a fully-qualified sui::tx_context::TxContext must still count as having ctx',
  check(qualifiedCtx, 'j.move').length === 1
);

const bareCtxControl = `module d::k {
    public fun act(sender: address, ctx: &mut TxContext) {
        abort 0
    }
}`;
assert(
  'control: bare TxContext must still count as having ctx',
  check(bareCtxControl, 'k.move').length === 1
);

const namedCtxWrongType = `module d::l {
    public fun act(sender: address, ctx: &Clock) {
        abort 0
    }
}`;
assert(
  'a param merely NAMED ctx but typed &Clock must NOT count as having ctx',
  check(namedCtxWrongType, 'l.move').length === 0
);

const substringWrapperType = `module d::m {
    public fun act(sender: address, ctx: &mut MyTxContextWrapper) {
        abort 0
    }
}`;
assert(
  'a type merely CONTAINING the substring TxContext must NOT count -- no substring matching',
  check(substringWrapperType, 'm.move').length === 0
);

// ── #[test_only] skip must survive unchanged ──
const testOnlySkip = `module d::f {
    #[test_only]
    public fun test_helper(user: address, ctx: &mut TxContext) {
        abort 0
    }
}`;
assert(
  '#[test_only] functions must stay exempt',
  check(testOnlySkip, 'f.move').length === 0
);

if (errs.length) {
  console.log(`${errs.length} case(s) failed:`);
  for (const e of errs) console.log(`  - ${e}`);
  process.exit(1);
}
console.log('MOV-012 narrowed to actionable identity claims: no-ctx and recipient FPs gone, TPs and #[test_only] skip intact');
process.exit(0);
