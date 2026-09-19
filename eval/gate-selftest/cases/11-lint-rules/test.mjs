/**
 * Selftest for lint rules — synthetic Move source, no sui needed.
 * Tests all 9 rules: MOV-001 through MOV-006 + MOV-008 + MOV-011 + MOV-012 (MOV-002 includes shift extension).
 * Each new skip pattern gets a pin here BEFORE the rule ships.
 */
import { check as check001 } from '../../../../rules/mov-001-missing-access-control.mjs';
import { check as check002 } from '../../../../rules/mov-002-unchecked-arithmetic.mjs';
import { check as check003 } from '../../../../rules/mov-003-division-without-zero-check.mjs';

const errs = [];
function assert(label, cond) {
  if (!cond) errs.push(label);
}

// ── MOV-001: access control ──────────────────────────────────────────

const unsafe001 = `
module example::pool {
    public struct Pool has key { id: UID, balance: u64 }
    public fun drain(pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance - amount;
    }
}`;

const safe_cap = `
module example::pool {
    public struct Pool has key { id: UID, balance: u64 }
    public struct AdminCap has key { id: UID }
    public fun drain(cap: &AdminCap, pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance - amount;
    }
}`;

const safe_init = `
module example::pool {
    public struct Pool has key { id: UID }
    fun init(ctx: &mut TxContext) { }
}`;

// generic function — MUST be detected (was silently skipped before fix)
const unsafe_generic = `
module example::dex {
    public struct Pool<phantom X, phantom Y> has key { id: UID, reserve_x: u64 }
    public fun update_pool<X, Y>(pool: &mut Pool<X, Y>, configs: &Configs) {
        abort 0
    }
}`;

// #[test_only] function — must be skipped
const safe_test_only = `
module example::pool {
    public struct Pool has key { id: UID, balance: u64 }
    #[test_only]
    public fun add_balance_test(pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance + amount;
    }
}`;

// _test suffix — must be skipped
const safe_test_suffix = `
module example::pool {
    public struct Pool has key { id: UID, balance: u64 }
    public fun drain_test(pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance - amount;
    }
}`;

// Version parameter — must be skipped (Scallop pattern)
const safe_version = `
module example::lending {
    public fun accrue_interest(version: &Version, market: &mut Market, clock: &Clock) {
        version::assert_current_version(version);
    }
}`;

// Key parameter — must be skipped (ObligationKey pattern)
const safe_key = `
module example::obligation {
    public fun unlock(self: &mut Obligation, obligation_key: &ObligationKey, key: u64) {
        abort 0
    }
}`;

// Witness parameter — must be skipped
const safe_witness = `
module example::market {
    public fun uid_mut_delegated(market: &mut Market, _: Witness<Market>): &mut UID {
        &mut market.id
    }
}`;

// Coin<T> parameter — permissionless DeFi function, must be skipped
const safe_coin = `
module example::dex {
    public struct Pool<phantom X, phantom Y> has key { id: UID }
    public fun swap<X, Y>(pool: &mut Pool<X, Y>, coin_in: Coin<X>, ctx: &mut TxContext): Coin<Y> {
        abort 0
    }
}`;

// LPToken parameter — must be skipped
const safe_lp = `
module example::dex {
    public struct Pool<phantom X, phantom Y> has key { id: UID }
    public fun remove_liquidity<X, Y>(pool: &mut Pool<X, Y>, lp: KriyaLPToken<X, Y>, amount: u64, ctx: &mut TxContext) {
        abort 0
    }
}`;

// key/witness named param (generic T: drop pattern) — must be skipped
const safe_key_param = `
module example::lock {
    public fun force_unlock<T: drop>(obligation: &mut Obligation, _key: T) {
        abort 0
    }
}`;

const r001 = check001(unsafe001, 'pool.move');
assert('MOV-001: flags public fun without cap', r001.length > 0);
assert('MOV-001: rule ID correct', r001[0].rule === 'MOV-001');
assert('MOV-001: severity HIGH', r001[0].severity === 'HIGH');

assert('MOV-001: passes with AdminCap', check001(safe_cap, 'pool.move').length === 0);
assert('MOV-001: skips init', check001(safe_init, 'pool.move').length === 0);

const r001_generic = check001(unsafe_generic, 'dex.move');
assert('MOV-001: catches generic function <X, Y>', r001_generic.length > 0);
assert('MOV-001: generic finding names update_pool', r001_generic[0].message.includes('update_pool'));

assert('MOV-001: skips #[test_only] function', check001(safe_test_only, 'pool.move').length === 0);
assert('MOV-001: skips _test suffix', check001(safe_test_suffix, 'pool.move').length === 0);
assert('MOV-001: skips Version param', check001(safe_version, 'lending.move').length === 0);
assert('MOV-001: skips Key param', check001(safe_key, 'obligation.move').length === 0);
assert('MOV-001: skips Witness param', check001(safe_witness, 'market.move').length === 0);
assert('MOV-001: skips Coin<T> param', check001(safe_coin, 'dex.move').length === 0);
assert('MOV-001: skips LPToken param', check001(safe_lp, 'dex.move').length === 0);
assert('MOV-001: skips _key witness param', check001(safe_key_param, 'lock.move').length === 0);

// ── MOV-002: unchecked multiplication ────────────────────────────────

const unsafe_mul = `
module example::fee {
    public fun calc(amount: u64, rate: u64): u64 {
        amount * rate
    }
}`;

const safe_mul_cast = `
module example::fee {
    public fun calc(amount: u64, rate: u64): u64 {
        ((amount as u128) * (rate as u128) / 10000 as u64)
    }
}`;

// #[test] function body — must be skipped
const safe_mul_test = `
module example::setup {
    public fun real_fn(): u64 { 42 }

    #[test]
    fun setup_test() {
        let amount = 1_000_000 * std::u64::pow(10, 6);
        assert!(amount > 0, 0);
    }
}`;

// _u256 suffix variables — already promoted, must be skipped
const safe_mul_u256 = `
module example::math {
    public fun calc(a: u128, b: u128): u256 {
        let a_u256 = (a as u256);
        let b_u256 = (b as u256);
        a_u256 * b_u256
    }
}`;

const r002a = check002(unsafe_mul, 'fee.move');
assert('MOV-002: flags u64 * u64 without cast', r002a.length > 0);
assert('MOV-002: rule ID correct', r002a[0].rule === 'MOV-002');

assert('MOV-002: passes with u128 cast', check002(safe_mul_cast, 'fee.move').length === 0);
assert('MOV-002: skips #[test] function body', check002(safe_mul_test, 'setup.move').length === 0);
assert('MOV-002: skips _u256 suffix vars', check002(safe_mul_u256, 'math.move').length === 0);

// ── MOV-003: division without zero check ─────────────────────────────

const unsafe_div = `
module example::vault {
    public fun shares(amount: u64, total: u64): u64 {
        amount / total
    }
}`;

const safe_div_assert = `
module example::vault {
    const EZero: u64 = 1;
    public fun shares(amount: u64, total: u64): u64 {
        assert!(total != 0, EZero);
        amount / total
    }
}`;

const safe_div_literal = `
module example::fee {
    public fun basis(amount: u64): u64 {
        amount / 10000
    }
}`;

// #[test] function body — must be skipped
const safe_div_test = `
module example::limiter {
    public fun real_fn(): u64 { 42 }

    #[test]
    fun outflow_limit_test() {
        let segment_duration: u64 = 60 * 30;
        let cycle_duration: u64 = 60 * 60 * 24;
        let segment_count = cycle_duration / segment_duration;
    }
}`;

const r003a = check003(unsafe_div, 'vault.move');
assert('MOV-003: flags division by unchecked variable', r003a.length > 0);
assert('MOV-003: rule ID correct', r003a[0].rule === 'MOV-003');

assert('MOV-003: passes with assert before division', check003(safe_div_assert, 'vault.move').length === 0);
assert('MOV-003: skips division by literal', check003(safe_div_literal, 'fee.move').length === 0);
assert('MOV-003: skips #[test] function body', check003(safe_div_test, 'limiter.move').length === 0);

// ── MOV-004: unsafe downcast ─────────────────────────────────────────

import { check as check004 } from '../../../../rules/mov-004-unsafe-downcast.mjs';

// unsafe downcast — must be flagged
const unsafe_downcast = `
module example::rewards {
    public fun pending_reward(stake: u128, rate: u128): u64 {
        let reward = stake * rate / 1000000;
        (reward as u64)
    }
}`;

// safe downcast with overflow check — must be skipped
const safe_downcast = `
module example::rewards {
    const MAX_U64: u256 = 18446744073709551615;
    public fun collect(payable: u256): u64 {
        assert!(payable <= MAX_U64, 0);
        (payable as u64)
    }
}`;

// downcast inside mul_div library function — must be skipped
const lib_downcast = `
module example::math {
    public fun mul_div(a: u64, b: u64, c: u64): u64 {
        ((
            (a as u128) * (b as u128) / (c as u128)
        ) as u64)
    }
}`;

// downcast of known-small field (duration) — must be skipped
const small_field_downcast = `
module example::limiter {
    public fun calc(limiter: &Limiter, now: u64): u64 {
        now / (limiter.outflow_segment_duration as u64)
    }
}`;

// #[test] function — must be skipped
const test_downcast = `
module example::test {
    public fun real_fn(): u64 { 42 }
    #[test]
    fun test_cast() {
        let big: u128 = 999;
        let small = (big as u64);
    }
}`;

const r004a = check004(unsafe_downcast, 'rewards.move');
assert('MOV-004: flags unsafe downcast', r004a.length > 0);
assert('MOV-004: rule ID correct', r004a[0].rule === 'MOV-004');
assert('MOV-004: severity MEDIUM', r004a[0].severity === 'MEDIUM');

assert('MOV-004: passes with overflow assert', check004(safe_downcast, 'rewards.move').length === 0);
assert('MOV-004: skips mul_div library function', check004(lib_downcast, 'math.move').length === 0);
assert('MOV-004: skips known-small field (duration)', check004(small_field_downcast, 'limiter.move').length === 0);
assert('MOV-004: skips #[test] function', check004(test_downcast, 'test.move').length === 0);

// ── MOV-005: unused auth result (Typus pattern) ────────────────────

import { check as check005 } from '../../../../rules/mov-005-unused-auth-result.mjs';

const unsafe_auth = `
module typus_oracle::oracle {
    public struct UpdateAuthority has key { id: UID, authority: vector<address> }
    public struct Oracle has key { id: UID, price: u64 }
    public fun update_v2(
        oracle: &mut Oracle,
        update_authority: &UpdateAuthority,
        price: u64,
        ctx: &mut TxContext
    ) {
        vector::contains(&update_authority.authority, &tx_context::sender(ctx));
        oracle.price = price;
    }
}`;

const safe_auth_assert = `
module typus_oracle::oracle {
    public struct UpdateAuthority has key { id: UID, authority: vector<address> }
    public struct Oracle has key { id: UID, price: u64 }
    public fun update_safe(
        oracle: &mut Oracle,
        update_authority: &UpdateAuthority,
        price: u64,
        ctx: &mut TxContext
    ) {
        assert!(vector::contains(&update_authority.authority, &tx_context::sender(ctx)), 0);
        oracle.price = price;
    }
}`;

const safe_auth_let = `
module example::access {
    public fun check_access(whitelist: &vector<address>, ctx: &TxContext): bool {
        let authorized = vector::contains(whitelist, &tx_context::sender(ctx));
        authorized
    }
}`;

const safe_auth_if = `
module example::access {
    public fun guarded_op(whitelist: &vector<address>, ctx: &TxContext) {
        if (vector::contains(whitelist, &tx_context::sender(ctx))) {
            do_something();
        };
    }
}`;

const test_auth = `
module example::access {
    #[test]
    public fun test_auth(whitelist: &vector<address>, ctx: &TxContext) {
        vector::contains(whitelist, &tx_context::sender(ctx));
    }
}`;

const r005a = check005(unsafe_auth, 'oracle.move');
assert('MOV-005: flags discarded vector::contains', r005a.length === 1);
assert('MOV-005: rule ID correct', r005a[0].rule === 'MOV-005');
assert('MOV-005: severity HIGH', r005a[0].severity === 'HIGH');

assert('MOV-005: passes with assert!', check005(safe_auth_assert, 'oracle.move').length === 0);
assert('MOV-005: passes with let binding', check005(safe_auth_let, 'access.move').length === 0);
assert('MOV-005: passes with if condition', check005(safe_auth_if, 'access.move').length === 0);
assert('MOV-005: skips #[test] function', check005(test_auth, 'test.move').length === 0);

// ── MOV-006: shared abort code ──────────────────────────────────────

import { check as check006 } from '../../../../rules/mov-006-shared-abort-code.mjs';

const shared_abort = `
module example::registry {
    const ENotPositive: u64 = 1;
    public fun add(r: &mut Registry, amount: u64) {
        assert!(amount > 0, ENotPositive);
    }
    public fun scale(r: &mut Registry, factor: u64) {
        assert!(factor > 0, ENotPositive);
    }
    public fun reserve(r: &mut Registry, amount: u64) {
        assert!(amount > 0, ENotPositive);
    }
}`;

const unique_abort = `
module example::registry {
    const EInvalidAmount: u64 = 1;
    const EInvalidFactor: u64 = 2;
    public fun add(r: &mut Registry, amount: u64) {
        assert!(amount > 0, EInvalidAmount);
    }
    public fun scale(r: &mut Registry, factor: u64) {
        assert!(factor > 0, EInvalidFactor);
    }
}`;

const variable_abort = `
module example::pool {
    public fun queue(proposal: &Proposal, now: u64) {
        assert!(now >= proposal.start, now);
    }
    public fun execute(proposal: &Proposal, now: u64) {
        assert!(now >= proposal.end, now);
    }
}`;

const r006a = check006(shared_abort, 'registry.move');
assert('MOV-006: flags shared abort code', r006a.length === 1);
assert('MOV-006: names 3 functions', r006a[0].message.includes('3 functions'));
assert('MOV-006: rule ID correct', r006a[0].rule === 'MOV-006');
assert('MOV-006: severity LOW', r006a[0].severity === 'LOW');

assert('MOV-006: passes with unique codes', check006(unique_abort, 'registry.move').length === 0);
assert('MOV-006: skips lowercase variable names', check006(variable_abort, 'pool.move').length === 0);

// ── MOV-011: public(package) entry bypass ────────────────────────────

import { check as check011 } from '../../../../rules/mov-011-package-entry-bypass.mjs';

const pkg_entry_unsafe = `
module example::admin {
    public(package) entry fun reset_pool(pool: &mut Pool) { }
}`;

const pkg_no_entry = `
module example::admin {
    public(package) fun internal_reset(pool: &mut Pool) { }
}`;

const public_entry_ok = `
module example::admin {
    public entry fun normal_entry(ctx: &mut TxContext) { }
}`;

assert('MOV-011: flags public(package) entry', check011(pkg_entry_unsafe, 'admin.move').length === 1);
assert('MOV-011: passes public(package) without entry', check011(pkg_no_entry, 'admin.move').length === 0);
assert('MOV-011: passes plain public entry', check011(public_entry_ok, 'admin.move').length === 0);

// ── MOV-012: sender as address parameter ─────────────────────────────

import { check as check012 } from '../../../../rules/mov-012-sender-as-address-param.mjs';

const sender_unsafe = `
module example::vault {
    public fun withdraw(sender: address, amount: u64, ctx: &mut TxContext) { }
}`;

const sender_safe_ctx = `
module example::vault {
    public fun withdraw(amount: u64, ctx: &mut TxContext) { }
}`;

const sender_safe_destination = `
module example::vault {
    public fun transfer(to: address, amount: u64) { }
}`;

assert('MOV-012: flags sender: address', check012(sender_unsafe, 'vault.move').length === 1);
assert('MOV-012: passes ctx-based auth', check012(sender_safe_ctx, 'vault.move').length === 0);
assert('MOV-012: passes to: address (destination)', check012(sender_safe_destination, 'vault.move').length === 0);

// ── MOV-008: exact-equality payment assert ───────────────────────────

import { check as check008 } from '../../../../rules/mov-008-exact-equality-assert.mjs';

const eq_unsafe = `
module example::pay {
    public fun settle(payment: u64, required: u64) {
        assert!(payment == required, 1);
    }
}`;

const eq_safe_gte = `
module example::pay {
    public fun settle(payment: u64, required: u64) {
        assert!(payment >= required, 1);
    }
}`;

const eq_safe_zero = `
module example::pay {
    public fun check(amount: u64) {
        assert!(amount == 0, 1);
    }
}`;

assert('MOV-008: flags exact equality on payment', check008(eq_unsafe, 'pay.move').length === 1);
assert('MOV-008: passes >= comparison', check008(eq_safe_gte, 'pay.move').length === 0);
assert('MOV-008: passes == 0 zero check', check008(eq_safe_zero, 'pay.move').length === 0);

// ── MOV-002 extension: bit-shift detection ───────────────────────────

const shift_unsafe = `
module example::math {
    public fun scale(value: u64, bits: u8): u64 {
        value << 32
    }
}`;

const shift_safe_cast = `
module example::math {
    public fun scale(value: u64): u128 {
        (value as u128) << 64
    }
}`;

assert('MOV-002: flags bare << shift', check002(shift_unsafe, 'math.move').some(f => f.message.includes('shift')));
assert('MOV-002: passes << with u128 cast', !check002(shift_safe_cast, 'math.move').some(f => f.message.includes('shift')));

// ── Summary ──────────────────────────────────────────────────────────

if (errs.length) {
  console.log('FAIL:');
  for (const e of errs) console.log(`  ✗ ${e}`);
  process.exit(1);
} else {
  console.log('lint-rules selftest: all checks passed');
  process.exit(0);
}
