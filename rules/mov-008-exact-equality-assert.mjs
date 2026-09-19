/**
 * MOV-008: Exact-equality assert on caller-supplied payment amounts.
 *
 * `assert!(payment == required)` on a value the caller controls is a
 * denial-of-service vector: dust, rounding, or fee-on-transfer tokens
 * make exact equality impossible to hit, so every transaction aborts.
 * The safe alternative is `assert!(payment >= required)`.
 *
 * Why it matters: documented in AlphaFiTech/sui-ai-commons
 * sui-move-auditor as a known DeFi pitfall. Protocols that enforce
 * exact payment matching brick their own users the moment any amount
 * drifts by a single unit.
 *
 * Detection: assert! containing `==` where at least one operand name
 * suggests a caller-controlled payment value (amount, payment, price,
 * deposit, fee, cost, value, balance, collateral). Uses the Move parser
 * (scripts/move-parser.mjs) for function extents and pre-parsed assert
 * conditions, rather than a private line-scanning state machine -- its
 * #[test]/#[test_only] attachment is item-boundary-based (the same fix
 * MOV-002/MOV-004/MOV-011 already rely on), where this rule's own former
 * scanner cleared its test flag at exactly the wrong line (the function
 * signature immediately after an attribute on its own line) and scanned
 * every test body as production code.
 */

import { parseModule } from '../scripts/move-parser.mjs';

const RULE_ID = 'MOV-008';
const SEVERITY = 'MEDIUM';
const TITLE = 'exact-equality assert on payment amount — use >= instead';

// Payment-relevance is decided per WORD, not by substring-searching the
// whole operand text: an identifier is split on underscores (Move's own
// naming convention) and camelCase boundaries, then each resulting word
// is tested for EXACT membership in this set. `payment_amount`, `fee_bps`,
// and `priceLimit` therefore match (a word component equals a name here);
// `coffee` and `defeated` do not (no word component of theirs equals one);
// neither does a word that only shares a stem with a name, deliberately
// -- `deposited` != `deposit` -- so the set never silently widens by
// matching more than it names.
const PAYMENT_NAMES = new Set([
  'amount', 'payment', 'price', 'deposit', 'fee', 'cost', 'collateral', 'paid', 'received',
]);

function containsPaymentWord(text) {
  const words = (text.match(/[A-Za-z][A-Za-z0-9]*/g) || [])
    .flatMap((tok) => tok.split(/(?=[A-Z])/))
    .map((w) => w.toLowerCase());
  return words.some((w) => PAYMENT_NAMES.has(w));
}

/**
 * @param {string} source
 * @param {string} filename
 * @returns {Array<{rule, severity, file, line, message}>}
 */
export function check(source, filename) {
  const findings = [];
  const mod = parseModule(source);

  for (const fn of mod.functions) {
    if (fn.isTest || fn.isTestOnly) continue;
    if (!fn.body) continue;

    for (const a of fn.body.asserts) {
      const expr = a.condition;

      // check for == (not !=)
      if (!expr.includes('==') || expr.includes('!=')) continue;

      // split on == and check if either side has a payment-related name
      const parts = expr.split('==');
      if (parts.length < 2) continue;

      const left = parts[0].trim();
      const right = parts[1].trim();

      if (containsPaymentWord(left) || containsPaymentWord(right)) {
        // exclude version/type checks like assert!(version == CURRENT_VERSION)
        if (/version|type|kind|status|state|flag|mode|role/i.test(left + right)) continue;
        // exclude zero checks like assert!(amount == 0)
        if (/^0\b/.test(right.trim()) || /^0\b/.test(left.trim())) continue;

        findings.push({
          rule: RULE_ID,
          severity: SEVERITY,
          file: filename,
          line: a.line,
          message: `${TITLE}: \`${fn.name || '(unknown)'}\` asserts exact equality on a payment value — an off-by-one dust amount aborts the entire transaction`,
        });
      }
    }
  }

  return findings;
}

export const meta = { id: RULE_ID, severity: SEVERITY, title: TITLE };
