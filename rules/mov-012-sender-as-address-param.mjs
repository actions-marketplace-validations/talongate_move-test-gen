/**
 * MOV-012: Sender identity taken as an address parameter instead of ctx.
 *
 * A function that accepts a caller/sender/owner identity as a plain
 * `address` parameter trusts the caller to tell the truth about who
 * they are. Any PTB can pass any address — the parameter is spoofable.
 * The safe alternative is `tx_context::sender(ctx)` inside the function.
 *
 * Why it matters: if `public fun withdraw(sender: address, ...)` checks
 * `assert!(sender == vault.owner)`, an attacker simply passes the real
 * owner's address and bypasses the check entirely. Documented in
 * AlphaFiTech/sui-ai-commons sui-move-auditor as a Sui-native pitfall.
 *
 * Detection: any public/entry function with a parameter whose name
 * CONTAINS a word suggesting caller identity (sender, caller, user, owner,
 * admin, signer, authority, operator, from -- matched per underscore/
 * camelCase-split word, not only as the whole bare name, so
 * `sender_address`/`senderAddress` fire exactly like `sender`) AND whose
 * type is bare `address` -- narrowed to only where the finding is
 * actionable:
 *
 * 1. The function must take a `TxContext` param. The rule's own
 *    prescribed fix, `tx_context::sender(ctx)`, needs one; a function
 *    with no TxContext cannot apply it, so a finding there is not
 *    actionable. This also correctly excludes a pure helper like
 *    `verify(root, proof, amount, sender: address)`, a Merkle-leaf
 *    check where `sender` is hashed INTO the leaf and validated against
 *    the root -- passing someone else's address there proves only
 *    their membership and grants the caller nothing.
 * 2. `recipient` is not in the identity-name list. A destination names
 *    where value is going -- a target the caller is entitled to choose
 *    -- not an assertion about who the caller is, unlike a claimed
 *    SOURCE (`from`), which stays spoofable in the way a chosen
 *    destination is not.
 *
 * Measured false positives this closes, all three from SuiTears
 * (eval/scenarios/08-suitears-oracle, 09-suitears-farm): airdrop.move's
 * and linear_vesting_airdrop.move's `has_account_claimed(..., user:
 * address): bool`, read-only views where querying another address is
 * the intended use; airdrop_utils.move's `verify(..., sender: address):
 * u256`, the Merkle-leaf helper above -- none of the three takes a
 * TxContext at all.
 */

const RULE_ID = 'MOV-012';
const SEVERITY = 'HIGH';
const TITLE = 'sender identity taken as spoofable address parameter';

// Identity-relevance is decided per WORD, not by exact-matching the whole
// parameter name: a name is split on underscores (Move's own naming
// convention) and camelCase boundaries, then each resulting word is
// tested for EXACT membership in this set -- the same shape #85 fixed for
// MOV-008's payment names, applied here to identity names (this room's
// own established approach for this exact defect family, reused rather
// than re-invented). `sender_address`, `caller_addr`, `owner_account`,
// `admin_id`, `the_sender`, and `senderAddress` therefore all match (a
// word component equals a name here); `recipient` does NOT (no word
// component of "recipient" equals a name -- the exact set membership
// this narrowing depends on is unchanged, so #86's exclusion survives
// unmodified); neither does a word that only shares a stem with a name,
// deliberately -- "authorized" != "authority" -- so the set never
// silently widens beyond what it names.
const IDENTITY_NAMES = new Set([
  'sender', 'caller', 'user', 'owner', 'admin', 'signer', 'authority', 'operator', 'from',
]);

// `[A-Za-z][A-Za-z0-9]*` is a single, unambiguous quantifier per match --
// each starting position either extends maximally or fails immediately,
// with no competing quantifier to backtrack against -- so a global scan
// over a name of any length is linear, the same proven-safe shape #85
// already shipped for this exact tokenization job.
function containsIdentityWord(text) {
  const words = (text.match(/[A-Za-z][A-Za-z0-9]*/g) || [])
    .flatMap((tok) => tok.split(/(?=[A-Z])/))
    .map((w) => w.toLowerCase());
  return words.some((w) => IDENTITY_NAMES.has(w));
}

/**
 * @param {string} source — file content
 * @param {string} filename
 * @returns {Array<{rule, severity, file, line, message}>}
 */
export function check(source, filename) {
  const findings = [];
  const lines = source.split('\n');

  let testOnlyNext = false;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();

    if (trimmed.startsWith('//')) continue;

    if (/#\[test_only\]/.test(trimmed)) {
      testOnlyNext = true;
      const afterAttr = trimmed.replace(/^#\[test_only\]\s*/, '');
      if (/\b(fun|use|struct|const|entry)\b/.test(afterAttr)) testOnlyNext = false;
      continue;
    }

    const isTestOnly = testOnlyNext;
    if (testOnlyNext && /\b(fun|use|struct|const|entry)\b/.test(trimmed)) testOnlyNext = false;

    // match public/entry function declarations
    const fnMatch = trimmed.match(/^public(?:\s*\((?:package|friend)\))?\s+(?:entry\s+)?fun\s+(\w+)/);
    const entryMatch = !fnMatch && trimmed.match(/^entry\s+fun\s+(\w+)/);
    const match = fnMatch || entryMatch;
    if (!match) continue;
    if (isTestOnly) continue;

    const name = match[1];
    if (name === 'init' || name.includes('testing') || name.includes('destroy')) continue;
    if (name.startsWith('test_') || name.endsWith('_test')) continue;

    // collect full parameter string (may span multiple lines)
    let paramStr = '';
    let depth = 0;
    let started = false;
    for (let j = i; j < Math.min(i + 10, lines.length); j++) {
      for (const ch of lines[j]) {
        if (ch === '(') { depth++; started = true; }
        if (started && depth > 0) paramStr += ch;
        if (ch === ')') { depth--; if (started && depth === 0) break; }
      }
      if (started && depth === 0) break;
    }
    paramStr = paramStr.slice(1); // remove leading (

    // parse each parameter. The type group captures a `::`-qualified path
    // (sui::tx_context::TxContext) whole, then resolves to its LAST segment
    // -- never a substring test, which would re-admit MyTxContextWrapper.
    const params = paramStr.split(',').map(p => p.trim()).filter(Boolean)
      .map(p => p.match(/(\w+)\s*:\s*(&mut\s+|&)?\s*([\w:]+)/))
      .filter(Boolean)
      .map(m => ({ name: m[1], type: m[3].split('::').pop() }));

    // No TxContext, no finding: the rule's own prescribed fix,
    // tx_context::sender(ctx), needs one to call. A function with no
    // TxContext parameter cannot apply it -- see the docstring above.
    const hasCtx = params.some(p => p.type === 'TxContext');
    if (!hasCtx) continue;

    for (const { name: paramName, type: paramType } of params) {
      if (containsIdentityWord(paramName) && paramType === 'address') {
        findings.push({
          rule: RULE_ID,
          severity: SEVERITY,
          file: filename,
          line: i + 1,
          message: `${TITLE}: \`${name}\` takes \`${paramName}: address\` — use \`tx_context::sender(ctx)\` instead; a PTB caller can pass any address`,
        });
      }
    }
  }

  return findings;
}

export const meta = { id: RULE_ID, severity: SEVERITY, title: TITLE };
