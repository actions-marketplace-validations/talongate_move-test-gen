/**
 * MOV-013: `#[spec_only]` function ships in production bytecode.
 *
 * `#[spec_only]` is a sui-prover marker, NOT a compiler attribute. The Move
 * compiler does not strip a function carrying it -- it emits
 * `warning[W02018]: unknown attribute` and compiles the function normally,
 * so a `#[spec_only] public fun` (or `public(package)`/`public(friend)`/
 * `entry`) ships in the built module exactly like any other function.
 * `#[ext(spec_only)]` -- the compiler's OWN suggested wrapped form for a
 * custom attribute -- is caught the same way; wrapping it in `ext` does not
 * make the compiler strip it either.
 *
 * Why it matters: a function its author believes is verification-only (a
 * getter over private state, a setter that skips the capability check
 * "because the prover needs it") passes every other rule in silence, since
 * nothing else in this tool recognizes the attribute. A public Sui lending
 * contract shipped `#[spec_only]` getters as an unauthenticated backdoor
 * this way (~$300K, 2026-08) -- the author's own tooling docs described the
 * attribute as "not included in regular compilation".
 *
 * What this does NOT flag: a PRIVATE `#[spec_only] fun` (nothing external
 * can reach it regardless of what the compiler keeps) and `#[test_only]`
 * (the compiler genuinely does strip that one).
 *
 * DELIBERATELY an independent scanner, not a `scripts/move-parser.mjs`
 * consumer, despite that file already walking `#[test_only]`/`#[test]`
 * attributes per function (the obvious reuse target). Measured, not
 * assumed: at this fork's current HEAD, `parseModule()`'s own internal
 * `parseBody()` still carries the unbounded `(\w+)...(\w+)` multiplication/
 * division/calls regexes the sibling `talongate/move-test-gen` room fixed
 * in a separate branch -- that fix has not landed on THIS fork, and this
 * unit's own rails do not authorize touching `move-parser.mjs` to bring it
 * over. Calling `parseModule()` here measured 5583ms on a 40,000-character
 * identifier (confirmed via a standalone timing check against
 * `parseModule()` alone, isolating the cost from this file's own code) --
 * consuming it would have made THIS rule inherit a live O(n^2) DoS on
 * commit, the exact defect class this unit's own proof requirements bar it
 * from introducing. So this file re-derives only the narrow slice it
 * actually needs (visibility + attribute attachment + a body's brace
 * boundary), independently and fully bounded, rather than the wide surface
 * `parseModule()` computes for every rule regardless of need.
 */

import { stripBlockComments } from '../scripts/strip-comments.mjs';

const RULE_ID = 'MOV-013';
const SEVERITY = 'HIGH';
const TITLE = '#[spec_only] function ships in production bytecode';

// Matches `#[spec_only]` or `#[ext(spec_only)]` -- as a WHOLE attribute
// line (tested against a comment-stripped, trimmed line with nothing else
// on it) or as a PREFIX directly before same-line content (`#[spec_only]
// public fun leak_secret(...)`). Not anchored at the end, so both shapes
// are one regex, same idiom move-parser.mjs uses for its own
// `#[test_only]`/`#[test]` attribute matching. No `\w+` in this one --
// pure literal alternation plus `\s*`, so it carries no backtracking risk
// on its own regardless of what follows on the line.
const SPEC_ONLY_RE = /^#\[\s*(?:spec_only|ext\s*\(\s*spec_only\s*\))\s*\]/;

// A line that is ONLY visibility/entry modifier tokens, no `fun` yet -- the
// leading fragment of a wrapped `public(package)\nentry fun f(...)`
// declaration. Mirrors move-parser.mjs's own (non-exported) BARE_VIS_RE --
// an independent copy of the identical shape, same as MOV-003's own copy
// of MOV-002's division regex elsewhere in this room. No `\w+` here either.
const BARE_VIS_RE = /^(?:public\s*\(\s*(?:package|friend)\s*\)|public|entry)(?:\s+(?:public\s*\(\s*(?:package|friend)\s*\)|public|entry))*$/;

// A function signature's leading visibility, then `fun NAME`, then the
// opening `(` of its parameter list. `\w{1,128}` (not bare `\w+`) bounds
// the name capture -- see the file-level docstring for the measured
// reason every `\w+` in this file is bounded, not just this one. The
// visibility alternatives are literal words, never `\w+`, so they carry
// no backtracking risk regardless of length.
const FN_SIG_RE = /(public\s+entry\s+|public\(package\)\s+entry\s+|public\(friend\)\s+entry\s+|public\(friend\)\s+|public\(package\)\s+|public\s+|entry\s+)?fun\s+(\w{1,128})/;

// A field READ or WRITE, distinguished from a Move-2024 dot-call
// (`c.withdraw(10)`, which desugars to a function call, not a field touch)
// by whether `(` follows immediately. `\w{1,128}` bounds backtracking the
// same way and for the same measured reason as FN_SIG_RE above. `\w+\.\w+`
// requires an actual `.` -- a qualified path (`sui::object::new`) uses
// `::` and never matches. Move has no floating-point literals, so a
// numeric `1.5` is not a real ambiguity here either.
const FIELD_WRITE_RE = /\b\w{1,128}\.\w{1,128}\s*=(?!=)/;
const FIELD_READ_RE = /\b\w{1,128}\.\w{1,128}\b(?!\s*\()/;

/**
 * @param {string} source
 * @param {string} filename
 * @returns {Array<{rule, severity, file, line, message}>}
 */
export function check(source, filename) {
  const findings = [];
  const lines = stripBlockComments(source).split('\n');

  // An attribute belongs to the item it is directly attached to, never to
  // whatever function happens to follow within N lines -- this room has
  // fixed that exact distance-window leak five times. `pendingSpecOnly`
  // carries a `#[spec_only]`/`#[ext(spec_only)]` line forward across
  // blank lines, `//` comments, stacked OTHER attributes, and a bare
  // visibility/entry fragment (a wrapped declaration's own prefix -- not
  // a different item), and is cleared the instant a real item is reached
  // that ISN'T the function it decorates.
  let pendingSpecOnly = false;
  let pendingVisPrefix = '';

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed === '' || trimmed.startsWith('//')) continue;

    const codeOnly = trimmed.replace(/\/\/.*$/, '').trim();

    const attrOnly = codeOnly.match(/^#\[([^\]]*)\]$/);
    if (attrOnly) {
      if (SPEC_ONLY_RE.test(codeOnly)) pendingSpecOnly = true;
      // any other attribute (#[allow(...)], #[expected_failure(...)]) is
      // just another line stacked above the same item -- leave the flag
      // as-is either way.
      continue;
    }

    if (!/\bfun\b/.test(codeOnly) && BARE_VIS_RE.test(codeOnly)) {
      pendingVisPrefix = pendingVisPrefix ? `${pendingVisPrefix} ${codeOnly}` : codeOnly;
      continue;
    }

    // A same-line attribute directly before `fun` on the fun-line itself
    // (`#[spec_only] public fun leak_secret(...)`) also sets the flag --
    // checked here, on the item's own line, rather than only via the
    // whole-line attrOnly branch above.
    const specOnlyHere = pendingSpecOnly || SPEC_ONLY_RE.test(codeOnly);

    const sigLine = pendingVisPrefix ? `${pendingVisPrefix} ${codeOnly}` : codeOnly;
    const sig = sigLine.match(FN_SIG_RE);
    pendingVisPrefix = '';

    if (sig) {
      pendingSpecOnly = false;

      if (specOnlyHere) {
        const visRaw = (sig[1] || '').trim();
        const visibility = classifyVisibility(visRaw);
        const name = sig[2];

        if (visibility !== 'private') {
          const endIdx = findFunctionEndLine(lines, i);
          const touchesFields = functionTouchesFields(lines, i, endIdx);
          const severity = touchesFields ? 'HIGH' : 'MEDIUM';

          findings.push({
            rule: RULE_ID,
            severity,
            file: filename,
            line: i + 1,
            message: `${TITLE}: \`${name}\` (${visibility}) is marked #[spec_only] -- the Move compiler does NOT strip this attribute (it emits "unknown attribute" and compiles the function normally), so it ships in production bytecode. Move it behind #[test_only], make it private, or gate it with an explicit auth/capability check.`,
          });
        }
      }
      continue;
    }

    // Reached a different item (use/struct/const, or any other code) --
    // any pending attribute belonged to THIS item, not to whatever
    // function comes later.
    pendingSpecOnly = false;
  }

  return findings;
}

function classifyVisibility(visRaw) {
  if (visRaw === '') return 'private';
  if (visRaw.includes('friend') && visRaw.includes('entry')) return 'public(friend) entry';
  if (visRaw.includes('package') && visRaw.includes('entry')) return 'public(package) entry';
  if (visRaw.includes('friend')) return 'public(friend)';
  if (visRaw.includes('entry') && visRaw.includes('public')) return 'public entry';
  if (visRaw.includes('entry')) return 'entry';
  return 'public';
}

/**
 * 0-indexed line of the closing `}` that matches this function's own
 * opening `{`, starting the brace-depth walk at the function's own
 * signature line. Bounded by construction -- a single forward pass over
 * the lines, one pass over the characters of each, never revisited.
 */
function findFunctionEndLine(lines, startIdx) {
  let depth = 0;
  let seenOpen = false;
  for (let i = startIdx; i < lines.length; i++) {
    for (const ch of lines[i]) {
      if (ch === '{') { depth++; seenOpen = true; }
      if (ch === '}') {
        depth--;
        if (seenOpen && depth === 0) return i;
      }
    }
  }
  return lines.length - 1; // unterminated body -- scan to EOF rather than crash
}

function functionTouchesFields(lines, startIdx, endIdx) {
  for (let i = startIdx; i <= endIdx; i++) {
    const codeOnly = (lines[i] || '').replace(/\/\/.*$/, '');
    if (FIELD_WRITE_RE.test(codeOnly) || FIELD_READ_RE.test(codeOnly)) return true;
  }
  return false;
}

export const meta = { id: RULE_ID, severity: SEVERITY, title: TITLE };
