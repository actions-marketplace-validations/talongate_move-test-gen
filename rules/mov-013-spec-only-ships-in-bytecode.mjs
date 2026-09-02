/**
 * MOV-013: `#[spec_only]` function ships in production bytecode.
 *
 * `#[spec_only]` is a sui-prover marker, NOT a compiler attribute. The Move
 * compiler does not strip a function carrying it — it emits
 * `warning[W02018]: unknown attribute` and compiles the function normally,
 * so a `#[spec_only] public fun` (or `public(package)`/`public(friend)`/
 * `entry`) ships in the built module exactly like any other function.
 * `#[ext(spec_only)]` — the compiler's OWN suggested wrapped form for a
 * custom attribute — is caught the same way; wrapping it in `ext` does not
 * make the compiler strip it either. Neither form has to stand alone: a
 * comma-separated attribute list (`#[test_only, spec_only]`) or a second
 * `#[...]` group stacked on the same line (`#[allow(lint(x))] #[spec_only]
 * public fun f(...)`) is idiomatic Move (this repo's own tests write
 * `#[test, expected_failure(abort_code = ...)]`), and `spec_only`/
 * `ext(spec_only)` is treated as a MEMBER of whichever group it sits in,
 * never only as a group's entire, sole content.
 *
 * Why it matters: a function its author believes is verification-only (a
 * getter over private state, a setter that skips the capability check
 * "because the prover needs it") passes every other rule in silence, since
 * nothing else in this tool recognizes the attribute. A public Sui lending
 * contract shipped `#[spec_only]` getters as an unauthenticated backdoor
 * this way (~$300K, 2026-08) — the author's own tooling docs described the
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
 * in a separate branch — that fix has not landed on THIS fork, and this
 * unit's own rails do not authorize touching `move-parser.mjs` to bring it
 * over. Calling `parseModule()` here measured 5583ms on a 40,000-character
 * identifier (confirmed via a standalone timing check against
 * `parseModule()` alone, isolating the cost from this file's own code) —
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

// A single `#[...]` attribute GROUP's content matches this when it is
// EXACTLY `spec_only` or `ext(spec_only)` — used only after the content has
// already been split on top-level commas (see splitAttrMembers below), so
// this never has to itself parse a list. No `\w+` here — pure literal
// alternation plus `\s*`, so it carries no backtracking risk regardless of
// what the member's own text is.
const SPEC_ONLY_MEMBER_RE = /^(?:spec_only|ext\s*\(\s*spec_only\s*\))$/;

// A line whose ENTIRE (trimmed, comment-stripped) content is one or more
// `#[...]` attribute groups, nothing else — the leading fragment of a
// declaration whose attributes sit on their own line(s), single group
// (`#[spec_only]`) or several stacked on one physical line
// (`#[allow(lint(x))] #[spec_only]`). Bounded: each `[^\]]*` is a single,
// non-ambiguous quantifier terminated by a required literal `]` — no two
// unbounded quantifiers ever compete over the same characters, so this is
// linear in line length regardless of how many groups repeat.
const ATTR_ONLY_LINE_RE = /^(?:#\[[^\]]*\]\s*)+$/;

// A line that is ONLY visibility/entry modifier tokens, no `fun` yet — the
// leading fragment of a wrapped `public(package)\nentry fun f(...)`
// declaration. Mirrors move-parser.mjs's own (non-exported) BARE_VIS_RE —
// an independent copy of the identical shape, same as MOV-003's own copy
// of MOV-002's division regex elsewhere in this room. No `\w+` here either.
const BARE_VIS_RE = /^(?:public\s*\(\s*(?:package|friend)\s*\)|public|entry)(?:\s+(?:public\s*\(\s*(?:package|friend)\s*\)|public|entry))*$/;

// A function signature's leading visibility, then `fun NAME`, then the
// opening `(` of its parameter list. `\w{1,128}` (not bare `\w+`) bounds
// the name capture — see the file-level docstring for the measured
// reason every `\w+` in this file is bounded, not just this one. The
// visibility alternatives are literal words, never `\w+`, so they carry
// no backtracking risk regardless of length.
const FN_SIG_RE = /(public\s+entry\s+|public\(package\)\s+entry\s+|public\(friend\)\s+entry\s+|public\(friend\)\s+|public\(package\)\s+|public\s+|entry\s+)?fun\s+(\w{1,128})/;

// A field READ or WRITE, distinguished from a Move-2024 dot-call
// (`c.withdraw(10)`, which desugars to a function call, not a field touch)
// by whether `(` follows immediately. `\w{1,128}` bounds backtracking the
// same way and for the same measured reason as FN_SIG_RE above. `\w+\.\w+`
// requires an actual `.` — a qualified path (`sui::object::new`) uses
// `::` and never matches. Move has no floating-point literals, so a
// numeric `1.5` is not a real ambiguity here either.
const FIELD_WRITE_RE = /\b\w{1,128}\.\w{1,128}\s*=(?!=)/;
const FIELD_READ_RE = /\b\w{1,128}\.\w{1,128}\b(?!\s*\()/;

// A pathological input can carry a function whose braces never balance
// (this room's own #88 established the linter runs on source that need
// not compile). Uncapped, scanning such a body from its own start to EOF
// is O(remaining file) — and INSPECT measured that N such functions in one
// file cost O(N x lines): 50/166/669/2576ms at N=500/1000/2000/4000, ~4x
// per doubling. A first attempt at bounding this with a 5000-line cap
// (comfortably larger than any real Move function body, chosen without
// checking it against THIS shape) was re-measured and found still
// quadratic-shaped and slower at every size than the uncapped original
// (167/710/2594/7269ms at the same four N) — 5000 x N is still large
// enough, at these N, to dominate. Re-measured at 200 (still generous for
// any real Move function body): 51/90/197/385ms, a clean ~2x per doubling
// — linear, not quadratic. The lesson: a cap bounds each CALL to a
// constant, but the constant still has to be checked against the N the
// threat model cares about, not chosen by "looks generous enough" alone.
const MAX_BODY_SCAN_LINES = 200;

/**
 * @param {string} source
 * @param {string} filename
 * @returns {Array<{rule, severity, file, line, message}>}
 */
export function check(source, filename) {
  const findings = [];
  const lines = stripBlockComments(source).split('\n');

  // An attribute belongs to the item it is directly attached to, never to
  // whatever function happens to follow within N lines — this room has
  // fixed that exact distance-window leak five times. `pendingSpecOnly`
  // carries a `#[spec_only]`/`#[ext(spec_only)]` line forward across
  // blank lines, `//` comments, stacked OTHER attributes, and a bare
  // visibility/entry fragment (a wrapped declaration's own prefix — not
  // a different item), and is cleared the instant a real item is reached
  // that ISN'T the function it decorates.
  let pendingSpecOnly = false;
  let pendingVisPrefix = '';

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed === '' || trimmed.startsWith('//')) continue;

    const codeOnly = trimmed.replace(/\/\/.*$/, '').trim();

    if (ATTR_ONLY_LINE_RE.test(codeOnly)) {
      if (lineHasSpecOnlyAttr(codeOnly)) pendingSpecOnly = true;
      // any other attribute (#[allow(...)], #[expected_failure(...)]), or
      // a spec_only-free member of a list on this line, is just another
      // line stacked above the same item — leave the flag as-is either
      // way if this line itself doesn't carry spec_only.
      continue;
    }

    if (!/\bfun\b/.test(codeOnly) && BARE_VIS_RE.test(codeOnly)) {
      pendingVisPrefix = pendingVisPrefix ? `${pendingVisPrefix} ${codeOnly}` : codeOnly;
      continue;
    }

    // A same-line attribute directly before `fun` on the fun-line itself
    // (`#[spec_only] public fun leak_secret(...)`, or several stacked
    // groups, e.g. `#[allow(lint(x))] #[spec_only] public fun f(...)`)
    // also sets the flag. Scanned only over the PREFIX before the `fun`
    // keyword's own position — never the whole line — so a single-line
    // function body containing attribute-shaped text (a byte string like
    // `b"#[spec_only]"`) after `fun` can never be misread as a real
    // attribute on this item.
    const funIdx = codeOnly.search(/\bfun\b/);
    const attrPrefix = funIdx >= 0 ? codeOnly.slice(0, funIdx) : codeOnly;
    const specOnlyHere = pendingSpecOnly || lineHasSpecOnlyAttr(attrPrefix);

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
          const { touchesFields } = scanFunctionBody(lines, i);
          const severity = touchesFields ? 'HIGH' : 'MEDIUM';

          findings.push({
            rule: RULE_ID,
            severity,
            file: filename,
            line: i + 1,
            message: `${TITLE}: \`${name}\` (${visibility}) is marked #[spec_only] — the Move compiler does NOT strip this attribute (it emits "unknown attribute" and compiles the function normally), so it ships in production bytecode. Move it behind #[test_only], make it private, or gate it with an explicit auth/capability check.`,
          });
        }
      }
      continue;
    }

    // Reached a different item (use/struct/const, or any other code) —
    // any pending attribute belonged to THIS item, not to whatever
    // function comes later.
    pendingSpecOnly = false;
  }

  return findings;
}

// Splits one `#[...]` group's INNER content on top-level commas, so a
// multi-member list (`test_only, spec_only`) yields separate members while
// a single member carrying its own parens (`expected_failure(abort_code =
// 1, location = Self)`) is not itself split on the comma inside those
// parens. Bounded: one linear pass over the content, tracking paren depth.
function splitAttrMembers(content) {
  const members = [];
  let depth = 0;
  let cur = '';
  for (const ch of content) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      members.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim() !== '') members.push(cur.trim());
  return members;
}

// True if ANY `#[...]` group anywhere in `text` contains `spec_only` or
// `ext(spec_only)` as one of its (possibly several) comma-separated
// members — not only as a group's entire, sole content, and not only in a
// LEADING group (`#[allow(lint(x))] #[spec_only]` stacks two groups on one
// physical line; both are scanned). `matchAll` + `[^\]]*` is bounded the
// same way ATTR_ONLY_LINE_RE is — no unbounded quantifier competes with
// another over the same span.
function lineHasSpecOnlyAttr(text) {
  for (const m of text.matchAll(/#\[([^\]]*)\]/g)) {
    for (const member of splitAttrMembers(m[1])) {
      if (SPEC_ONLY_MEMBER_RE.test(member)) return true;
    }
  }
  return false;
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
 * One bounded pass from a function's own signature line: tracks brace
 * depth to find its closing `}` AND checks each line for a field
 * read/write in the SAME walk (folded into one pass rather than two
 * separate full-range scans over the same lines). Capped at
 * MAX_BODY_SCAN_LINES — see that constant's own comment for the measured
 * reason: an unterminated body no longer costs O(remaining file), only a
 * constant, so N of them in one file cost O(N), not O(N x lines).
 * @returns {{ endIdx: number, touchesFields: boolean }}
 */
function scanFunctionBody(lines, startIdx) {
  let depth = 0;
  let seenOpen = false;
  let touchesFields = false;
  const limit = Math.min(lines.length, startIdx + MAX_BODY_SCAN_LINES);

  for (let i = startIdx; i < limit; i++) {
    const codeOnly = (lines[i] || '').replace(/\/\/.*$/, '');
    if (!touchesFields && (FIELD_WRITE_RE.test(codeOnly) || FIELD_READ_RE.test(codeOnly))) {
      touchesFields = true;
    }
    for (const ch of lines[i]) {
      if (ch === '{') { depth++; seenOpen = true; }
      if (ch === '}') {
        depth--;
        if (seenOpen && depth === 0) return { endIdx: i, touchesFields };
      }
    }
  }
  // Unterminated within the cap — whatever was seen up to the bound
  // stands; the scan stops rather than continuing unbounded.
  return { endIdx: limit - 1, touchesFields };
}

export const meta = { id: RULE_ID, severity: SEVERITY, title: TITLE };
