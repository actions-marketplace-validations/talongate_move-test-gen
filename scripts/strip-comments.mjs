/**
 * Shared state machine: strips block comments and tracks whether the file
 * ended still inside one. Both exports below are thin wrappers over this,
 * so the string/line-comment-aware scanning logic exists in exactly one
 * place -- never duplicated between the two questions "what does the
 * stripped text look like" and "did a block comment ever close".
 */
function scan(text) {
  let result = '';
  let inBlock = false;
  let inString = false;
  let inLineComment = false;
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];
    if (inLineComment) {
      result += ch;
      if (ch === '\n') inLineComment = false;
      continue;
    }
    if (inBlock) {
      if (ch === '*' && next === '/') { inBlock = false; i++; result += '  '; }
      else result += (ch === '\n' ? '\n' : ' ');
      continue;
    }
    if (inString) {
      result += ch;
      if (ch === '\\') { result += (next || ''); i++; continue; }
      if (ch === quote) inString = false;
      continue;
    }
    if (ch === '/' && next === '/') { inLineComment = true; result += ch; continue; }
    if (ch === '"' || ch === '\'') { inString = true; quote = ch; result += ch; continue; }
    if (ch === '/' && next === '*') { inBlock = true; i++; result += '  '; continue; }
    result += ch;
  }
  return { result, unterminated: inBlock };
}

/**
 * Strip block comments from Move source text.
 * String- and line-comment-aware: ignores comment markers inside quoted
 * strings, and inside `//` line comments (so an apostrophe in ordinary
 * prose like "don't" cannot flip the scanner into string mode and swallow
 * every `/* *\/` block for the rest of the file).
 * Preserves line count (replaces comment content with spaces) so that
 * line numbers in findings remain correct.
 *
 * An unterminated `/*` blanks everything from there to EOF, same as
 * always -- this function's contract (a plain string) is unchanged for
 * every existing caller. Detecting that condition is
 * `hasUnterminatedBlockComment`'s job, below.
 */
export function stripBlockComments(text) {
  return scan(text).result;
}

/**
 * True if `text` contains a `/*` with no matching `*\/` before EOF.
 * A caller that scans stripped-to-blank text has no way to tell "the file
 * was clean" from "the file was unreadable and got blanked" -- this is
 * the signal that distinguishes them.
 */
export function hasUnterminatedBlockComment(text) {
  return scan(text).unterminated;
}
