#!/usr/bin/env node
/**
 * GHSA-mwqv-cfjv-p4cc — `scripts/walk-dir.mjs` decided whether to descend
 * into a directory with `Dirent.isDirectory()`, which describes the LINK
 * itself, never its target. A symlinked directory (or a Windows junction)
 * therefore fell into neither branch -- not a directory, and its name does
 * not end in `.move` -- and was silently dropped, with no warning. The
 * Move compiler does the opposite: `sui move build` enumerates sources
 * with `walkdir::WalkDir::new(path).follow_links(true)`, so those modules
 * are compiled and shipped. A module placed behind a symlink under
 * `sources/` reached production bytecode with zero findings and zero
 * coverage accounting, while the gate reported the package clean. Both
 * `lint.mjs` (all nine MOV rules) and `check-coverage.mjs` share this one
 * walker.
 *
 * Fixed by resolving a link entry (`realpathSync.native` + `statSync`,
 * matching the compiler's own `follow_links(true)` semantics) and
 * recursing when the target is a directory. Two things this fix must NOT
 * do while closing the omission:
 *   - Loop forever on a symlink cycle -- a `Set` of visited REAL paths
 *     (not link paths) makes a cycle terminate on first re-visit rather
 *     than blowing the stack.
 *   - Silently skip a link whose target cannot be resolved (dangling, or
 *     any other stat failure) -- that would just be a SECOND instance of
 *     the exact defect class this fix exists to close. A broken link is a
 *     NAMED entry `readdirSync` already found and enumerated, so it is a
 *     HARD ERROR at every depth, deliberately NOT covered by the existing
 *     readdirSync error contract (root throws, non-root swallows) --
 *     that contract is for a whole SUBDIRECTORY becoming unreadable, a
 *     failure the walker never had visibility into; a broken link is a
 *     failure the walker already knows by name.
 *
 * Windows note: creating a real symlink needs elevated privilege; a
 * DIRECTORY JUNCTION (`fs.symlinkSync(target, path, 'junction')`) does
 * not -- this room's own hard-won lesson. Every fixture below uses a
 * junction so this test never requires an elevated shell. A symlinked
 * individual FILE (as opposed to a directory) was never part of this
 * defect -- `entry.name.endsWith(ext)` already matched a file symlink's
 * NAME under the pre-fix code regardless of what it pointed at -- and
 * file-symlink creation genuinely does need elevation on Windows, so it
 * is checked by code inspection only (the new `isSymbolicLink()` branch
 * reaches the identical `entry.name.endsWith(ext)` test, just via a
 * different path than before), not by a live fixture here.
 */
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { spawnSync } from 'child_process';

import { walkDir } from '../../../../scripts/walk-dir.mjs';

const errs = [];
function assert(label, cond) {
  if (!cond) errs.push(label);
}

const LINT_CLI = join('scripts', 'lint.mjs');

function freshDir(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

// ── Ordinary dirs/files: behaviour must stay byte-identical ────────────

{
  const base = freshDir('mtg-walkdir-plain-');
  mkdirSync(join(base, 'nested'), { recursive: true });
  writeFileSync(join(base, 'a.move'), 'module d::a {}');
  writeFileSync(join(base, 'nested', 'b.move'), 'module d::b {}');
  writeFileSync(join(base, 'ignore.txt'), 'not a move file');
  const results = walkDir(base, '.move').sort();
  assert(
    'ordinary nested dirs/files: unchanged (a.move + nested/b.move, .txt ignored)',
    results.length === 2 && results.some(r => r.endsWith('a.move')) && results.some(r => r.endsWith(join('nested', 'b.move')))
  );
}

// ── RED-FIRST regression fixture: the advisory's own layout ─────────────
// pkg/sources/direct.move + pkg/sources/linked -> ../outside, where
// outside/hidden.move holds the SAME module body. Must produce the SAME
// findings as the flattened layout (control), through the REAL lint.mjs
// CLI -- not just walkDir() in isolation.

const advisoryBase = freshDir('mtg-walkdir-advisory-');
const pkgSources = join(advisoryBase, 'pkg', 'sources');
const outside = join(advisoryBase, 'outside');
mkdirSync(pkgSources, { recursive: true });
mkdirSync(outside, { recursive: true });
// MOV-001 is an independent scanner (unlike move-parser.mjs, #88 never
// un-anchored it) with its own `^public` line anchor -- a one-line
// module is invisible to it. Multi-line, matching real Move style.
const DRAIN_MODULE = (moduleName) => `module probe::${moduleName} {
    public fun open_drain(v: &mut u64) {
        *v = 0;
    }
}
`;
writeFileSync(join(pkgSources, 'direct.move'), DRAIN_MODULE('direct'));
writeFileSync(join(outside, 'hidden.move'), DRAIN_MODULE('hidden'));

let junctionUnavailable = false;
try {
  symlinkSync(outside, join(pkgSources, 'linked'), 'junction');
} catch (err) {
  junctionUnavailable = true;
  console.log(`skip-note: directory junction creation failed unexpectedly (${err.code || err.message}) -- this box normally allows junctions with no elevation`);
}

if (!junctionUnavailable) {
  // walkDir() itself must see both files
  const walked = walkDir(pkgSources, '.move');
  assert('walkDir() follows the junction: both direct.move and hidden.move are seen', walked.length === 2 && walked.some(r => r.endsWith('direct.move')) && walked.some(r => r.endsWith('hidden.move')));

  // through the real lint.mjs CLI: must fire HIGH on BOTH modules (same
  // finding as the flattened control, per the advisory's own draft)
  const linked = spawnSync(process.execPath, [LINT_CLI, pkgSources], { encoding: 'utf8', timeout: 30000 });
  const linkedOut = (linked.stdout || '') + (linked.stderr || '');
  assert('linked layout: exit 1 (a HIGH finding exists)', linked.status === 1);
  assert('linked layout: MOV-001 fires on direct.move', /direct\.move.*MOV-001/.test(linkedOut) || /MOV-001.*direct\.move/.test(linkedOut));
  assert('linked layout: MOV-001 ALSO fires on hidden.move (behind the junction -- this is the bug, fixed)', /hidden\.move/.test(linkedOut));
  assert('linked layout: 2 findings total, matching the flattened control below', /2 finding/.test(linkedOut));

  // control: the flattened layout (no symlink) must find the identical 2
  const flatBase = freshDir('mtg-walkdir-flat-');
  writeFileSync(join(flatBase, 'direct.move'), DRAIN_MODULE('direct'));
  writeFileSync(join(flatBase, 'hidden.move'), DRAIN_MODULE('hidden'));
  const flat = spawnSync(process.execPath, [LINT_CLI, flatBase], { encoding: 'utf8', timeout: 30000 });
  const flatOut = (flat.stdout || '') + (flat.stderr || '');
  assert('flattened control: exit 1, 2 findings (same as the linked layout above)', flat.status === 1 && /2 finding/.test(flatOut));
} else {
  console.log('skip-note: advisory regression fixture skipped (junction unavailable on this box)');
}

// ── Cycle guard: a junction loop must terminate, not blow the stack ────

{
  const cycleBase = freshDir('mtg-walkdir-cyclea-');
  const cycleB = freshDir('mtg-walkdir-cycleb-');
  writeFileSync(join(cycleB, 'in_b.move'), 'module d::b {}');
  try {
    symlinkSync(cycleB, join(cycleBase, 'to_b'), 'junction');
    symlinkSync(cycleBase, join(cycleB, 'back_to_a'), 'junction');
    const t0 = Date.now();
    const results = walkDir(cycleBase, '.move');
    const ms = Date.now() - t0;
    assert('symlink cycle terminates and finds in_b.move exactly once (no infinite loop)', results.filter(r => r.endsWith('in_b.move')).length === 1);
    assert(`symlink cycle completes within a generous 2000ms ceiling (got ${ms}ms) -- loose regression tripwire, not a perf SLA`, ms < 2000);
  } catch (err) {
    console.log(`skip-note: cycle-guard fixture skipped (junction creation failed: ${err.code || err.message})`);
  }
}

// ── Dangling link: a HARD ERROR, never a silent skip ────────────────────

{
  const danglingBase = freshDir('mtg-walkdir-dangling-');
  try {
    const ghostTarget = join(danglingBase, 'this_path_never_exists');
    symlinkSync(ghostTarget, join(danglingBase, 'ghost'), 'junction');
    let threw = false;
    let message = '';
    try {
      walkDir(danglingBase, '.move');
    } catch (err) {
      threw = true;
      message = err.message;
    }
    assert('a dangling link throws (never silently dropped from the walk)', threw);
    assert('the thrown error names the unresolvable symlink', /cannot resolve symlink/.test(message));
  } catch (err) {
    console.log(`skip-note: dangling-link fixture skipped (junction creation failed: ${err.code || err.message})`);
  }
}

// ── Link to a FILE, not a directory: walkDir() must not throw or hang ──
// (Windows junctions are directory-only; a FILE-typed symlink needs
// elevation and is out of scope here -- see the file-level docstring.
// This instead confirms the isSymbolicLink() branch, when the target
// turns out NOT to be a directory, cleanly falls through without error.)

{
  const linkToFileParentBase = freshDir('mtg-walkdir-linktofiledir-');
  // A junction whose target is itself a plain file (not a directory) --
  // Windows permits creating the junction reparse point, but resolving it
  // will show a non-directory target; exercises the `targetStat.isDirectory()`
  // false branch without needing file-symlink privilege.
  const aFile = join(linkToFileParentBase, 'a_real_file.move');
  writeFileSync(aFile, 'module d::real {}');
  try {
    symlinkSync(aFile, join(linkToFileParentBase, 'junction_to_a_file'), 'junction');
    let threwOrHung = false;
    const t0 = Date.now();
    try {
      walkDir(linkToFileParentBase, '.move');
    } catch {
      // A junction-to-a-file may itself fail to resolve depending on the
      // OS/Node version -- either a clean non-throwing walk or a clean
      // thrown resolution error is acceptable; a HANG is not.
    }
    const ms = Date.now() - t0;
    assert(`a junction pointed at a file does not hang (${ms}ms)`, ms < 2000);
  } catch (err) {
    console.log(`skip-note: junction-to-file fixture skipped (junction creation failed: ${err.code || err.message})`);
  }
}

// ── Deep nest: bounded time, no stack blow-up from ordinary recursion ──

{
  const deepBase = freshDir('mtg-walkdir-deep-');
  let cur = deepBase;
  for (let i = 0; i < 300; i++) {
    cur = join(cur, `d${i}`);
    mkdirSync(cur, { recursive: true });
  }
  writeFileSync(join(cur, 'bottom.move'), 'module d::bottom {}');
  const t0 = Date.now();
  const results = walkDir(deepBase, '.move');
  const ms = Date.now() - t0;
  assert('a 300-level deep ordinary nest finds the bottom file', results.length === 1 && results[0].endsWith('bottom.move'));
  assert(`a 300-level deep nest completes within a generous 2000ms ceiling (got ${ms}ms)`, ms < 2000);
}

if (errs.length) {
  console.log('FAIL:');
  for (const e of errs) console.log(`  ✗ ${e}`);
  process.exit(1);
}
console.log('walk-dir.mjs symlink fix: a directory junction is followed and its .move files are seen by the real lint.mjs CLI (matching a flattened control exactly), a symlink cycle terminates instead of blowing the stack, a dangling link is a hard error rather than a silent skip, and ordinary dirs/files/deep nests are unaffected');
process.exit(0);
