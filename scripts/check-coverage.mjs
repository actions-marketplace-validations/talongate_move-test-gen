#!/usr/bin/env node

import { stripBlockComments } from "./strip-comments.mjs";

/**
 * check-coverage.mjs
 *
 * Scans a Sui Move package and reports:
 *   1. Every assert!/abort in source modules
 *   2. Every #[expected_failure] test
 *   3. Unpaired asserts (no matching expected_failure test)
 *   4. (Optional) mutation results if --mutate flag is passed
 *
 * Usage:
 *   node check-coverage.mjs <sources-dir> <tests-dir>
 *   node check-coverage.mjs <sources-dir> <tests-dir> --mutate
 *   node check-coverage.mjs <sources-dir> <tests-dir> --lint
 *   node check-coverage.mjs <sources-dir> <tests-dir> --testability
 *   node check-coverage.mjs <sources-dir> <tests-dir> --scope fund.move,oracle.move
 */

import { readFileSync, readdirSync, writeFileSync, mkdtempSync, cpSync, rmSync } from 'fs';
import { join, relative, resolve } from 'path';
import { execSync } from 'child_process';
import { tmpdir } from 'os';
import { identifyProbeCandidates, finalizeEvidence } from './classify.mjs';
import { filterByScope } from './scope-filter.mjs';
import { walkDir } from './walk-dir.mjs';

// ── helpers ──────────────────────────────────────────────────────────
function stripComment(line) {
  // Remove trailing // comment, but not inside string literals
  let inString = false;
  let quote = null;
  for (let i = 0; i < line.length - 1; i++) {
    const ch = line[i];
    if (inString) {
      if (ch === '\\') { i++; continue; } // skip escaped char
      if (ch === quote) inString = false;
    } else {
      if (ch === '"' || ch === '\'') { inString = true; quote = ch; }
      if (ch === '/' && line[i + 1] === '/' && !inString) return line.slice(0, i).trim();
    }
  }
  return line.trim();
}

function joinMultiline(lines, startIdx) {
  // Join lines until parentheses balance, respecting string literals
  let result = '';
  let depth = 0;
  let started = false;
  for (let i = startIdx; i < lines.length; i++) {
    const clean = stripComment(lines[i]);
    result += ' ' + clean;
    let inStr = false;
    let q = null;
    for (let j = 0; j < clean.length; j++) {
      const ch = clean[j];
      if (inStr) {
        if (ch === '\\') { j++; continue; }
        if (ch === q) inStr = false;
      } else {
        if (ch === '"' || ch === "\'") { inStr = true; q = ch; }
        if (ch === '(') { depth++; started = true; }
        if (ch === ')') depth--;
      }
    }
    if (started && depth <= 0) break;
  }
  return result.trim();
}

function extractAsserts(filePath) {
  const content = stripBlockComments(readFileSync(filePath, 'utf8'));
  const lines = content.split('\n');
  const asserts = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // skip full-line comments
    if (line.startsWith('//')) continue;

    const code = stripComment(line);

    // detect assert! start — may span multiple lines
    if (/assert!\s*\(/.test(code)) {
      const full = joinMultiline(lines, i);
      // tolerate a trailing comma and a parenthesised code - both valid Move,
      // both previously dropped on the floor
      const assertMatch = full.match(/assert!\s*\(.*,\s*\(?\s*(\w+)\s*\)?\s*,?\s*\)/);
      if (!assertMatch) {
        // An assert! we can SEE but cannot READ is not an absent assert.
        // Discarding it removed it from both sides of the ratio, so a file of
        // unreadable asserts scored 100%.
        asserts.push({
          file: filePath, line: i + 1, code: null, text: line, type: 'unparsed',
        });
      }
      if (assertMatch) {
        asserts.push({
          file: filePath,
          line: i + 1,
          code: assertMatch[1],
          text: line,
          type: 'assert',
        });
      }
    }

    // abort ERROR_CODE — handle module-qualified (take last segment after ::)
    const abortMatch = code.match(/\babort\s+(?:[\w:]*::)?(\w+)\b/);
    if (abortMatch) {
      asserts.push({
        file: filePath,
        line: i + 1,
        code: abortMatch[1],
        text: line,
        type: 'abort',
      });
    }
  }

  return asserts;
}

function extractExpectedFailures(filePath) {
  const content = stripBlockComments(readFileSync(filePath, 'utf8'));
  const lines = content.split('\n');
  const failures = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // skip commented-out test annotations
    if (line.startsWith('//')) continue;
    const src = stripComment(line);

    // #[expected_failure(abort_code = module::ERROR_CODE)] or with location=
    // Match abort_code value, stop at comma or closing paren
    const efMatch = src.match(/expected_failure\s*\(\s*abort_code\s*=\s*[\w:]*?(\w+)\s*[,)]/);
    if (efMatch) {
      let fnName = '?';
      for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
        const fnMatch = lines[j].match(/fun\s+(\w+)/);
        if (fnMatch) { fnName = fnMatch[1]; break; }
      }

      failures.push({
        file: filePath,
        line: i + 1,
        code: efMatch[1],
        fnName,
        text: line,
        scoped: true,
      });
    }

    // expected_failure without abort_code (bare, arithmetic_error, out_of_gas, etc.)
    if (/^\#\[.*expected_failure/.test(src) && !efMatch) {
      let fnName = '?';
      for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
        const fnMatch = lines[j].match(/fun\s+(\w+)/);
        if (fnMatch) { fnName = fnMatch[1]; break; }
      }

      failures.push({
        file: filePath,
        line: i + 1,
        code: null,
        fnName,
        text: line,
        scoped: false,
      });
    }
  }

  return failures;
}

// ── mutation testing ─────────────────────────────────────────────────

const MUTATIONS = [
  {
    name: 'flip-lt',
    desc: 'Flip < to >=',
    // \s+ (not \s*) so generics like Vector<Coin> are never matched
    pattern: /(\w+)\s+<\s+(\w+)/,
    replace: (m, a, b) => `${a} >= ${b}`,
  },
  {
    name: 'flip-gt',
    desc: 'Flip > to <=',
    pattern: /(\w+)\s+>\s+(\w+)/,
    replace: (m, a, b) => `${a} <= ${b}`,
  },
  {
    name: 'flip-lte',
    desc: 'Flip <= to >',
    pattern: /(\w+)\s*<=\s*(\w+)/,
    replace: (m, a, b) => `${a} > ${b}`,
  },
  {
    name: 'flip-gte',
    desc: 'Flip >= to <',
    pattern: /(\w+)\s*>=\s*(\w+)/,
    replace: (m, a, b) => `${a} < ${b}`,
  },
  {
    name: 'flip-eq',
    desc: 'Flip == to !=',
    pattern: /(\w+)\s*==\s*(\w+)/,
    replace: (m, a, b) => `${a} != ${b}`,
  },
  {
    name: 'flip-neq',
    desc: 'Flip != to ==',
    pattern: /(\w+)\s*!=\s*(\w+)/,
    replace: (m, a, b) => `${a} == ${b}`,
  },
  {
    name: 'drop-assert',
    desc: 'Comment out an assert!',
    pattern: /^(\s*)(assert!\s*\()/,
    replace: (m, ws, a) => `${ws}// MUTANT: ${a}`,
  },
];

// A killed test and a timed-out test are not the same evidence. execSync sets
// e.signal to SIGTERM (or e.code to ETIMEDOUT) when its timeout fires.
const isTimeout = (e) => Boolean(e && (e.signal === 'SIGTERM' || e.code === 'ETIMEDOUT'));

function runMutations(packageDir, sourceDir, scopeFilter) {
  // baseline: run tests on unmodified code first
  console.log('Running baseline test (unmodified code)...');
  let baselineMs;
  try {
    const start = Date.now();
    const baselineOut = execSync('sui move test 2>&1', {
      cwd: packageDir,
      timeout: 120000,
      encoding: 'utf8',
    });
    baselineMs = Date.now() - start;
    const testCountMatch = baselineOut.match(/Total tests:\s*(\d+)/);
    const testCount = testCountMatch ? Number(testCountMatch[1]) : null;
    if (testCount === null) {
      console.log('ERROR: could not read a test count from the baseline run.');
      console.log('The output did not contain a "Total tests:" line, so there is no way to');
      console.log('tell an empty suite from a passing one. Refusing to score mutations.\n');
      return null;
    }
    if (testCount === 0) {
      console.log('WARNING: baseline ran 0 tests — this is an empty check, not a pass.');
      console.log('Generate tests before running mutation testing.\n');
      return null;
    }
    console.log(`Baseline: PASS ✓ (${testCount} tests, ${Math.round(baselineMs / 1000)}s)\n`);
  } catch (e) {
    const output = e.stdout?.toString() || e.stderr?.toString() || '';
    if (output.includes('not found') || output.includes('No such file') || output.includes('not recognized')) {
      console.log('ERROR: sui CLI not found. Cannot run mutation testing without sui.');
      console.log('Install: https://docs.sui.io/build/install\n');
      return null;
    }
    console.log('ERROR: Baseline tests fail on unmodified code.');
    console.log('Fix your tests before running mutation testing.\n');
    return null;
  }
  const mutantTimeout = Math.max(30000, baselineMs * 3);

  // work on a temp copy to protect user's source
  let tempDir = null;

  const cleanup = () => {
    if (!tempDir) return;
    try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
  };

  // handle SIGINT/SIGTERM gracefully (CI sends SIGTERM on timeout).
  //
  // Registered BEFORE the directory is created and copied into. The recursive
  // copy below is the slowest step in this function, so a SIGTERM landing
  // during it is exactly the CI-timeout case these handlers exist for - and it
  // was previously outside their window, leaving a full copy of the package
  // behind with nothing registered to remove it. cleanup() no-ops while
  // tempDir is still null.
  const onSignal = (sig) => {
    console.log(`\n${sig} — cleaning up temp directory...`);
    cleanup();
    process.exit(sig === 'SIGINT' ? 130 : 143);
  };
  process.on('SIGINT', () => onSignal('SIGINT'));
  process.on('SIGTERM', () => onSignal('SIGTERM'));

  tempDir = mkdtempSync(join(tmpdir(), 'mtg-mutate-'));
  cpSync(packageDir, tempDir, { recursive: true });
  const tempSourceDir = join(tempDir, relative(packageDir, sourceDir));

  let sourceFiles = walkDir(tempSourceDir, '.move');
  if (scopeFilter) {
    sourceFiles = filterByScope(sourceFiles, scopeFilter);
    console.log(`Scope: mutating ${sourceFiles.length} file(s) (${scopeFilter.join(', ')})\n`);
  }
  const results = [];

  try {
    for (const srcFile of sourceFiles) {
      const original = readFileSync(srcFile, 'utf8');
      const lines = original.split('\n');
      const strippedLines = stripBlockComments(original).split('\n');

      for (const mut of MUTATIONS) {
        for (let i = 0; i < lines.length; i++) {
          if (!mut.pattern.test(strippedLines[i])) continue;
          if (lines[i].trim().startsWith('//')) continue;

          // apply mutation in temp copy
          const mutated = [...lines];
          // mutate the comment-stripped line: applicability was decided on it
          // above, and replacing on the raw line can land the edit inside a
          // /* ... */ comment that happens to precede the code on that line.
          mutated[i] = strippedLines[i].replace(mut.pattern, mut.replace);
          writeFileSync(srcFile, mutated.join('\n'));

          // check if mutant compiles first
          let compiles = true;
          let buildTimedOut = false;
          try {
            execSync('sui move build 2>&1', {
              cwd: tempDir,
              timeout: mutantTimeout,
              stdio: 'pipe',
            });
          } catch (e) {
            compiles = false;
            buildTimedOut = isTimeout(e);
          }

          if (!compiles) {
            // A build that TIMED OUT is not a stillborn mutant: it may be
            // perfectly valid and simply slow. Dropping it silently shrinks the
            // denominator and inflates the score.
            if (buildTimedOut) {
              results.push({
                file: relative(tempDir, srcFile), line: i + 1,
                mutation: mut.name, desc: mut.desc,
                original: lines[i].trim(), killed: false, timedOut: true,
              });
            }
            writeFileSync(srcFile, original);
            continue;
          }

          // run tests against compiled mutant
          let killed = false;
          let timedOut = false;
          try {
            execSync('sui move test 2>&1', {
              cwd: tempDir,
              timeout: mutantTimeout,
              stdio: 'pipe',
            });
            // tests passed = mutation survived = weak test
            killed = false;
          } catch (e) {
            // A timeout is not a kill. Counting it as one lets budget pressure
            // quietly raise the mutation score.
            timedOut = isTimeout(e);
            killed = !timedOut;
          }

          results.push({
            file: relative(tempDir, srcFile),
            line: i + 1,
            mutation: mut.name,
            desc: mut.desc,
            original: lines[i].trim(),
            killed,
            timedOut,
          });

          // restore for next mutation
          writeFileSync(srcFile, original);
        }
      }
    }
  } finally {
    cleanup();
  }

  // Carried on the array (not a separate return value) so every existing
  // caller check -- `=== null`, `.length`, `.filter(...)` -- keeps working
  // unchanged; only the one site that needs the timeout has to know it's here.
  results.mutantTimeout = mutantTimeout;
  return results;
}

// ── joint mutant probe ──────────────────────────────────────────────

function runJointMutant(packageDir, sourceDir, candidate, probeTimeout = 60000) {
  const tempDir = mkdtempSync(join(tmpdir(), 'mtg-probe-'));
  cpSync(packageDir, tempDir, { recursive: true });

  try {
    const srcFile = join(tempDir, candidate.file);
    const original = readFileSync(srcFile, 'utf8');
    const lines = original.split('\n');

    for (const ln of candidate.lines) {
      const idx = ln - 1;
      if (idx >= 0 && idx < lines.length && /assert!\s*\(/.test(lines[idx])) {
        lines[idx] = lines[idx].replace(/^(\s*)(assert!\s*\()/, '$1// JOINT-PROBE: $2');
      }
    }

    writeFileSync(srcFile, lines.join('\n'));

    try {
      execSync('sui move build 2>&1', { cwd: tempDir, timeout: probeTimeout, stdio: 'pipe' });
    } catch {
      return null;
    }

    try {
      execSync('sui move test 2>&1', { cwd: tempDir, timeout: probeTimeout, stdio: 'pipe' });
      return false;
    } catch {
      return true;
    }
  } finally {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
  }
}

// ── main ─────────────────────────────────────────────────────────────

// exit-code contract (documented in README):
//   0  clean
//   1  the gate failed - unpaired asserts, surviving mutants, or a lint
//      finding at or above the fail-on threshold
//   2  usage error, or the sources/tests DIRECTORY itself cannot be read
//   3  the tool could not run and produced no verdict -- --mutate requested
//      with no sui CLI, or a --lint FILE inside an otherwise-readable
//      directory that could not be parsed (an unterminated block comment)
const EXIT_OK = 0;
const EXIT_GATE_FAILED = 1;
const EXIT_USAGE = 2;
const EXIT_CANNOT_RUN = 3;

const args = process.argv.slice(2);
if (args.length < 2) {
  console.log('Usage: node check-coverage.mjs <sources-dir> <tests-dir> [options]');
  console.log('');
  console.log('  --mutate                     run Layer 2 mutation testing (needs the sui CLI)');
  console.log('  --lint                       run the security lint rules');
  console.log('  --testability                run the testability pre-flight');
  console.log('  --scope a.move,b.move        only score these source files');
  process.exit(EXIT_USAGE);
}

const [sourceDir, testDir] = args.map(a => resolve(a));
const doMutate = args.includes('--mutate');
const doLint = args.includes('--lint');
const failOnIdx = args.indexOf('--fail-on');
const failOn = failOnIdx >= 0 ? args[failOnIdx + 1] : 'high';
if (!['critical', 'high', 'medium', 'low', 'none'].includes(String(failOn).toLowerCase())) {
  console.log(`Error: --fail-on must be one of critical|high|medium|low|none (got "${failOn}")`);
  process.exit(EXIT_USAGE);
}
const disableIdx = args.indexOf('--disable');
const disabledRules = disableIdx >= 0 ? String(args[disableIdx + 1] || '').split(',') : [];
const scopeIdx = args.indexOf('--scope');
if (scopeIdx >= 0 && !args[scopeIdx + 1]) {
  console.log('Error: --scope needs a comma-separated file list, e.g. --scope fund.move,oracle.move');
  process.exit(2);
}
const scopeFiles = scopeIdx >= 0
  ? args[scopeIdx + 1].split(',').map(f => f.trim()).filter(Boolean)
  : null;
const jsonIdx = args.indexOf('--json');
const jsonPath = jsonIdx >= 0 ? (args[jsonIdx + 1] || '-') : null;
let mutationWeak = false;
let mutationSkipped = false;
let mutationReport = null;
let lintReport = null;
let gateFailed = false;
// A --lint file the tool could not read (an unterminated block comment) is
// the SAME "no verdict reached" class as --mutate finding no sui CLI --
// both feed the exit-3 branch below, unless a real finding elsewhere
// outranks them (the same precedence lint.mjs's own standalone CLI uses).
let lintUnreadable = false;

console.log('=== move-test-gen coverage checker ===\n');

// Layer 1: collect asserts and expected_failures
let sourceFiles, testFiles;
try {
  sourceFiles = walkDir(sourceDir, '.move');
  testFiles = walkDir(testDir, '.move');
} catch (e) {
  console.error(`Error: cannot read directory — ${e.message}`);
  process.exit(EXIT_USAGE);
}

const allAsserts = sourceFiles.flatMap(extractAsserts);
const allFailures = testFiles.flatMap(extractExpectedFailures);
const scopedFailures = allFailures.filter(f => f.scoped);
const unscopedFailures = allFailures.filter(f => !f.scoped);

console.log(`Source files: ${sourceFiles.length}`);
console.log(`Test files:   ${testFiles.length}`);
console.log(`Asserts found:           ${allAsserts.length}`);
console.log(`Expected failures found: ${allFailures.length} (${scopedFailures.length} scoped, ${unscopedFailures.length} unscoped)\n`);

if (unscopedFailures.length > 0) {
  console.log('Note: unscoped #[expected_failure] tests (no abort_code):');
  for (const u of unscopedFailures) {
    const rel = relative(process.cwd(), u.file);
    console.log(`  ${rel}:${u.line} → ${u.fnName}`);
  }
  console.log('  These catch any abort but are not counted toward specific assert coverage.\n');
}

// scope Layer 1 to target files if --scope is set
let targetAsserts = allAsserts;
if (scopeFiles) {
  const norm = (p) => p.split('\\').join('/');
  const wanted = scopeFiles.map(norm);
  const inScope = (a) => wanted.some(s => norm(a.file).endsWith(s));
  targetAsserts = allAsserts.filter(inScope);
  if (targetAsserts.length === 0 && allAsserts.length > 0) {
    console.log(`Error: --scope matched no source file (scope: ${scopeFiles.join(', ')})`);
    console.log(`       ${allAsserts.length} assert site(s) were found, every one of them outside the scope list.`);
    process.exit(2);
  }
  if (targetAsserts.length !== allAsserts.length) {
    const excluded = [...new Set(allAsserts.filter(a => !inScope(a)).map(a => a.file))];
    console.log(`Scope (Layer 1): ${targetAsserts.length} asserts in target, ${allAsserts.length - targetAsserts.length} outside --scope (not scored)`);
    console.log(`  not scored: ${excluded.join(', ')}\n`);
  }
}

// pair only with scoped failures
const failureCodes = new Set(scopedFailures.map(f => f.code));

const unpaired = targetAsserts.filter(a => !failureCodes.has(a.code));
const covered = targetAsserts.filter(a => failureCodes.has(a.code));

console.log('--- Coverage ---');
console.log(`Covered:  ${covered.length}/${targetAsserts.length}`);
console.log(`Unpaired: ${unpaired.length}/${targetAsserts.length}`);

if (unpaired.length > 0) {
  console.log('\nUnpaired asserts (no matching expected_failure test):');
  for (const u of unpaired) {
    const rel = relative(process.cwd(), u.file);
    console.log(`  ${rel}:${u.line}  ${u.type} ${u.code}`);
    console.log(`    ${u.text}`);
  }
}

if (covered.length > 0) {
  console.log('\nCovered asserts:');
  for (const c of covered) {
    const rel = relative(process.cwd(), c.file);
    const match = scopedFailures.find(f => f.code === c.code);
    console.log(`  ✓ ${c.code} (${rel}:${c.line}) → ${match?.fnName || '?'}`);
  }
}

// warn about shared error codes (multiple asserts map to one test)
const codeCounts = {};
for (const a of allAsserts) { codeCounts[a.code] = (codeCounts[a.code] || 0) + 1; }
const shared = Object.entries(codeCounts).filter(([, n]) => n > 1);
if (shared.length > 0) {
  console.log('\n⚠ Shared abort codes (one test covers multiple asserts — consider name-based pairing):');
  for (const [code, count] of shared) {
    const locs = allAsserts.filter(a => a.code === code)
      .map(a => `${relative(process.cwd(), a.file)}:${a.line}`);
    console.log(`  ${code} appears ${count}× — ${locs.join(', ')}`);
  }
}

// Layer 2: mutation testing (optional)
if (doMutate) {
  console.log('\n--- Mutation Testing ---\n');

  // resolve package root (parent of sources dir)
  const packageDir = resolve(sourceDir, '..');
  const mutResults = runMutations(packageDir, sourceDir, scopeFiles);

  if (mutResults === null) {
    console.log('Mutation testing skipped (see errors above).\n');
    mutationSkipped = true;
  } else if (mutResults.length === 0) {
    console.log('No applicable mutations found in source files.\n');
  } else {
    const timedOut = mutResults.filter(r => r.timedOut);
    const decided = mutResults.filter(r => !r.timedOut);
    const killed = decided.filter(r => r.killed);
    const survived = decided.filter(r => !r.killed);

    console.log(`Mutations: ${mutResults.length} applied (stillborn excluded)`);
    console.log(`Killed:    ${killed.length} (tests caught the bug ✓)`);
    console.log(`Survived:  ${survived.length} (tests missed the bug ✗)`);
    if (timedOut.length > 0) {
      console.log(`Timed out: ${timedOut.length} (no verdict — excluded from the score)`);
      for (const t of timedOut) console.log(`  ⏱ ${t.file}:${t.line} [${t.mutation}]`);
    }

    if (survived.length > 0) {
      const { candidates } = identifyProbeCandidates(mutResults, allAsserts);

      const probeOutcomes = candidates.map(c => {
        const probed = runJointMutant(packageDir, sourceDir, c, mutResults.mutantTimeout);
        return { ...c, jointKilled: probed };
      });

      const reframed = finalizeEvidence(survived, probeOutcomes);
      console.log('\nSurviving mutations:');
      for (const s of reframed) {
        console.log(`  ✗ ${s.file}:${s.line} [${s.mutation}] SURVIVED — undecidable by this gate:`);
        console.log(`    weak suite OR equivalent mutant. Judgment needed above this floor.`);
        if (s.evidence) {
          console.log(`    evidence: ${s.evidence}`);
        }
      }
    }

    const score = decided.length > 0
      ? Math.round((killed.length / decided.length) * 100)
      : null;
    console.log(score === null
      ? '\nMutation score: n/a (every mutant timed out)'
      : `\nMutation score: ${score}%`);
    mutationReport = {
      applied: mutResults.length,
      killed: killed.length,
      survived: survived.length,
      score,
      skipped: false,
      survivors: survived.map(r => ({
        file: r.file, line: r.line, mutation: r.mutation, original: r.original,
      })),
    };

    if (survived.length > 0) {
      mutationWeak = true;
      gateFailed = true;
    }
  }
}

// summary
console.log('\n--- Summary ---');
const unparsedAsserts = targetAsserts.filter(a => a.type === 'unparsed');
if (unparsedAsserts.length > 0) {
  console.log(`\n⚠ ${unparsedAsserts.length} assert(s) could not be parsed and are NOT scored:`);
  for (const a of unparsedAsserts) console.log(`  ? ${a.file}:${a.line}  ${a.text.trim()}`);
  gateFailed = true;
}

// A sources path holding no .move files at all is a misconfiguration, not a
// clean result - it is how a repo that reorganises its layout ends up with a
// permanently green gate. A real package that genuinely contains no asserts
// is a different thing and is reported, not failed.
if (sourceFiles.length === 0) {
  console.log(`\n⚠ no .move files were found under ${sourceDir}`);
  console.log('  Nothing was analysed. This is reported as a failure rather than');
  console.log('  as full coverage, because it is usually a wrong path.');
  gateFailed = true;
}

const coverageScore = targetAsserts.length > 0
  ? Math.round((covered.length / targetAsserts.length) * 100)
  : 100;
console.log(targetAsserts.length === 0
  ? 'Assert coverage: n/a (no assert sites found — nothing to measure)'
  : `Assert coverage: ${coverageScore}% (${covered.length}/${targetAsserts.length})`);
if (unpaired.length > 0) {
  console.log(`⚠ ${unpaired.length} assert(s) have no expected_failure test`);
  gateFailed = true;
}
if (unpaired.length === 0) {
  if (mutationSkipped) {
    console.log('⚠ All asserts paired, but --mutate was requested and could not run');
  } else if (mutationWeak) {
    console.log('✓ All asserts paired, but mutation testing found weaknesses (see above)');
  } else {
    console.log(targetAsserts.length === 0
      ? 'No assert sites to check.'
      : '✓ All asserts have matching expected_failure tests');
  }
}

// Security lint (optional)
if (doLint) {
  const { runLint, printLintResults, printUnreadable, shouldFail } = await import('./lint.mjs');
  // runLint() throws for an unreadable sources DIRECTORY and for a malformed
  // rule file (validateRule()) -- either way this is a config/usage problem,
  // not a lint verdict, and must not crash uncaught into Node's default
  // exit 1, the code this tool's own contract reserves for "the gate
  // failed" (real findings). A per-FILE content problem inside an otherwise
  // readable directory -- an unterminated block comment -- is a DIFFERENT
  // failure class, reported via the returned `unreadable` array below, not
  // this catch: the directory was readable, one file inside it was not.
  let findings, ruleCount, suppressed, unreadable;
  try {
    ({ findings, ruleCount, suppressed, unreadable } = await runLint(sourceDir, { disable: disabledRules }));
  } catch (e) {
    console.error(`Error: lint could not run — ${e.message}`);
    process.exit(EXIT_USAGE);
  }
  printLintResults(findings, ruleCount, suppressed, unreadable.length > 0);
  printUnreadable(unreadable);
  lintReport = {
    ruleCount,
    findings: findings.map(f => ({
      file: f.file, line: f.line, rule: f.rule, severity: f.severity, message: f.message,
    })),
    unreadable,
  };
  if (shouldFail(findings, failOn)) {
    gateFailed = true;
  }
  if (unreadable.length > 0) {
    lintUnreadable = true;
  }
}

// Testability pre-flight (runs with --lint or standalone --testability)
if (doLint || args.includes('--testability')) {
  const { readFileSync } = await import('fs');
  const { basename } = await import('path');
  const { checkTestability } = await import('./testability.mjs');
  const { walkDir: walkSrc } = await import('./walk-dir.mjs');
  const srcFiles = walkSrc(sourceDir, '.move');
  const testWarnings = [];
  for (const f of srcFiles) {
    const src = readFileSync(f, 'utf8');
    const mod = basename(f, '.move');
    const { warnings } = checkTestability(src, mod);
    testWarnings.push(...warnings);
  }
  if (testWarnings.length > 0) {
    console.log(`\n=== Testability Pre-flight (${testWarnings.length} warning(s)) ===\n`);
    for (const w of testWarnings) {
      const icon = w.level === 'blocker' ? '🔴' : '🟡';
      console.log(`  ${icon} ${w.level.toUpperCase()}  ${w.message}`);
    }
  }
}

// ── exit ─────────────────────────────────────────────────────────────
// A real defect outranks a missing tool: if Layer 1 found something, that is a
// verdict and it is 1. Exit 3 is reserved for a run that produced no verdict at
// all, which is why "--mutate could not run" no longer looks like "found a bug".
// A --lint file the tool could not read joins --mutate's "no sui CLI" in that
// same exit-3 bucket -- both are "some part of this run reached no verdict",
// never "we scanned it and it's clean" (EXIT_OK) and never "we found something
// wrong" (EXIT_GATE_FAILED, which still wins if gateFailed is also true).
if (gateFailed) {
  process.exitCode = EXIT_GATE_FAILED;
} else if (mutationSkipped || lintUnreadable) {
  process.exitCode = EXIT_CANNOT_RUN;
} else {
  process.exitCode = EXIT_OK;
}

// ── machine-readable report ──────────────────────────────────────────
if (jsonPath) {
  const report = {
    schemaVersion: 1,
    tool: 'move-test-gen',
    sources: sourceDir,
    tests: testDir,
    coverage: {
      covered: covered.length,
      total: targetAsserts.length,
      // null, not 100, when there was nothing to measure -- matches the
      // console's own "n/a" branch above. A machine reader (the Action's
      // coverage-percent output, a dashboard) that only sees the number
      // cannot tell "100% covered" from "zero measurable sites" otherwise
      // (GHSA-w7pc fixed this for the console text; this JSON field, and
      // the Action output that reads directly from it, still published
      // a bare 100).
      percent: targetAsserts.length > 0 ? coverageScore : null,
      unpaired: unpaired.map(a => ({
        file: a.file, line: a.line, code: a.code, type: a.type,
      })),
    },
    mutation: doMutate
      ? (mutationReport || { applied: 0, killed: 0, survived: 0, score: null,
                             skipped: mutationSkipped, survivors: [] })
      : null,
    lint: lintReport,
    exit: process.exitCode || 0,
  };
  const text = JSON.stringify(report, null, 2);
  if (jsonPath === '-') {
    console.log(text);
  } else {
    writeFileSync(jsonPath, text + '\n');
    console.log(`\nJSON report written to ${jsonPath}`);
  }
}
