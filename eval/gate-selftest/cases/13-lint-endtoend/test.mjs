#!/usr/bin/env node
/**
 * cases/11-lint-rules imports each rule's check() directly. That covers the
 * rules and nothing around them: lint.mjs's rule discovery, its rule count,
 * and check-coverage.mjs's severity-to-exit mapping are all reached only by
 * running the CLI, and were covered by no case at all.
 *
 * This spawns the real gate twice — once on a tree with a HIGH finding, once on
 * a clean tree — and asserts the exit code both ways.
 */
import { spawnSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..', '..', '..', '..');
const GATE = process.env.GATE || join(repoRoot, 'scripts', 'check-coverage.mjs');

function makeTree(moveSource) {
  const dir = mkdtempSync(join(tmpdir(), 'mtg-lint-e2e-'));
  mkdirSync(join(dir, 'sources'), { recursive: true });
  mkdirSync(join(dir, 'tests'), { recursive: true });
  writeFileSync(join(dir, 'sources', 'a.move'), moveSource);
  return dir;
}

const HIGH = `module demo::high {
    public fun drain(v: &mut Pool, amount: u64) {
        v.total = amount;
    }
}
`;
const CLEAN = `module demo::clean {
    public fun total(p: &Pool): u64 {
        p.total
    }
}
`;

const run = (dir) => spawnSync(process.execPath,
  [GATE, join(dir, 'sources'), join(dir, 'tests'), '--lint'],
  { encoding: 'utf8', timeout: 30000 });

const errs = [];

const high = run(makeTree(HIGH));
const highOut = (high.stdout || '') + (high.stderr || '');
if (high.status === 0) errs.push('a HIGH lint finding did not fail the gate (exit 0)');
if (!/MOV-001/.test(highOut)) errs.push('MOV-001 did not fire on a function that mutates state with no capability');
if (!/Security Lint \(10 rules\)/.test(highOut)) {
  errs.push(`rule discovery did not report 10 rules: ${(highOut.match(/Security Lint \([^)]*\)/) || ['<absent>'])[0]}`);
}

const clean = run(makeTree(CLEAN));
const cleanOut = (clean.stdout || '') + (clean.stderr || '');
if (!/No findings\./.test(cleanOut)) errs.push('a clean tree produced lint findings');
if (clean.status !== 0) errs.push(`a clean tree exited ${clean.status}, expected 0`);

if (errs.length) {
  for (const e of errs) console.log(`  ${e}`);
  process.exit(1);
}
console.log('lint runs end-to-end: 10 rules discovered, HIGH fails, clean passes');
process.exit(0);
