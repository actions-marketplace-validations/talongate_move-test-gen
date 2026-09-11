# Changelog

Notable changes per released tag. Dates are the tag's commit date.

Generated from `git log` between tags — if an entry looks wrong, the commit
history is the source of truth.

## v1.6.1 — 2026-09-10

Accuracy and coverage patch — 43 commits from @HetCreep plus three security advisories.

### New rule

- **MOV-013** [HIGH] — `#[spec_only]` public functions ship in production bytecode with zero access control. Same class as the CDPM $300K drain.

### Fixes (rules)

- **MOV-002** bit-shift detection was wrong in both directions (fail-open on some patterns, false positive on others). Rewritten.
- **MOV-006** now detects shared abort codes in single-line function bodies.
- **MOV-008** no longer flags test bodies; catches snake_case payment names (`total_amount`, `deposit_fee`).
- **MOV-011** catches attribute-prefixed and line-wrapped `entry` declarations; closes a latent param bug.
- **MOV-012** narrows to actionable identity claims, closing 3 corpus FPs. Also catches decorated names (`sender_address`, `caller_addr`).

### Fixes (parser / infra)

- Parser attaches `#[test_only]` / `#[test]` by item boundary instead of leaking onto the next function.
- Parser recognizes `macro fun` bodies and `$`-prefixed operands — four rules were blind to macro functions.
- Unparseable Move source now fails the run instead of reading as clean (fail-open → fail-closed).
- `walk-dir.mjs` follows symlinked source directories.

### Security advisories

- [GHSA-vvr3](https://github.com/talongate/move-test-gen/security/advisories/GHSA-vvr3-fhhp-wvhq) — MOV-012 decorated name bypass
- [GHSA-xc3j](https://github.com/talongate/move-test-gen/security/advisories/GHSA-xc3j-493g-97q6) — missing `#[spec_only]` detection rule
- [GHSA-mwqv](https://github.com/talongate/move-test-gen/security/advisories/GHSA-mwqv-cfjv-p4cc) — symlink directory skip

### Stats

- Lint rules: 9 → 10 files (11 checks)
- gate-selftest: 14 → 25 cases
- Contributors: mehvetero (193) + @HetCreep (95)

## v1.6.0 — 2026-08-26

New lint rules and accuracy improvements. Three of the new checks were inspired by patterns documented in @jangid's [sui-move-auditor](https://github.com/AlphaFiTech/sui-ai-commons) — the exact-equality payment assert, bit-shift silent wrapping, and sender-as-address spoofability. Credited because that's where the signal came from.

### New rules

- **MOV-008** [MEDIUM] — exact-equality assert on payment amounts (`assert!(amount == price)` → DoS via dust/rounding; use `>=` instead)
- **MOV-011** [HIGH] — `public(package) entry` function is externally callable via PTB (the `entry` modifier defeats the package restriction)
- **MOV-012** [HIGH] — sender identity taken as a plain `address` parameter instead of `tx_context::sender(ctx)` (spoofable by any PTB caller)

### Extended rules

- **MOV-002** now detects `<<` / `>>` bit-shift operations that silently wrap on overflow (unlike `+`/`-`/`*` which abort). Same class as the Cetus $223M checked_shlw root cause.

### Fixes

- **MOV-001** word-boundary fix — `PositionManager` (shared object) was falsely exempt because `/Position/` matched as a substring. Only exact `Position` (user-owned NFT) is now exempt.

### Stats

- Lint rules: 6 → 9 files (10 checks including MOV-002 shift extension)
- gate-selftest: 14/14 cases green

## v1.5.2 — 2026-08-21

Community audit round 2 — 25 fixes from @HetCreep's CoalBoard nasa-rigor review.

### Fixes

- **Lint rules:** MOV-001 wrapped-signature fallback + key/witness type check; MOV-003 guard ordering + capture window; MOV-005 overbroad safe-context + Move 2024 `let mut`; MOV-006 abort-code regex comma
- **Parser:** block-comment apostrophe handling; trailing comment stripping before cast/mul/div
- **Mutation:** timeout scope at joint probe; timed-out mutants excluded from probe candidates
- **Coverage:** 0/0 assert = null (not 100%) in JSON + Action output
- **Lint infra:** `#[test_only]` scope per-module (not per-file); severity normalized at collection; CLI exit-code contract; uncaught malformed-rule crash guard
- **Eval:** round-key parser recognizes unparsed asserts; doctor catches unpinned dependencies
- **Testability:** generic public functions recognized
- **Docs:** README claim scoped to --mutate; template name/assertion sync; truncated words restored; bare npm name warning; selftest case count synced
- **Examples:** action pins updated to talongate post-transfer

## v1.5.1 — 2026-08-16

Security patch. Fixes GHSA-w7pc-q6qh-49qw, which was declared fixed in v1.5.0 but was not.

- Assert regex now tolerates parenthesised abort codes `(EBad)` and trailing commas `EWorse,`
- An assert site the regex cannot parse is recorded as `unparsed`, printed with its location, and fails the run — instead of vanishing from both sides of the ratio
- A zero denominator reports `n/a` instead of `100% (0/0)`
- A sources path with no `.move` files is a hard failure

PR #51 by [@HetCreep](https://github.com/HetCreep). Issue #50.

## v1.5.0 — 2026-08-13

Major community release. 23 pull requests merged from [@HetCreep](https://github.com/HetCreep), 3 security advisories patched, and the first external contributor joined the project.

### Security fixes
- GHSA-6r4g: block comment containing `#[test_only]` above module skipped all 6 lint rules
- GHSA-w7pc: zero parsed asserts printed "100% coverage" and exited 0
- GHSA-5499: same-line `#[test_only] use ...` leaked exemption onto the next function (MOV-001, MOV-003)
- `stripBlockComments` extracted to shared module (`scripts/strip-comments.mjs`)

### New features
- `--fail-on <severity>` flag — configurable gate threshold (default: high)
- `--json` machine-readable output with versioned schema
- `// move-test-gen-disable-next-line MOV-003` suppression pragmas + `--disable` flag
- Exit codes: 0 clean / 1 findings / 2 usage error / 3 tool error
- Action outputs: `coverage-percent`, `mutation-score`, `lint-findings` + job summary
- Action boolean inputs accept `yes`/`true`/`on`/`1` (case-insensitive)
- Rule metadata validated at load — missing id/severity fails immediately

### Compatibility
- `public(package)` visibility (Move 2024 edition) recognized by parser, MOV-001, MOV-006
- `--scope` separator normalized for Windows paths
- `--scope` with no match is now an error, not a silent pass

### Reliability
- Mutation timeout is its own outcome (not counted as killed)
- `runJointMutant` timeout scales from baseline instead of hard-coded 60s
- Missing test count is an error, not a pass
- Lint self-test capable of actually failing
- Lint path exercised end-to-end through the CLI
- MOV-001 exemption list pinned in selftest
- Temp-dir cleanup registered before the recursive copy
- `persist-credentials: false` on all non-pushing checkout steps
- `timeout-minutes` and `concurrency` group on both workflows
- SHA-pinned `actions/setup-node` in the composite action

### Documentation
- `SECURITY.md` — vulnerability reporting channel
- `CHANGELOG.md` — this file
- `RELEASE.md` — release checklist
- README: manual-install tree corrected, exit-code section, untrusted-code warning, skills-path versioning note, consumer workflow examples hardened
- dependabot for `github-actions` ecosystem

### Packaging
- `package.json`: `files` allowlist (246 entries → essential files only), `engines` field
- npm `move-test-gen@0.0.2` republished (leading-space shebang fixed)
- Dead import removed from `walk-dir.mjs`

## v1.4.1 — 2026-08-06

- afdf70b fix: selftest header comment still said 3 rules, now 6
- 552c8c0 Merge pull request #1 from mehvetero/fix/selftest-description-typo
- 879f6c0 fix: summary no longer prints success when asserts are unpaired (fixes #2)
- 3c069dd fix: add SuiTears scenario 10 and Cetus i128 attribution to LICENSE (fixes #3)
- 7daae46 fix: align all action version pins to v1.4.0 (fixes #4)
- 12b5f7a fix: remove references to uncommitted CAMPAIGN2.md (fixes #7)
- 339c96e fix: CI hardening + selftest docs + validation scope (fixes #5, #6, #8, #9)
- 5049b2f fix: layer3-lint CI expects findings on example code, not zero exit
- d2f80d6 fix: layer3-lint tolerates non-zero exit (findings expected on example code)
- 1ade734 fix: walkDir throws on root ENOENT instead of returning empty (GHSA-cvv4-fqh2-qjmp)
- fbd5474 fix: strip /* */ block comments before extracting asserts and tests (GHSA-x92p-5vp7-jccr)
- a1178ba fix: action.yml uses env+array instead of string concat for scope (GHSA-w5jq-f9f6-9wm4)
- c80c3ef fix: MOV-005 catches let _ok=, trailing comments, multiline calls; message no longer recommends binding (GHSA-wjph-hf99-9gw5)
- 7631be3 fix: #[test_only] only exempts file when it precedes the first module declaration (GHSA-j66v-q36w-g97p)
- ff85e08 fix: selftest runner distinguishes skip (exit 2) from pass (exit 0) (fixes #10)
- 4d16250 fix: case 07 asserts specific exit code and corrects scope label (fixes #11)
- d06fc6a docs: add HetCreep security audit acknowledgement + bump v1.4.1

## v1.4.0 — 2026-08-05

- 7198fe1 fix: address 3 findings from rot-canary field run
- 0b67621 fix(docs): demote campaign headings to h2 — single h1 per document
- eea04e2 fix(docs): correct round count 47 → 46 (doc-grounding finding)
- be4bb7b feat: testability pre-check splits blocker vs cost severity
- f1b497b refactor: extract walkDir to shared module — eliminates rot-canary finding #2
- 49964be feat: wire testability pre-flight into --lint and --testability flags
- 92301af feat(lint): MOV-005 — authorization check result discarded (Typus pattern)
- 075ef38 fix(lint): MOV-005 remove verify/check_auth from patterns — void functions are not bool
- ebe572c feat(lint): MOV-006 — shared abort code across multiple public functions
- b76c684 docs: update README, action, selftest for v1.4.0 (6 rules)

## v1.3.0 — 2026-07-23

- 2784134 chore: action description — add security lint mention
- 7bd963c fix(lint): MOV-001 skip functions accepting Balance<T>
- c02b630 feat(lint): MOV-004 unsafe u128/u256 to u64 downcast without overflow check
- d00f360 feat: lightweight Move source parser — function-level type tracking
- 58ba25a feat(lint): MOV-002 uses parser for type tracking — u128/u256 FP eliminated
- afb4835 feat(lint): MOV-004 uses parser — type-aware downcast checks
- 20e901c fix(lint): MOV-004 skip library functions by name pattern (safe_mul_div)
- 548bdae docs: update README for v1.3.0 — MOV-004 + parser-backed type tracking

## v1.2.0 — 2026-07-22

- 322004e eval: campaign 5 — cross-family independent measurement (DeepSeek via Venice.ai)
- 3cf22fe docs(eval): campaign 5 digest — cross-family independent (DeepSeek vs GPT-5.5)
- 68da6d0 feat: security lint engine — 3 rules for Move vulnerability detection
- 2e746e2 fix(lint): skip inaccessible directories in walkDir
- 1fa337b fix(lint): skip #[test_only] modules — test scaffolding is not audit target
- 1c0a357 fix(lint): MOV-001 handle generic functions — was silently skipping all <T>
- 4a433ac fix(lint): MOV-001 skip #[test_only] and _test suffix functions
- dbbc5a3 fix(lint): MOV-001 recognize Witness, Version, and Key access patterns
- 8070f24 fix(lint): MOV-001 skip permissionless DeFi functions (Coin/LP/Receipt)
- f7e1d3a fix(lint): MOV-002 skip test functions and u256-typed variables
- 085eb6d fix(lint): MOV-003 skip test function bodies
- eb5b08c test: pin all lint hardening patterns in selftest case 11
- 3262294 docs: add security lint section to README, update eval lab stats
- ce8819d chore: bump version to 1.2.0

## v1.1.2 — 2026-07-19

- dec3f0e chore: final polish — L2 mutation CI lane + README action jump link
- 38da391 eval: campaign 4 complete — Layer 1 real-protocol validation + cross-team diversity
- 63c9bbb docs(eval): campaign 4 digest — L1 field-proven, session discipline not enforced
- 8724e53 feat(gate): warn on baseline 0-tests — empty check is not a pass
- a654a60 test: selftest case 08 — pins baseline 0-tests warning (gate-modify rule)
- 32f91fa feat(gate): extract scope filter to pure function + selftest case 09
- 34745bf feat: testability pre-flight check + selftest case 10
- ebfdd48 feat(gate): target-scoped Layer 1 — assert coverage counts target only

## v1.1.1 — 2026-07-17

- 14921ea chore: add marketplace branding (shield/purple)
- 9c77db6 chore: marketplace icon shield → eye

## v1.1.0 and earlier

See the commit history; this changelog starts at v1.1.1.
