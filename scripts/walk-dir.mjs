import { readdirSync, realpathSync, statSync } from 'fs';
import { join } from 'path';

export function walkDir(dir, ext) {
  // Seed the cycle guard with the ROOT's own real identity -- a symlink
  // buried anywhere in the tree that points back to the root (or to an
  // ancestor of it) must be recognized as a cycle the first time it is
  // reached, not only once some OTHER directory has already been visited.
  // If the root itself can't be resolved, don't mask that behind a
  // resolution-error message -- let the readdirSync failure below throw
  // the real, informative error for the path the caller explicitly named.
  const visitedRealDirs = new Set();
  try {
    visitedRealDirs.add(realpathSync.native(dir));
  } catch {
    // handled by walkDirInner's own readdirSync try/catch, below
  }
  return walkDirInner(dir, ext, true, visitedRealDirs);
}

function walkDirInner(dir, ext, isRoot, visitedRealDirs) {
  const results = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    if (isRoot) throw err;
    return results;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);

    if (entry.isSymbolicLink()) {
      // Match the compiler: `sui move build` walks with
      // `walkdir::WalkDir::new(path).follow_links(true)`, so a symlinked
      // directory (or a Windows junction -- Node reports isDirectory=false,
      // isSymbolicLink=true for those too) is real, compiled, deployable
      // source. `Dirent.isDirectory()` describes the LINK, never the
      // TARGET, so treating a link as neither a directory nor a `.move`
      // file silently drops it from the walk -- GHSA-mwqv-cfjv-p4cc, the
      // defect this branch exists to close. Resolve with `.native` (not
      // plain `realpathSync` -- see runtime.md §4: plain does not expand a
      // Windows 8.3 short name and leaves UNC paths uncollapsed) and
      // recurse if the target is a directory.
      let real, targetStat;
      try {
        real = realpathSync.native(full);
        targetStat = statSync(real);
      } catch (err) {
        // A link whose target cannot be resolved (dangling, permission
        // denied, or any other stat failure) is a HARD ERROR here,
        // unconditionally -- at every depth, root or not. This is
        // deliberately NOT the same contract as the whole-directory
        // readdirSync failure above (root throws, non-root swallows): that
        // contract is for an entire SUBDIRECTORY becoming unreadable, a
        // failure the walker never had visibility into in the first place
        // (it can't enumerate what it can't list). A broken link is
        // different in kind -- readdirSync already found and enumerated
        // this exact entry by name, so swallowing its resolution failure
        // at ANY depth would silently drop a NAMED, known entry from the
        // walk, exactly reproducing the class of defect this fix exists to
        // close rather than a genuinely unreachable subtree. The caller
        // (lint.mjs / check-coverage.mjs) gets an uncaught exception naming
        // the broken link, never a package that quietly scores clean.
        throw new Error(`walkDir: cannot resolve symlink ${full}`, { cause: err });
      }

      if (targetStat.isDirectory()) {
        // Cycle guard: a symlink loop (A/link -> B, B/link -> A, or a link
        // pointing at one of its own ancestors) must terminate, never blow
        // the stack. Keyed on the REAL path so two different link paths
        // that resolve to the SAME directory are recognized as the same
        // visit, not just a literal link pointing directly at itself.
        if (visitedRealDirs.has(real)) continue;
        visitedRealDirs.add(real);
        results.push(...walkDirInner(full, ext, false, visitedRealDirs));
      } else if (entry.name.endsWith(ext)) {
        // a symlinked FILE (not a directory) -- treat like an ordinary file
        results.push(full);
      }
      continue;
    }

    if (entry.isDirectory()) results.push(...walkDirInner(full, ext, false, visitedRealDirs));
    else if (entry.name.endsWith(ext)) results.push(full);
  }
  return results;
}
