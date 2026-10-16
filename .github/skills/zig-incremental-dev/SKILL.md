---
name: zig-incremental-dev
description: Manage a persistent Zig incremental build/test watcher (`zig build ... -Doptimize=debug -fincremental --watch`) via a bounded helper script during multi-edit Zig development in `src/` or `build.zig`. Use when iteratively writing, refactoring, or debugging Zig code to get fast incremental compiler/test feedback without cold-rebuilding on every edit.
---

# Zig Incremental Development (`zig-incremental-dev`)

Use this skill during iterative Zig implementation tasks in `src/`, `build.zig`, or `build.zig.zon`. Instead of spawning a cold `zig build` process after every edit or managing raw background shells by hand, use `.github/skills/zig-incremental-dev/scripts/watcher-helper` to supervise a single per-worktree `zig build ... -Doptimize=debug -fincremental --watch` process with isolated cache/output directories and deterministic source-revision synchronization.

## When to Use (and When Not to Use)

- **Use this skill** when making multiple edits to Zig source files (`src/**/*.zig`, `build.zig`, `build.zig.zon`) or iterating on compiler errors and unit tests.
- **Do not use this skill** for read-only codebase questions, issue/PR triage, documentation-only edits, or `website/`-only tasks.
- **Keep final verification standard**: `-fincremental --watch` accelerates the inner edit-compile-test loop; always run the normal one-shot `zig build test` check before pushing or completing a task.

## Bounded Helper Commands

All interaction with the watcher goes through bounded commands on `.github/skills/zig-incremental-dev/scripts/watcher-helper`:

### 1. Start (or Reuse) the Watcher

Start the default incremental test watcher for the current worktree and wait for the initial build/test generation to finish:

```bash
.github/skills/zig-incremental-dev/scripts/watcher-helper start
```

By default, this runs and supervises:

```bash
zig build test -Doptimize=debug -fincremental --watch --debounce 50 \
  --cache-dir .zig-cache/copilot-watch --prefix zig-out/copilot-watch \
  --summary all --color off
```

Common options for `start`:
- `--step install`: Watch compilation/installation only (skips running unit test binaries on every save; useful for rapid type-checking and compile-error iteration).
- `--target x86_64-linux`: Cross-target `x86_64-linux` (useful on `aarch64` hosts where Zig's self-hosted `x86_64` backend supports sub-100ms in-place `-fincremental` rebuilds during compile-only `--step install` loops).
- `--optimize <debug|safe|fast|small>`: Override `-Doptimize` (defaults to `debug`).
- `--arg <flag>`: Pass additional `zig build` flags (repeatable).
- `--session <id>` / `--owner-pid <pid>`: Bind ownership to a session identifier or process PID (when `--owner-pid` exits, the supervisor automatically stops the watcher).
- `--json`: Emit machine-readable JSON output.

If a watcher is already running for the worktree with the same configuration, `start` reuses it (`action: reused`). If the build configuration changed (for example switching from `--step install` to `--step test`), `start` cleanly restarts the watcher (`action: restarted`).

### 2. Wait for Rebuild After Edits

After editing any file in `src/`, `build.zig`, or `build.zig.zon`, wait for the watcher to complete a clean build generation matching the current worktree snapshot:

```bash
.github/skills/zig-incremental-dev/scripts/watcher-helper wait
```

How `wait` guarantees freshness:
- Computes a SHA-256 `source_digest` and maximum `mtime_ns` across `build.zig`, `build.zig.zon`, and `src/**`, plus `git_head`.
- Never substitutes an earlier generation or a build that was dirtied mid-flight (`dirty_during_build`) for a current pass.
- If a file change did not yet wake the watcher after the debounce window, automatically nudges `fanotify` without modifying file contents or timestamps.
- Pass `--fresh` to force a new build generation even if the worktree digest has not changed.

### 3. Check Current Watcher Status

Inspect watcher health, active PIDs, compiler version, cache paths, current `source_digest`, and latest generation result without blocking:

```bash
.github/skills/zig-incremental-dev/scripts/watcher-helper status
```

### 4. Stop the Watcher

When finished with iterative Zig edits (before final one-shot verification or branch cleanup), stop the watcher owned by the worktree/session:

```bash
.github/skills/zig-incremental-dev/scripts/watcher-helper stop
```

## Exit Codes

`watcher-helper` fails explicitly so callers never mistake a broken, stale, or dead watcher for a passing build:

| Exit Code | Meaning |
| --- | --- |
| `0` | Build/test generation matching the current worktree `source_digest` succeeded (`status: ready` or `stopped`). |
| `1` | Compiler error or test failure in the current generation (`status: build_failed`), or no watcher running on `status`. |
| `2` | Watcher process exited unexpectedly (`status: exited`; for example a syntax error in `build.zig` during reconfigure). Run `start` after fixing `build.zig`. |
| `3` | (`status` only) Watcher is alive, but the latest generation is `stale` or `building` relative to current sources. Run `wait`. |
| `124` | Timed out waiting for a clean generation matching current sources (`status: timeout`). |

## Recommended Inner-Loop Workflow

1. **Start once** when beginning Zig code changes:
   ```bash
   .github/skills/zig-incremental-dev/scripts/watcher-helper start --step install
   ```
   (or `watcher-helper start` to run unit tests on every change).
2. **Edit -> Wait**: After each edit to `src/*.zig`, run:
   ```bash
   .github/skills/zig-incremental-dev/scripts/watcher-helper wait
   ```
   Read the returned diagnostics if exit code is non-zero, fix, and `wait` again.
3. **Switch to full test watch or final check**:
   ```bash
   .github/skills/zig-incremental-dev/scripts/watcher-helper stop
   zig build test
   ```
