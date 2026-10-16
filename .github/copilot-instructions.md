# Repository Instructions for `ghr`

- **Incremental Zig development (`zig-incremental-dev` skill)**:
  - For iterative Zig implementation, refactoring, or debugging tasks touching `src/`, `build.zig`, or `build.zig.zon`, use the `.github/skills/zig-incremental-dev/` skill and its bounded `.github/skills/zig-incremental-dev/scripts/watcher-helper` script (`start`, `wait`, `status`, `stop`) instead of running repeated cold builds or ad-hoc background `--watch` loops.
  - Do **not** start the Zig incremental watcher for read-only questions, issue/PR research, documentation-only edits, or `website/`-only tasks.
  - Before concluding a Zig code change, stop the watcher (`watcher-helper stop`) and run the standard one-shot `zig build test` check.
