# Build from source

This contributor guide is kept in the repository only and is not published
on the website. Run the commands below from the repository root.

The current source and `website/` require **official Zig 0.17.0**, not a
development/nightly compiler. Install the signed compiler bundles with:

```sh
ghr install cataggar/zig@v0.17.0 RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
zig build -Doptimize=safe
zig build test
# Static website: Markdown + routes + compilation + prerender into website/dist/
(cd website && zig build prod)
```

## Website generation

Website regression checks: `cd website && zig build test prod check`.
All generation and checks use Zig; Koino converts `doc/**/*.md` mechanically,
except this repository-only guide, and merjs applies the shared layout and
prerenders the result. `doc/README.md` becomes `/ghr/docs.html`; published
documents become `/ghr/docs/<name>.html`. `website/tools/docs.zig` explicitly
excludes `doc/build-from-source.md` from routes and navigation.

Relative Markdown links and heading fragments are checked and rewritten;
links outside the published docs point to GitHub source files. Raw HTML is
omitted by Koino's safe default. Edit Markdown in `doc/`, not generated route
modules.

The shared top menu and homepage **Get started** links open
`doc/getting-started.md`. The homepage and documentation share a grouped sidebar
with every group expanded by default and the current document highlighted;
on smaller screens it becomes a **Documentation menu** disclosure.
Group order and short labels live in `website/tools/docs.zig`.
New published Markdown pages appear automatically under **More documentation**
until assigned to a group; missing and repository-only pages are omitted.

The palette uses the logo's black, orange, and muted olive tones, with a darker
orange for readable text links. Code blocks have keyboard-accessible copy
buttons with success/failure feedback, using the browser's Clipboard API.
Without JavaScript, code remains selectable and navigation stays available.
Keep alternative install commands in separate Markdown fences so each can
be copied independently.

The cache checks use an isolated fixture and keep Zig's cache warm while
editing, adding, renaming, and deleting Markdown, routes, directories, and
optional layouts. Production builds remove stale generated pages.

## Website publication

The Pages workflow publishes only `website/dist/` and `.nojekyll` to the
independent `website` branch. Its first commit has no parent; later publishes
preserve that branch's history without force pushes. GitHub Pages serves the
branch root at <https://cataggar.github.io/ghr/>. Publication is restricted to
`main`, and explicitly requests a Pages build because `GITHUB_TOKEN` pushes
do not automatically trigger branch-based Pages builds.

Pages source configuration is a one-time administrator step: in repository
**Settings > Pages**, choose **Deploy from a branch**, `website`, and
**/ (root)**. The first workflow run creates the branch if necessary; configure
Pages and rerun it. `GITHUB_TOKEN` cannot change Pages source settings, so the
workflow verifies them instead of requesting administrator permissions.
If the `github-pages` environment restricts deployment branches, allow both
`main` (the publisher workflow) and `website` (the Pages deployment).

CI runs native unit/help checks on Linux, macOS, and Windows. The required
`Build & Test` aggregate succeeds only when those jobs, cross-target builds,
and production-site/cache-freshness checks all pass.

## Compiler and operating system requirements

Zig 0.17 spells optimization modes `debug`, `safe`, `fast`, and `small`.
For releases built with this compiler, the standard-library OS floors are
Linux **5.10+**, macOS **15.0+**, and Windows **10+**. The release notes
label the Apple requirement "Darwin 15.0+"; the installed toolchain's
`std.Target` defines the versionless `*-macos` release targets' minimum
as macOS 15.0, not the Darwin kernel version corresponding to OS X 10.11.
Older OS versions are not supported by these new builds;
this does not change the requirements of previously published releases.
See the [official release notes](https://ziglang.org/download/0.17.0/release-notes.html#OS-Version-Requirements).

macOS PyPI wheels built with Zig 0.17 use `macosx_15_0_arm64` and
`macosx_15_0_x86_64` tags to match the binaries' macOS 15.0 minimum.
`pip` will not select these wheels on older macOS. The previously advertised
macOS 11.0 (ARM64) and 10.9 (x86_64) wheel tags no longer apply to new builds.

To rebuild a historical release, use the compiler and optimization spelling
of the **checked-out tag**, not the current branch's toolchain. See the
[historical rebuild policy](reproducible-builds.md#compiler-selection).
