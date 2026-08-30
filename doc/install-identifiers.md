# Install identifiers: design and migration

## Status

This document is the design contract and migration reference for the stable-ID
syntax and v2 install state introduced in ghr v0.8.0. The ordered rollout is
complete. Older ghr releases continue to understand untouched legacy installs,
but they cannot safely mutate v2 state.

## Goals

An install needs a stable name that does not change when its release, selected
asset, download URL, or executable names change. That stable name is the
**install ID**.

The design separates four concepts:

1. **ID**: stable identity used by install, list, and uninstall.
2. **Source intent**: durable user input, such as a GitHub repository and
   optional tag or asset selector.
3. **Resolved provenance**: the release, asset, URL, and digest selected for one
   completed install.
4. **Configuration**: durable choices such as aliases and verification
   material.

This separation permits:

- two installs from the same repository under different IDs;
- replacing one ID without disturbing another;
- explicit executable renaming;
- safe ownership and collision checks before publication; and
- durable source intent that a future upgrade command can resolve again.

## Non-goals for this release

- There is no `ghr upgrade` command in this release. Installing an existing ID
  replaces it transactionally.
- An ID does not implicitly rename an executable.
- This design does not make arbitrary install IDs into literal filesystem
  paths.
- Legacy installs are not eagerly rewritten.
- Downgrading to an old ghr after v2 state has been written is unsupported.

## Motivating examples

Install a repository release with a stable custom ID and rename its `zig`
command to `zigb`:

```sh
ghr install cataggar/zig@zigb-0.16.1 "?id=zigb&alias=zig:zigb"
```

Install another release from the same repository alongside it:

```sh
ghr install cataggar/zig@ziga-0.15.2 "?id=ziga&alias=zig:ziga"
```

The IDs `zigb` and `ziga` coexist because identity is no longer derived solely
from the repository. Neither ID implies an alias: the `alias` mapping is what
changes the published command name.

Existing inline minisign syntax remains valid:

```sh
ghr install jedisct1/minisign@0.12 \
  RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

A bare key is shorthand for minisign configuration attached to the preceding
source. It is not a second install request.

## Terminology

- **Source token**: the positional token that says where to resolve an
  artifact.
- **Query token**: a quoted positional token beginning with `?`, attached to
  the immediately preceding source token.
- **Request**: one source token plus its query token and/or bare minisign key.
- **Canonical ID**: the normalized ID used for comparisons and persisted
  ownership.
- **Unit**: one independently replaceable installed directory and its owned
  commands. An archive or bare executable is normally one unit; each wasm
  module is a separate unit.
- **Command**: a name published into ghr's bin directory.
- **Alias**: an explicit mapping from a discovered command name to its
  published command name.
- **Legacy state** or **v1**: the pre-v2 unversioned `ghr.json` layout under
  `<tools>/<owner>/<repo>/`, including nested wasm units.
- **v2 state**: the versioned, ID-keyed state used by ID-capable ghr releases.

## Command grammar

The positional grammar is:

```text
install       = "ghr install" request *(request) [options]
request       = source [query-token] [bare-minisign-key]
source        = github-spec / github-release-url / generic-url
query-token   = "?" query-pair *("&" query-pair)
query-pair    = query-name "=" query-value
```

Each `&`-delimited pair is split at its **first** `=`. Everything before that
`=` is the name; everything after it, including any further `=`, is the value.
Splitting at the first `=` keeps base64 values intact, because minisign keys
and other base64 material carry trailing `=` padding that must survive
verbatim. A pair with no `=`, or with an empty name, is an error.

The grammar recognizes these query names:

| Name | Repeats? | Meaning |
|------|----------|---------|
| `id` | singleton | Explicit stable install ID. |
| `alias` | repeatable | One explicit command mapping, `source-name:published-name`. Repeat `alias=` to map several commands. |
| `minisign` | singleton | Minisign public key required for this request. |

Aliases are expressed as one mapping per `alias=from:to` pair, repeated as
needed (for example `?id=x&alias=a:aa&alias=b:bb`). Comma-packed values are not
used: repeated pairs keep each mapping independently reportable in diagnostics,
avoid a second in-value delimiter that could collide with future command-name
rules, and read the same as every other pair. `id` and `minisign` remain
singletons.

For example, these are two requests in one invocation:

```sh
ghr install \
  cataggar/zig@zigb-0.16.1 "?id=zigb&alias=zig:zigb" \
  cataggar/zig@ziga-0.15.2 "?id=ziga&alias=zig:ziga"
```

The query token is a separate positional token rather than a suffix on the
source. This keeps source parsing independent and preserves multi-install
boundaries. It should be quoted because `?` and `&` have shell meanings.

### Query token rules

- A query token attaches only to the immediately preceding source.
- A query token with no preceding source is a **lone query token** and is an
  error.
- A second query token for the same source is a duplicate and is an error.
- Unknown query names are errors. Configuration is a closed set for each CLI
  version so typos do not silently change install policy.
- Every pair splits at its first `=` and must have a non-empty name and a
  value. Empty segments, such as `?id=x&&alias=a:b`, and pairs with no `=` are
  errors.
- `id` and `minisign` are singletons and may appear at most once. `alias` is
  repeatable; each `alias=from:to` pair contributes one mapping.
- A bare minisign key and `minisign=` on the same request are duplicate
  configuration and are rejected, even if their values match.
- A bare minisign key without a preceding source remains an error. A second
  bare key for one request remains an error.
- A source begins the next request. Configuration never floats forward or
  backward across source tokens.

Query names and values use RFC 3986 percent-decoding, applied to each half
after the first-`=` split. A `%` must be followed by exactly two hexadecimal
digits. Invalid escapes and decoded values that are invalid for their field are
errors. This is URI query decoding, not HTML form decoding: `+` remains a
literal plus and is never turned into a space. Preserving `+` is required for
minisign keys, which commonly contain `+`.

The parser retains enough source spans to report which token and which query
name failed, identifying the field by name and position only. It does not
echo whole query tokens or raw values in diagnostics or logs, because a value
may be a minisign key or other credential-like material. Report the offending
field by name (for example, "invalid value for `id`"), not by dumping the
token.

### Compatibility with current arguments

`owner/repo[@tag] [bare-minisign-key]` remains valid. The bare key is normalized
as though minisign configuration had been supplied for that request.

Existing command-level options are applied to each affected request during
normalization. Options whose current behavior requires exactly one source,
such as `--bin`, keep that restriction until a later design explicitly gives
them per-request query forms.

## Normalized request model

Parsing produces a model independent of download resolution:

```text
InstallRequest
  id: canonical ID
  id_origin: explicit | derived
  source:
    kind: github | generic_url
    durable source intent
  config:
    aliases: ordered source -> published mappings
    selected commands, if configured by existing CLI options
    minisign key, if configured
    effective verification policy
  original tokens: diagnostic-only source locations
```

Download resolution later adds a separate result:

```text
ResolvedInstall
  request: InstallRequest
  resolved release/tag
  selected asset(s)
  requested and final download URL(s)
  content digest(s), when available
  discovered commands and app bundles
  verification outcomes and evidence references
```

Resolved URLs are provenance, not the durable source definition. A future
upgrade-by-ID operation can resolve the stored source intent again rather than
treating an expiring redirect or API asset URL as the source.

Resolved provenance must never persist secrets. Auth headers, bearer or
installation tokens, API credentials, and sensitive or expiring signed query
parameters (for example, a pre-signed object-store redirect carrying
`X-Amz-Signature`, `X-Amz-Credential`, or an expiry) must not be written to
disk. A resolved download URL is persisted only when it is stable and free of
such material -- for example, a canonical release-asset URL. When the effective
download URL is a signed or credential-bearing redirect, ghr stores
non-sensitive provenance instead -- repository, tag, asset name, and the API
asset identity sufficient to resolve the artifact again -- and omits the signed
URL. Digests remain safe to persist and are preferred for provenance.

## ID rules

The ID is the only identity accepted by install-state operations:

- `ghr install` creates or replaces IDs.
- `ghr list` reports IDs and their definitions.
- `ghr uninstall <id>` removes exactly that ID.

Canonical IDs follow deliberately portable rules:

- IDs are non-empty ASCII and are canonicalized to lowercase.
- IDs consist of slash-separated segments.
- Each segment starts and ends with an ASCII letter or digit and may contain
  ASCII letters, digits, `.`, `_`, and `-` internally.
- Empty segments, `.` and `..` segments, leading or trailing `/`, control
  characters, backslashes, and percent escapes remaining after query decoding
  are rejected.
- Canonical comparison is byte-for-byte after lowercasing. Thus `ZigB` and
  `zigb` are one ID, including on case-sensitive filesystems.
- IDs are limited to 240 bytes total and 100 bytes per segment. These limits
  are enforced before any filesystem work.

GitHub source specs may derive an ID as
`lowercase(owner)/lowercase(repo)`. An explicit `id=` overrides that
derivation. Generic URLs have no reliable repository identity and therefore
require an explicit `id=`.

The source does not own the ID namespace. Two IDs may refer to the same
repository, tag, asset, or URL. Conversely, one ID may have only one live
definition.

## ID path encoding

v2 units live in a dedicated, versioned namespace under the tool store:

```text
<tools>/_v2/units/u-<segment>/.../_unit/
```

Each canonical ID segment is stored in its own `u-`-prefixed directory. The
terminal `_unit` marker allows prefix-related IDs such as `a` and `a/b` to
coexist. The encoding:

- be reversible and injective for every accepted canonical ID;
- never interpret an arbitrary ID directly as an absolute or relative path;
- prevent traversal, separator injection, reserved device names, trailing-dot
  and trailing-space hazards, and case-folding collisions;
- behave consistently across Windows, macOS, and Linux;
- permit inventory code to verify that the encoded path matches the ID stored
  in metadata; and
- provide a defined failure for IDs that cannot fit platform path limits.

A readable encoding is desirable, but correctness is more important. A hash
alone is insufficient unless metadata provides a checked, unambiguous reverse
mapping.

## Aliases, command ownership, and collisions

IDs and command names are separate namespaces.

```text
?id=zigb
```

does not rename `zig` to `zigb`. Renaming is explicit:

```text
?id=zigb&alias=zig:zigb
```

Alias requirements:

- The left side names one discovered command selected for the unit.
- The right side is the exact published command name.
- An alias whose source command is absent is an error.
- Duplicate source mappings or duplicate published names in one request are
  errors.
- Platform command equivalence is used for collision checks. In particular,
  Windows command names compare case-insensitively and account for the shim
  files used to publish one command.
- Unaliased selected commands retain their discovered names.
- Aliases do not change the install ID or the stored relative executable path.

Before any live directory or command change, ghr must:

1. resolve every effective ID in the invocation, including wasm expansion;
2. reject duplicate IDs;
3. resolve aliases and the final command set;
4. reject duplicate final commands within the invocation;
5. build an ownership inventory from valid v1 and v2 state; and
6. reject commands owned by another ID or unmanaged entries in the bin
   directory.

Replacing the same ID may replace that ID's existing commands. It may not take
commands owned by another ID. Cross-ID and unmanaged collisions must be
reported before live state changes, not as warnings after a directory has
already been replaced.

## Persisted v2 state

Today, archive and bare-binary installs live at
`<tools>/<owner>/<repo>/`; wasm units live at
`<tools>/<owner>/<repo>/<stem>/`. Their unversioned `ghr.json` records `tag`,
`asset`, `verified`, optional `minisign`, and `bins`/`apps`.

v2 metadata is schema-versioned and sufficient to reconstruct ownership and a
future upgrade request. The following illustrates its wire shape:

```json
{
  "schema": 2,
  "layout_generation": 2,
  "id": "zigb",
  "source": {
    "kind": "github",
    "owner": "cataggar",
    "repo": "zig",
    "tag": "zigb-0.16.1",
    "asset_selector": null
  },
  "config": {
    "aliases": [
      { "from": "zig", "to": "zigb" }
    ],
    "selected_commands": null,
    "minisign": null,
    "verification_policy": {}
  },
  "resolved": {
    "tag": "zigb-0.16.1",
    "asset": "example.tar.xz",
    "api_asset_id": 123456789,
    "download_url": "https://github.com/cataggar/zig/releases/download/zigb-0.16.1/example.tar.xz",
    "digest": { "algorithm": "sha256", "value": "..." }
  },
  "commands": [
    {
      "name": "zigb",
      "source_name": "zig",
      "relative_target": "zig"
    }
  ],
  "apps": [],
  "verification": {
    "result": "checksum",
    "minisign": null
  },
  "tag": "zigb-0.16.1",
  "asset": "example.tar.xz",
  "verified": "checksum",
  "bins": ["zig"]
}
```

Schema requirements:

- `id`, durable `source`, normalized `config`, resolved provenance, explicit
  commands and ownership, and existing verification data are required
  concepts.
- Source intent and resolved provenance must not be conflated.
- Resolved provenance must be non-sensitive. `download_url` is persisted only
  when it is a stable, credential-free URL; when resolution used a signed or
  token-bearing redirect, `download_url` is omitted and the artifact is instead
  identified by repository, tag, asset name, and `api_asset_id`. Auth headers,
  tokens, credentials, and expiring signed query parameters are never written.
- Relative paths from metadata must be validated before use.
- Writers may retain legacy-compatible top-level fields (`tag`, `asset`,
  `verified`, `bins`) only as read-only hints for current tooling and
  diagnostics. Their presence does not make the record writable by old ghr and
  must not be read as license for downgrade mutation.
- Missing `schema` means v1. An unknown future schema is unsupported, not v1.
- Readers must distinguish missing, malformed, conflicting, corrupt, and
  unsupported state rather than silently treating all of them as absent.

Old ghr versions cannot understand custom IDs or the dedicated v2 namespace.
Once v2 state is written, downgrade mutation (install, uninstall, link, unlink
with an older ghr) is unsupported. Legacy-compatible top-level fields exist for
read-only compatibility only and never make old-ghr mutation of a v2 record
safe.

## Transaction and recovery invariants

Installing an existing ID is replacement, not a separate upgrade operation.
Replacement must be transactional across both the unit directory and command
publication.

The v2 installer stages the unit and complete command plan before publication.
A per-ID transaction journal coordinates the staged, backup, live, and command
states so publication failure restores the previous definition instead of
leaving a partially replaced ID.

The v2 implementation must satisfy these invariants:

- Downloads, extraction, metadata construction, ID expansion, alias
  resolution, ownership inventory, and collision checks complete before live
  mutation.
- A per-ID commit either exposes the new directory and complete command set,
  or restores the previous directory and command set.
- Metadata describing ownership is committed consistently with the live
  commands.
- Stale commands from the same ID are removed only as part of the successful
  replacement.
- Another ID's commands and unmanaged files are never overwritten or removed.
- Interruption at each commit step has a deterministic recovery path.
- Recovery validates identity and ownership before deleting staging, backup,
  command, or journal artifacts.
- Independently installed wasm siblings survive archive replacement.
- The local install transaction covers only local tool directories, commands,
  apps, and metadata. Cross-OS WSL manifest reconciliation is a separate step
  (see [WSL manifests](#wsl-manifests)) and is never part of this atomic
  commit; a WSL failure must not roll back a completed local install.
- Multi-request collision planning covers the complete invocation before its
  first live mutation. Runtime failure policy may still be per request, as
  selected by fail-fast or `--keep-going`.

The implementation uses rename-based staging and a per-ID transaction journal,
with failure-injection tests covering recovery at each publication boundary.

## List and uninstall semantics

`ghr list` uses the inventory reader rather than inferring identity only from
directory depth. It:

- reports the canonical ID for every valid unit;
- distinguishes v1 and v2 entries during migration;
- exposes enough source and configuration to reproduce an install definition
  without substituting resolved URLs for source intent;
- reports conflict, corrupt, and unsupported entries clearly; and
- avoids presenting malformed metadata as an unowned but healthy install.

The implemented human and machine-readable list formats are deliberately
unambiguous. A definition and a bare ID are not interchangeable because an ID
can carry aliases, a selector, and configuration that a plain slug cannot.
The separate forms are:

- a plain **list of IDs** (one canonical ID per line) for scripting that only
  needs identities; and
- a **reproducible install definition** per ID (source intent plus effective
  configuration) suitable for re-running an install.

The default output labels itself as a report, `--ids` emits one healthy ID per
line, and `--json` emits deterministic versioned records with a full definition
for each v2 unit. Legacy definitions are explicitly null because v1 state does
not retain enough source intent to reproduce them.

`ghr uninstall <id>` removes exactly the canonical ID and its owned commands,
apps, metadata, and unit directory. It must inventory and validate ownership
before mutation. Prefixes are not recursive: uninstalling `owner/repo` does not
implicitly remove `owner/repo/module`.

If an ID is missing, conflicted, corrupt, or uses an unsupported schema,
uninstall refuses mutation and reports the state. There is no fallback to
deleting a path constructed directly from user input.

## Wasm units

Wasm modules remain independent units.

When one source request with base ID `example/tools` selects several modules,
it expands deterministically:

```text
example/tools/parser
example/tools/formatter
```

The suffix is the canonical module stem. Expansion happens before duplicate-ID
and command collision checks. A repeated or unsafe stem is an error.

An archive installed as `example/tools` may coexist with those module IDs.
Replacing the archive preserves sibling wasm IDs. Replacing one wasm ID
touches neither the archive nor another module. Exact-ID uninstall semantics
also apply to wasm units.

For legacy nested wasm units, the synthesized ID is
`lower(owner)/lower(repo)/stem`.

## WSL manifests

Legacy WSL manifests are keyed by owner/repo and persist command targets as
paths. v2 linking uses versioned, ID-keyed manifests derived from the same
install inventory used by install, list, and uninstall.

Requirements:

- WSL manifest reconciliation is a separate step from the local install
  transaction. `ghr link`/`ghr unlink`, run under WSL interop, reconcile
  manifests from the shared install inventory; the local install/uninstall
  transaction neither waits on nor rolls back for WSL, and never invokes
  cross-OS operations inside its atomic commit.
- `ghr link` and `ghr unlink` reconcile an ID's explicit command ownership.
- Manifests carry a schema version and canonical ID.
- A changed encoded unit path can be reconciled without confusing another ID
  from the same repository.
- Existing owner/repo manifests are not eagerly rewritten.
- A legacy manifest is imported lazily only after its paths and commands have
  been successfully reconciled to one unambiguous install ID.
- A conflict, modified link, malformed manifest, or ambiguous legacy install
  is reported without destructive cleanup.

Bare Windows-PATH executable manifests remain a separate kind because they are
not backed by a ghr install ID.

The implemented ID manifest is stored at:

```text
<links>/by-id/u-<segment>/.../_manifest.json
```

It uses the same prefixed, slash-segment encoding principle as install state,
so IDs such as `a` and `a/b` can coexist and raw IDs are never interpreted as
paths. The payload records `schema: 2`, `layout_generation: 2`, `kind:
"wsl-id"`, the canonical `id`, the inventory-relative `unit_path`, the
diagnostic absolute `source`, and each owned link's exact name and target. The
ID is the ownership key; `source` is never used to infer identity.

`ghr link <id>` resolves exact command ownership from a Windows-platform
inventory, so aliases remain aliases and are not re-derived from executable
filenames. For the compatibility shorthand `ghr link <name>`, an existing
one-segment ID or ID manifest takes precedence; otherwise the name retains its
historical Windows-PATH meaning. `--id` and `--path` force either side of that
ambiguity. Automatic disambiguation requires canonical Windows tools-directory
discovery; if that lookup fails, it refuses the operation rather than guessing
from the WSL username and requires explicit `--path` or
`GHR_WIN_TOOLS_DIR`.

Before replacing or retiring any link, reconciliation verifies that its live
target still equals the target in the owning manifest. A changed link or an
unmanaged entry blocks the operation before mutation. During lazy import, the
new ID manifest is written only after links are reconciled; failure rolls link
changes back, and the old owner/repo manifest is deleted only after the new
manifest is durable. A legacy manifest can still be unlinked safely after its
Windows install has been removed because its exact source and targets are
validated directly; partial `--bin` operations are refused until legacy state
has been fully reconciled.

Legacy owner/repo validation preserves the actual casing recorded in the
manifest while requiring its final two source components to case-fold to the
canonical ID. This keeps pre-migration mixed-case installs recoverable without
allowing a legacy manifest to claim targets outside the Windows tools root.

Native Windows commands link directly to their installed executables. Wasm
commands are refused rather than linked to raw `.wasm` bytes, which are not
directly executable through WSL interop; a future WSL-aware wasm launcher can
add that support without emitting broken links today.

## GitHub Actions and caches

The install composite action accepts one complete
`source [query-token] [minisign-key]` request per line. It gates on an
ID-capable CLI and asks that CLI to produce the cache fingerprint, so shell
token handling cannot drift from the install parser.

The implemented action:

- parses complete install definitions without losing quoted query tokens;
- normalizes source plus effective ID and configuration before hashing;
- includes the state layout/schema generation, target OS/architecture/ABI, and
  ghr version in the key;
- rejects duplicate IDs and malformed definitions consistently with the CLI;
- preserves `+` in minisign material; and
- caches the tool store, command store, and any required transaction/state
  roots as one compatible generation.

The cache definition must be complete: changing an ID, alias, source selector,
verification policy, or minisign key must invalidate the cache. Sorting is
permitted only after requests have been parsed into complete definitions; raw
token sorting could detach a query token or key from its source.

Action rollout is gated by checking for the CLI's normalized cache-key mode.
The action fails clearly rather than emitting new syntax to a `ghr-bin` version
that only understands the old positional grammar.

## Migration plan

### Is there a good migration plan?

Yes: keep legacy installs readable indefinitely and migrate each one lazily
only when its inferred ID is successfully replaced by a v2 install.

Lazy migration is safest because current metadata does not contain enough
information to reconstruct all source and configuration intent. Command and
app ownership is path-based, WSL manifests persist those paths, and nested
wasm directories are independent units. An eager rewrite would have to invent
facts or risk moving one unit while leaving commands and WSL links owned by an
old path.

### Reading legacy state

Missing `schema` is v1. The inventory reader synthesizes IDs only from facts
that are reliable:

- repo-level unit: `lower(owner)/lower(repo)`;
- nested wasm unit: `lower(owner)/lower(repo)/stem`.

The reader may preserve known `tag`, `asset`, `verified`, `minisign`, `bins`,
and `apps` fields. It must not invent a resolved URL, original source token,
asset-selection intent, alias policy, or verification policy that v1 did not
record.

Legacy directories remain in place and usable. Merely listing, linking, or
starting ghr must not move them.

### Lazy replacement

When a v2 install successfully replaces an ID currently represented by one
unambiguous legacy unit:

1. stage and validate the complete v2 replacement;
2. reconcile old path-based command/app ownership into the v2 command plan;
3. commit the v2 unit, its commands, and its metadata transactionally;
4. remove the replaced legacy unit only after the new v2 state **and** its
   published commands are durable -- never before both are committed; and
5. reconcile WSL manifests as a separate follow-up, outside the local
   transaction. WSL reconciliation is not required for steps 3 and 4 to be
   considered complete, and a WSL failure never resurrects or blocks removal of
   the migrated legacy unit.

Steps 1-4 are local and atomic; step 5 is cross-OS best-effort. Because legacy
removal in step 4 depends only on durable local v2 state and command
publication, an interrupted or unavailable WSL environment can never leave a
half-deleted legacy install.

An archive replacement preserves independent nested wasm units. A wasm
replacement migrates only its exact synthesized child ID.

### States that refuse mutation

The inventory must surface and refuse mutation when:

- a legacy entry and a v2 entry map to the same canonical ID;
- mixed-case legacy paths collapse to one canonical ID;
- two metadata records claim the same command;
- metadata is malformed or contains unsafe paths;
- an encoded v2 path does not match its metadata ID;
- a WSL manifest cannot be reconciled unambiguously; or
- metadata uses an unknown future schema.

These are conflict, corrupt, or unsupported states, not opportunities to pick
one entry arbitrarily.

### Downgrade

Old ghr may continue to read untouched legacy installs, but it cannot
understand custom IDs, v2 ownership, or v2 WSL manifests. Once any v2 writer
has mutated the store, using an older ghr to install, uninstall, link, or
unlink is unsupported. Recovery should use an ID-capable ghr, not manual
movement into owner/repo paths.

## Rollout sequence

The implementation was split and merged in this strict order:

1. **Design contract only**: add `doc/install-identifiers.md` and index it from
   `doc/README.md`.
2. **Pure install-request parser**: add `src/install_request.zig` without
   changing download parsing.
3. **Versioned install state/inventory reader**: add
   `src/install_state.zig`, legacy-compatible, with writers still unused.
4. **Collision-safe command publication planner**: add
   `src/command_plan.zig` plus narrow install helpers, still not activated.
5. **Activate ID install/list/uninstall**: first persisted-state change and
   lazy legacy migration.
6. **Convert WSL link/unlink**: use ID inventory and versioned manifests.
7. **Update action and public surfaces**: composite action, help, CI smoke
   tests, and user documentation; gate action rollout on an ID-capable CLI.

Each stage was enabled for auto-merge only after its predecessor merged and
post-merge `main` CI passed.

## Validation matrix

The rollout added focused tests across this matrix, with lifecycle smoke
coverage on every supported runner platform.

| Area | Required cases |
|------|----------------|
| Request boundaries | One request; multiple requests; query attaches to preceding source; source after configured request starts a new request. |
| Query errors | Lone query; duplicate query token; unknown name; repeated singleton (`id`/`minisign`); empty name/value; pair with no `=`; empty segment; malformed `%` escape. |
| Pair splitting | Split at first `=`; value containing further `=`; base64 `=` padding in a `minisign=` value preserved. |
| Percent decoding | `%2F`, `%3A`, `%25`, lowercase hex, invalid hex, and literal `+` (never a space) in a minisign key. |
| Diagnostics safety | Failing field named without echoing the whole token or a key-bearing value. |
| Minisign compatibility | Existing bare key; lone key; double key; bare key plus `minisign=` duplicate; per-request key overriding a command-level default where allowed. |
| IDs | Derived lowercase GitHub ID; required explicit generic-URL ID; case collapse; unsafe segments; length limits; two IDs for one repository. |
| Aliases | No inference from ID; valid rename; multiple repeated `alias=` pairs; missing source command; duplicate source mapping; duplicate published name; platform case collision. |
| Invocation planning | Duplicate IDs; duplicate commands; cross-ID owned collision; unmanaged collision; same-ID replacement allowed; no live mutation on rejection. |
| v1 inventory | Repo unit; nested wasm unit; missing schema; mixed-case path; absent optional fields; reliable facts only. |
| v2 inventory | Valid schema; reversible path check; malformed metadata; unsafe relative target; unknown future schema. |
| Provenance safety | Stable `download_url` persisted; signed/credential redirect not persisted (falls back to asset identity); no auth headers/tokens written. |
| Migration ordering | Legacy unit removed only after v2 state and commands are durable; WSL unavailable does not block or half-delete legacy; interrupted removal recovers. |
| Mixed inventory | v1/v2 same-ID conflict; mixed-case legacy collapse; duplicate command ownership; deterministic diagnostics. |
| Replacement | Fresh install; same-ID replacement; failure before commit; failure during directory publication; failure during command publication; recovery after interruption. |
| Commands/apps | New commands published; stale same-ID commands removed; other-ID and unmanaged entries untouched; app ownership rollback where supported. |
| Wasm | One module; deterministic multi-module expansion; duplicate stem; exact child replacement/uninstall; archive preserves siblings. |
| List/uninstall | List-of-IDs form and reproducible-definition form each labeled and unambiguous; IDs reported from inventory; exact-ID uninstall; prefix is not recursive; corrupt/conflict/unsupported state refuses mutation. |
| WSL | New ID-keyed manifest; same repo with two IDs; lazy legacy import; changed or ambiguous target refuses destructive reconciliation. |
| Actions/cache | Complete normalized definitions; reordered requests; changed ID/alias/policy/key invalidates; layout generation invalidates; old CLI gate. |
| Platforms | Linux symlinks, Windows shims and case rules, macOS app bundles, path limits, reserved names, and recovery on each filesystem model. |

The repository test suite runs with:

```sh
zig build test
```

It covers install, replacement, list, uninstall, multi-ID coexistence,
collision refusal, wasm independence, and cache restoration. Platform CI
smoke jobs additionally exercise the full native install lifecycle.

## Implemented storage choices

The rollout settled the previously open implementation choices as follows:

- v2 units use `_v2/units/u-<segment>/.../_unit`;
- canonical IDs are limited to 240 bytes with 100-byte segments;
- per-ID journals coordinate staged, backup, live, and command-publication
  recovery; and
- `ghr list`, `ghr list --ids`, and `ghr list --json` provide separate human,
  identity-only, and machine-readable forms.

These choices preserve the ID safety, ownership, schema-versioning, and
rollback requirements above.
