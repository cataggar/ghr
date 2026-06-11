const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const archive = @import("archive.zig");
const auth = @import("auth.zig");
const release_mod = @import("release.zig");
const Dirs = @import("dirs.zig").Dirs;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const EnvironMap = std.process.Environ.Map;
const Args = std.process.Args;

const Sha256 = std.crypto.hash.sha2.Sha256;
const sha256_hex_len = Sha256.digest_length * 2;

/// Exit codes used by `cmdDownload`.
pub const exit_arg_error: u8 = 1;
pub const exit_io_error: u8 = 1;
pub const exit_http_error: u8 = 2;
pub const exit_sha256_mismatch: u8 = 3;

/// Parsed `download` command-line options.
pub const Options = struct {
    /// Positional arguments: URLs, `owner/repo[@tag]`, or
    /// `owner/repo/file[@tag]`, each optionally followed by an inline
    /// minisign public key. Multi-spec downloads loop over this list
    /// sharing a single HTTP client + auth resolution.
    targets: std.ArrayListUnmanaged(release_mod.SpecWithKey) = .empty,
    /// Single-output path. Rejected when `targets.len > 1`.
    output: ?[]const u8 = null,
    extract: ?[]const u8 = null,
    /// Per-target SHA-256 digest. Rejected when `targets.len > 1`.
    sha256: ?[]const u8 = null,
    strip_components: u32 = 0,
    keep_archive: bool = false,
    quiet: bool = false,
    no_auth: bool = false,
    skip_verify: bool = false,
    /// Skip the checksum verification step (GitHub asset digest and any
    /// `.sha256` sidecar). Minisign, sigstore, and authenticode continue
    /// to run as usual.
    skip_checksum: bool = false,
    /// Skip just the minisign-sidecar verification step. Bypasses the
    /// fail-closed "sidecar present but no key" diagnostic.
    skip_minisign: bool = false,
    /// Skip just the sigstore-bundle verification step.
    skip_sigstore: bool = false,
    /// Skip just the Authenticode (Windows PE) verification step.
    skip_authenticode: bool = false,
    /// Raw base64 minisign public key (single token). Default applied to
    /// every target that does not carry its own inline key. When set,
    /// ghr fetches `<asset>.minisig` from the release and verifies it;
    /// missing sidecar is treated as a verification failure (fail-closed).
    minisign_pubkey: ?[]const u8 = null,
    debug: bool = false,
    /// Continue past per-spec failures, then exit non-zero with a summary
    /// if any spec failed.
    keep_going: bool = false,

    /// Free the targets list. Target slices themselves borrow from argv.
    pub fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        self.targets.deinit(allocator);
    }

    /// Snapshot of skip flags as a `VerifyGates`.
    pub fn gates(self: *const Options) release_mod.VerifyGates {
        return .{
            .skip_verify = self.skip_verify,
            .skip_checksum = self.skip_checksum,
            .skip_minisign = self.skip_minisign,
            .skip_sigstore = self.skip_sigstore,
            .skip_authenticode = self.skip_authenticode,
        };
    }
};

/// Internal: target resolved from a single positional spec plus any release
/// context needed for verification.
const ResolvedTarget = struct {
    /// Final URL to download from. Borrows from argv (URL form) or from a
    /// release asset (spec form: the API asset URL when authenticated,
    /// otherwise `browser_download_url`).
    download_url: []const u8,
    /// Optional `Accept` header for `download_url` (set to
    /// `application/octet-stream` when using the GitHub asset API endpoint).
    accept: ?[]const u8 = null,
    /// Default output filename. When null, the caller derives one from the URL.
    default_filename: ?[]const u8,
    /// Release context for verification, when known.
    release: ?release_mod.ParsedRelease,
    /// Asset name within `release.parsed.value.assets`, when release is set.
    asset_name: ?[]const u8,
    /// Allocated buffer for parseGitHubReleaseUrl results (URL form only).
    url_decoded: ?release_mod.ParsedReleaseUrl,

    fn deinit(self: *ResolvedTarget, allocator: std.mem.Allocator) void {
        if (self.release) |*r| r.deinit();
        if (self.url_decoded) |*u| u.deinit(allocator);
    }
};

/// Per-spec error signalling a single download failed after a user-visible
/// diagnostic was printed. The caller uses `StepResult.exit_code` to map the
/// failure back to a documented exit status (1/2/3).
pub const DownloadStepError = error{DownloadStepFailed};

/// Captures the documented exit code (1/2/3) that a per-spec failure would
/// have used in the single-spec path. Multi-spec drivers use the *most
/// severe* (numerically highest) code seen across the batch as the process
/// exit code.
const StepResult = struct {
    exit_code: u8 = 0,

    fn fail(self: *StepResult, code: u8) DownloadStepError!void {
        self.exit_code = code;
        return error.DownloadStepFailed;
    }
};

/// Shared state for one or more sequential per-spec downloads in a single
/// `ghr download` invocation.
pub const DownloadContext = struct {
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    client: *std.http.Client,
    /// GitHub auth resolved once. Per-spec downloads attach it only when
    /// the URL points at a github-owned host.
    auth_resolved: auth.Resolved,
    /// `Bearer <token>` header, or null when auth was disabled / not found.
    auth_header: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
};

pub fn cmdDownload(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    args: *Args.Iterator,
    w: *Writer,
    err_w: *Writer,
) !void {
    var opts = parseArgs(allocator, args, err_w) catch |err| switch (err) {
        error.HelpRequested => {
            try printDownloadUsage(w);
            return;
        },
        error.MissingValue, error.InvalidArgument, error.MissingTarget, error.ConflictingFlag => std.process.exit(exit_arg_error),
        else => return err,
    };
    defer opts.deinit(allocator);

    return cmdDownloadMany(allocator, io, environ, &opts, w, err_w);
}

/// Download every spec in `opts.targets` in sequence using a shared HTTP
/// client + auth context. Fail-fast unless `opts.keep_going` is set.
pub fn cmdDownloadMany(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    opts: *const Options,
    w: *Writer,
    err_w: *Writer,
) !void {
    if (opts.targets.items.len == 0) return;

    // GitHub auth resolved once and reused across all specs. Borrowing
    // the resolved token avoids re-invoking `gh auth token` per spec.
    const auth_resolved = auth.resolveGithubToken(allocator, io, environ, opts.no_auth);
    defer auth_resolved.deinit(allocator);
    const auth_header = try auth.bearerHeader(allocator, auth_resolved);
    defer if (auth_header) |h| allocator.free(h);

    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
        .write_buffer_size = http.http_write_buffer_size,
    };
    defer client.deinit();

    const ctx = DownloadContext{
        .allocator = allocator,
        .io = io,
        .environ = environ,
        .client = &client,
        .auth_resolved = auth_resolved,
        .auth_header = auth_header,
        .w = w,
        .err_w = err_w,
    };

    var failed_specs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer failed_specs.deinit(allocator);
    var max_exit_code: u8 = 0;

    for (opts.targets.items, 0..) |target, i| {
        if (opts.targets.items.len > 1 and !opts.quiet) {
            try w.print("[{d}/{d}] {s}\n", .{ i + 1, opts.targets.items.len, target.spec });
            try w.flush();
        }
        var step: StepResult = .{};
        downloadOne(&ctx, opts, target, &step) catch |err| switch (err) {
            error.DownloadStepFailed => {
                try failed_specs.append(allocator, target.spec);
                if (step.exit_code > max_exit_code) max_exit_code = step.exit_code;
                if (!opts.keep_going) std.process.exit(if (step.exit_code == 0) exit_http_error else step.exit_code);
                if (!opts.quiet) {
                    try err_w.print("note: --keep-going, continuing past failure for {s}\n", .{target.spec});
                    try err_w.flush();
                }
            },
            else => return err,
        };
    }

    if (opts.targets.items.len > 1 and !opts.quiet) {
        const ok = opts.targets.items.len - failed_specs.items.len;
        try w.print("downloaded {d}/{d}", .{ ok, opts.targets.items.len });
        if (failed_specs.items.len > 0) {
            try w.print(", failed:", .{});
            for (failed_specs.items) |s| try w.print(" {s}", .{s});
        }
        try w.print("\n", .{});
        try w.flush();
    }

    if (failed_specs.items.len > 0) {
        std.process.exit(if (max_exit_code == 0) exit_http_error else max_exit_code);
    }
}

/// Download a single spec using the shared `DownloadContext`. On failure,
/// `step.exit_code` is set to the corresponding documented exit status (1/2/3)
/// before `error.DownloadStepFailed` is returned.
fn downloadOne(
    ctx: *const DownloadContext,
    opts: *const Options,
    entry: release_mod.SpecWithKey,
    step: *StepResult,
) anyerror!void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const environ = ctx.environ;
    const w = ctx.w;
    const err_w = ctx.err_w;

    const target_str = entry.spec;
    // Per-spec inline key beats the global `--minisign` default.
    const effective_minisign_pubkey: ?[]const u8 = entry.key orelse opts.minisign_pubkey;
    const gates = opts.gates();

    const debug_w: ?*Writer = if (opts.debug) err_w else null;

    // 0) Classify positional + resolve release context (for spec forms, or
    //    for URL form when it's a github release URL).
    var target = resolveTarget(ctx, opts, target_str) catch |err| switch (err) {
        error.InvalidArgument => return step.fail(exit_arg_error),
        error.ReleaseLookupFailed, error.AssetMatchFailed => return step.fail(exit_http_error),
        else => return err,
    };
    defer target.deinit(allocator);

    // 1) Determine output and archive-on-disk paths.
    const paths = resolvePaths(allocator, io, opts, target.download_url, target.default_filename, err_w) catch |err| switch (err) {
        error.InvalidUrl, error.NoFilename, error.UnsupportedScheme => return step.fail(exit_arg_error),
        else => return err,
    };
    defer paths.deinit(allocator);

    // 2) If extracting, ensure destination dir exists.
    if (paths.extract_dir) |edir| {
        Dir.cwd().createDirPath(io, edir) catch |err| {
            try err_w.print("error: failed to create extract dir '{s}': {}\n", .{ edir, err });
            try err_w.flush();
            return step.fail(exit_io_error);
        };
    }

    // 3) Per-spec host check: only attach auth for github-owned hosts.
    const uri = std.Uri.parse(target.download_url) catch unreachable; // already validated
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = (uri.getHost(&host_buf) catch null) orelse blk: {
        break :blk std.Io.net.HostName{ .bytes = "" };
    };
    const per_spec_auth_header: ?[]const u8 = if (auth.isGithubHost(host.bytes)) ctx.auth_header else null;
    const per_spec_auth_source: []const u8 = if (auth.isGithubHost(host.bytes)) ctx.auth_resolved.source else "skipped";

    if (opts.debug) {
        try err_w.print("debug: url: {s}\n", .{target.download_url});
        try err_w.print("debug: host: {s}\n", .{host.bytes});
        try err_w.print("debug: auth: {s}\n", .{per_spec_auth_source});
        try err_w.print("debug: archive_path: {s}\n", .{paths.archive_path});
        if (paths.extract_dir) |e| try err_w.print("debug: extract_dir: {s}\n", .{e});
        try err_w.flush();
    }

    // 4) Pre-flight verification check: if a `.minisig` sidecar is
    //    published, refuse to download without explicit user intent
    //    (inline key, `--minisign <key>`, `--skip-minisign`, or
    //    `--skip-verify`). Similarly, fail early if a minisign key was
    //    supplied but no sidecar exists.
    if (target.release != null and target.asset_name != null) {
        release_mod.preflightVerification(
            target.release.?.parsed.value.assets,
            target.asset_name.?,
            gates,
            effective_minisign_pubkey,
            err_w,
        ) catch |perr| switch (perr) {
            error.MinisignSidecarPresentButNoKey,
            error.MinisignSidecarMissing,
            => return step.fail(exit_sha256_mismatch),
            error.MinisignPubKeyParseError,
            => return step.fail(exit_arg_error),
            else => return perr,
        };
    }

    // 5) Download to a `.part` file beside the destination so a partial file
    //    never appears at the user-visible path.
    const part_path = try std.fmt.allocPrint(allocator, "{s}.part", .{paths.archive_path});
    defer allocator.free(part_path);

    Dir.deleteFileAbsolute(io, part_path) catch {};

    var hasher: ?Sha256 = if (opts.sha256 != null) Sha256.init(.{}) else null;

    if (!opts.quiet) {
        try w.print("downloading {s} ...\n", .{target.download_url});
        try w.flush();
    }

    http.downloadToFile(allocator, io, target.download_url, part_path, .{
        .auth_header = per_spec_auth_header,
        .accept = if (per_spec_auth_header != null) target.accept else null,
        .debug_w = debug_w,
        .hasher = if (hasher != null) &hasher.? else null,
    }) catch |err| {
        Dir.deleteFileAbsolute(io, part_path) catch {};
        try err_w.print("error: download failed: {}\n", .{err});
        try err_w.print("  url: {s}\n", .{target.download_url});
        try err_w.flush();
        return step.fail(exit_http_error);
    };

    // 5a) Verify SHA-256 if --sha256 was passed.
    if (opts.sha256) |expected_hex| {
        var digest: [Sha256.digest_length]u8 = undefined;
        hasher.?.final(&digest);
        var got_hex_buf: [sha256_hex_len]u8 = undefined;
        const got_hex = bytesToHexLower(&digest, &got_hex_buf);
        if (!std.ascii.eqlIgnoreCase(got_hex, expected_hex)) {
            Dir.deleteFileAbsolute(io, part_path) catch {};
            try err_w.print("error: sha256 mismatch\n", .{});
            try err_w.print("  expected: {s}\n", .{expected_hex});
            try err_w.print("  actual:   {s}\n", .{got_hex});
            try err_w.flush();
            return step.fail(exit_sha256_mismatch);
        }
        if (!opts.quiet) {
            try w.print("sha256 ok\n", .{});
            try w.flush();
        }
    }

    // 5b) Auto-verify against release manifest (sha256 / sigstore) when we
    //     have a release context. `--skip-verify` bypasses this. An explicit
    //     `--sha256` already validated the bytes, so we still attempt
    //     sigstore verification but allow `.no_verification` outcomes to be
    //     silent.
    if (target.release != null and target.asset_name != null) {
        const r = &target.release.?;
        const d = try Dirs.detect(allocator, environ);
        defer d.deinit();
        if (std.fs.path.dirname(d.cache)) |parent| {
            Dir.createDirAbsolute(io, parent, .default_dir) catch {};
        }
        Dir.createDirAbsolute(io, d.cache, .default_dir) catch {};
        const outcome = release_mod.verifyAssetOnDisk(
            allocator,
            io,
            d.cache,
            r.parsed.value.assets,
            target.asset_name.?,
            part_path,
            debug_w,
            per_spec_auth_header,
            gates,
            effective_minisign_pubkey,
            w,
            err_w,
        ) catch |verr| {
            Dir.deleteFileAbsolute(io, part_path) catch {};
            switch (verr) {
                error.ChecksumMismatch,
                error.ChecksumDownloadFailed,
                error.ChecksumEntryMissing,
                error.MinisignSidecarMissing,
                error.MinisignSidecarPresentButNoKey,
                error.MinisignKeyIdMismatch,
                error.MinisignSignatureMismatch,
                error.MinisignGlobalSigMismatch,
                => return step.fail(exit_sha256_mismatch),
                error.MinisignDownloadFailed,
                => return step.fail(exit_http_error),
                else => {
                    try err_w.print("error: verification failed: {}\n", .{verr});
                    try err_w.flush();
                    return step.fail(exit_http_error);
                },
            }
        };
        _ = outcome;
    }

    // 6) Atomic rename into place.
    Dir.renameAbsolute(part_path, paths.archive_path, io) catch |err| {
        Dir.deleteFileAbsolute(io, part_path) catch {};
        try err_w.print("error: failed to finalise output '{s}': {}\n", .{ paths.archive_path, err });
        try err_w.flush();
        return step.fail(exit_io_error);
    };

    // 7) Print download size summary.
    if (!opts.quiet) {
        const f = Dir.openFileAbsolute(io, paths.archive_path, .{}) catch null;
        if (f) |file| {
            defer file.close(io);
            const size = file.length(io) catch 0;
            if (size > 0) {
                try w.print("downloaded {d:.1} MB to {s}\n", .{
                    @as(f64, @floatFromInt(size)) / 1024.0 / 1024.0,
                    paths.archive_path,
                });
            } else {
                try w.print("downloaded to {s}\n", .{paths.archive_path});
            }
        } else {
            try w.print("downloaded to {s}\n", .{paths.archive_path});
        }
        try w.flush();
    }

    // 8) Optional extraction.
    if (paths.extract_dir) |edir| {
        const fmt = archive.detectFormat(paths.archive_name);
        if (fmt == .unknown) {
            try err_w.print("error: cannot extract '{s}': unrecognised archive format\n", .{paths.archive_name});
            try err_w.print("  supported formats: .zip, .tar.gz, .tgz, .tar.xz, .txz\n", .{});
            try err_w.flush();
            return step.fail(exit_arg_error);
        }

        if (!opts.quiet) {
            try w.print("extracting to {s} ...\n", .{edir});
            try w.flush();
        }

        var dest_dir = Dir.openDirAbsolute(io, edir, .{}) catch |err| {
            try err_w.print("error: failed to open extract dir '{s}': {t}\n", .{ edir, err });
            try err_w.flush();
            return step.fail(exit_io_error);
        };
        defer dest_dir.close(io);

        archive.extractAuto(allocator, io, dest_dir, paths.archive_path, opts.strip_components) catch |err| {
            try err_w.print(
                "error: failed to extract '{s}' from '{s}' into '{s}': {t}\n",
                .{ paths.archive_name, paths.archive_path, edir, err },
            );
            try err_w.flush();
            return step.fail(exit_io_error);
        };

        if (!opts.keep_archive and !paths.user_supplied_output) {
            Dir.deleteFileAbsolute(io, paths.archive_path) catch {};
        }
    }
}

/// Resolve the positional argument into an actual download URL, optional
/// default output filename, and optional release context for verification.
fn resolveTarget(
    ctx: *const DownloadContext,
    opts: *const Options,
    target_str: []const u8,
) !ResolvedTarget {
    const allocator = ctx.allocator;
    const err_w = ctx.err_w;

    const classified = release_mod.classifyArg(target_str) catch {
        try err_w.print("error: invalid argument '{s}'\n", .{target_str});
        try err_w.print("  expected: owner/repo[@tag] or owner/repo/file[@tag]\n", .{});
        try err_w.flush();
        return error.InvalidArgument;
    };

    switch (classified) {
        .url => |u| {
            // Try to extract a github release context for opportunistic
            // verification. Failure is silent — non-github URLs and odd
            // shapes simply skip verification.
            const gh_opt = release_mod.parseGitHubReleaseUrl(allocator, u) catch null;
            if (gh_opt == null) {
                return .{
                    .download_url = u,
                    .default_filename = null,
                    .release = null,
                    .asset_name = null,
                    .url_decoded = null,
                };
            }
            const gh = gh_opt.?;

            const rel_opt = fetchRelease(ctx, opts, gh.owner, gh.repo, gh.tag) catch null;
            if (rel_opt) |rel| {
                return .{
                    .download_url = u,
                    .default_filename = null,
                    .release = rel,
                    .asset_name = gh.file,
                    .url_decoded = gh,
                };
            }
            // Couldn't fetch release context; download anyway, no verify.
            var gh_mut = gh;
            gh_mut.deinit(allocator);
            return .{
                .download_url = u,
                .default_filename = null,
                .release = null,
                .asset_name = null,
                .url_decoded = null,
            };
        },
        .repo_spec => |rs| {
            var rel = try fetchRelease(ctx, opts, rs.owner, rs.repo, rs.tag);
            errdefer rel.deinit();

            const asset = release_mod.findBestAsset(rel.parsed.value.assets) catch {
                try err_w.print("error: no matching asset for this platform\n", .{});
                try err_w.print("available assets:\n", .{});
                for (rel.parsed.value.assets) |a| try err_w.print("  {s}\n", .{a.name});
                try err_w.flush();
                return error.AssetMatchFailed;
            };
            const dl = release_mod.assetDownload(asset, ctx.auth_header != null);
            return .{
                .download_url = dl.url,
                .accept = dl.accept,
                .default_filename = asset.name,
                .release = rel,
                .asset_name = asset.name,
                .url_decoded = null,
            };
        },
        .file_spec => |fs| {
            var rel = try fetchRelease(ctx, opts, fs.owner, fs.repo, fs.tag);
            errdefer rel.deinit();

            const m = release_mod.findAssetByName(allocator, rel.parsed.value.assets, fs.file) catch |err| {
                try err_w.print("error: failed to match asset by name: {}\n", .{err});
                try err_w.flush();
                return error.AssetMatchFailed;
            };
            switch (m) {
                .one => |asset| {
                    const dl = release_mod.assetDownload(asset, ctx.auth_header != null);
                    return .{
                        .download_url = dl.url,
                        .accept = dl.accept,
                        .default_filename = asset.name,
                        .release = rel,
                        .asset_name = asset.name,
                        .url_decoded = null,
                    };
                },
                .none => {
                    try err_w.print("error: no asset matching '{s}' in {s}/{s}@{s}\n", .{
                        fs.file, fs.owner, fs.repo, rel.parsed.value.tag_name,
                    });
                    try err_w.print("available assets:\n", .{});
                    for (rel.parsed.value.assets) |a| try err_w.print("  {s}\n", .{a.name});
                    try err_w.flush();
                    return error.AssetMatchFailed;
                },
                .ambiguous => |list| {
                    defer allocator.free(list);
                    try err_w.print("error: '{s}' matches multiple assets in {s}/{s}@{s}:\n", .{
                        fs.file, fs.owner, fs.repo, rel.parsed.value.tag_name,
                    });
                    for (list) |a| try err_w.print("  {s}\n", .{a.name});
                    try err_w.flush();
                    return error.AssetMatchFailed;
                },
            }
        },
    }
}

/// Fetch a release via the GitHub API using the shared HTTP client + auth
/// header carried in `ctx`. Logs progress lines mimicking `cmdInstall`'s
/// output.
fn fetchRelease(
    ctx: *const DownloadContext,
    opts: *const Options,
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
) !release_mod.ParsedRelease {
    const w = ctx.w;
    const err_w = ctx.err_w;

    if (!opts.quiet) {
        try w.print("resolving {s}/{s}", .{ owner, repo });
        if (tag) |t| try w.print("@{s}", .{t});
        try w.print(" ...\n", .{});
        try w.flush();
    }

    const rel = release_mod.getRelease(ctx.allocator, ctx.client, owner, repo, tag, ctx.auth_header) catch |err| {
        switch (err) {
            error.GitHubApiError => {
                try err_w.print("error: release not found for {s}/{s}", .{ owner, repo });
                if (tag) |t| try err_w.print("@{s}", .{t});
                try err_w.print("\n", .{});
            },
            else => try err_w.print("error: failed to fetch release: {}\n", .{err}),
        }
        try err_w.flush();
        return error.ReleaseLookupFailed;
    };
    if (!opts.quiet) {
        try w.print("found release {s}\n", .{rel.parsed.value.tag_name});
        try w.flush();
    }
    return rel;
}

const ResolvedPaths = struct {
    /// Absolute path to the downloaded archive on disk.
    archive_path: []const u8,
    /// Filename portion of `archive_path` (used for format detection).
    archive_name: []const u8,
    /// Absolute path of the extraction destination, or null when no `--extract`.
    extract_dir: ?[]const u8,
    /// True when the user passed `-o`. When set we never auto-delete the
    /// archive after extraction; the user explicitly asked for that file.
    user_supplied_output: bool,

    fn deinit(self: ResolvedPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.archive_path);
        if (self.extract_dir) |e| allocator.free(e);
    }
};

fn resolvePaths(
    allocator: std.mem.Allocator,
    io: Io,
    opts: *const Options,
    download_url: []const u8,
    default_filename: ?[]const u8,
    err_w: *Writer,
) !ResolvedPaths {
    const uri = std.Uri.parse(download_url) catch {
        try err_w.print("error: invalid URL: {s}\n", .{download_url});
        try err_w.flush();
        return error.InvalidUrl;
    };
    if (!isHttpScheme(uri.scheme)) {
        try err_w.print("error: unsupported URL scheme '{s}' (only http/https)\n", .{uri.scheme});
        try err_w.flush();
        return error.UnsupportedScheme;
    }

    const archive_path = if (opts.output) |out|
        try toAbsolute(allocator, io, out)
    else if (default_filename) |name|
        try toAbsolute(allocator, io, name)
    else blk: {
        const default_name = derivedFilename(uri) catch {
            try err_w.print("error: cannot derive output filename from URL; pass -o <path>\n", .{});
            try err_w.flush();
            return error.NoFilename;
        };
        break :blk try toAbsolute(allocator, io, default_name);
    };
    errdefer allocator.free(archive_path);

    const archive_name = std.fs.path.basename(archive_path);

    const extract_dir: ?[]const u8 = if (opts.extract) |e|
        try toAbsolute(allocator, io, e)
    else
        null;

    return .{
        .archive_path = archive_path,
        .archive_name = archive_name,
        .extract_dir = extract_dir,
        .user_supplied_output = opts.output != null,
    };
}

fn isHttpScheme(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "https");
}

/// Derive an output filename from a URI's path component. Strips trailing
/// slashes and rejects empty/path-traversing names.
pub fn derivedFilename(uri: std.Uri) ![]const u8 {
    var raw_buf: [Dir.max_path_bytes]u8 = undefined;
    const raw_path = uri.path.toRaw(&raw_buf) catch return error.NoFilename;
    var path = raw_path;
    while (path.len > 0 and path[path.len - 1] == '/') path = path[0 .. path.len - 1];
    if (path.len == 0) return error.NoFilename;

    const last_slash = std.mem.lastIndexOfScalar(u8, path, '/');
    const name = if (last_slash) |i| path[i + 1 ..] else path;

    if (name.len == 0) return error.NoFilename;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.NoFilename;
    if (std.mem.indexOfAny(u8, name, "/\\") != null) return error.NoFilename;

    // The slice is into raw_buf which is a stack buffer; the caller must dupe
    // before raw_buf is reused. We dupe by always copying via toAbsolute.
    return try staticDupeName(name);
}

threadlocal var derived_name_buf: [Dir.max_path_bytes]u8 = undefined;
fn staticDupeName(name: []const u8) ![]const u8 {
    if (name.len > derived_name_buf.len) return error.NoFilename;
    @memcpy(derived_name_buf[0..name.len], name);
    return derived_name_buf[0..name.len];
}

fn toAbsolute(allocator: std.mem.Allocator, io: Io, path: []const u8) ![]const u8 {
    if (std.fs.path.isAbsolute(path)) {
        return try allocator.dupe(u8, path);
    }
    var cwd_buf: [Dir.max_path_bytes]u8 = undefined;
    const cwd_len = try std.process.currentPath(io, &cwd_buf);
    const cwd = cwd_buf[0..cwd_len];
    return try std.fs.path.join(allocator, &.{ cwd, path });
}

fn bytesToHexLower(bytes: []const u8, out: []u8) []const u8 {
    std.debug.assert(out.len >= bytes.len * 2);
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}

fn parseArgs(allocator: std.mem.Allocator, args: *Args.Iterator, err_w: *Writer) !Options {
    var opts: Options = .{};
    errdefer opts.deinit(allocator);

    while (args.next()) |arg| {
        if (eql(arg, "-o") or eql(arg, "--output")) {
            opts.output = try takeValue(args, "-o", err_w);
        } else if (eql(arg, "--extract")) {
            opts.extract = try takeValue(args, "--extract", err_w);
        } else if (eql(arg, "--strip-components")) {
            const v = try takeValue(args, "--strip-components", err_w);
            opts.strip_components = std.fmt.parseInt(u32, v, 10) catch {
                try err_w.print("error: --strip-components requires a non-negative integer (got '{s}')\n", .{v});
                try err_w.flush();
                return error.InvalidArgument;
            };
        } else if (eql(arg, "--sha256")) {
            const v = try takeValue(args, "--sha256", err_w);
            if (v.len != sha256_hex_len or !isHex(v)) {
                try err_w.print("error: --sha256 requires {d} hex characters\n", .{sha256_hex_len});
                try err_w.flush();
                return error.InvalidArgument;
            }
            opts.sha256 = v;
        } else if (eql(arg, "--keep-archive")) {
            opts.keep_archive = true;
        } else if (eql(arg, "--quiet")) {
            opts.quiet = true;
        } else if (eql(arg, "--no-auth")) {
            opts.no_auth = true;
        } else if (eql(arg, "--skip-verify")) {
            opts.skip_verify = true;
        } else if (eql(arg, "--skip-checksum")) {
            opts.skip_checksum = true;
        } else if (eql(arg, "--skip-minisign")) {
            opts.skip_minisign = true;
        } else if (eql(arg, "--skip-sigstore")) {
            opts.skip_sigstore = true;
        } else if (eql(arg, "--skip-authenticode")) {
            opts.skip_authenticode = true;
        } else if (eql(arg, "--minisign")) {
            opts.minisign_pubkey = try takeValue(args, "--minisign", err_w);
        } else if (eql(arg, "--keep-going")) {
            opts.keep_going = true;
        } else if (eql(arg, "--debug")) {
            opts.debug = true;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try err_w.print("error: unknown flag '{s}' for 'ghr download'\n", .{arg});
            try err_w.flush();
            return error.InvalidArgument;
        } else if (eql(arg, "help") and opts.targets.items.len == 0) {
            return error.HelpRequested;
        } else {
            switch (release_mod.classifySpecOrKey(arg, opts.targets.items)) {
                .spec => |s| try opts.targets.append(allocator, .{ .spec = s }),
                .key => |k| opts.targets.items[opts.targets.items.len - 1].key = k,
                .lone_key => {
                    try err_w.print(
                        "error: positional minisign key '{s}' must follow a spec\n",
                        .{arg},
                    );
                    try err_w.print(
                        "  hint: write `<owner/repo[@tag]> <pubkey>` (key attaches to the preceding spec)\n",
                        .{},
                    );
                    try err_w.flush();
                    return error.InvalidArgument;
                },
                .double_key => {
                    const last_spec = opts.targets.items[opts.targets.items.len - 1].spec;
                    try err_w.print(
                        "error: spec '{s}' already has an inline minisign key; second key '{s}' is not allowed\n",
                        .{ last_spec, arg },
                    );
                    try err_w.flush();
                    return error.InvalidArgument;
                },
            }
        }
    }

    try validateMultiTargetOptions(&opts, err_w);
    return opts;
}

/// Post-parse multi-spec validation. Rejects per-target flags (`-o`,
/// `--sha256`) when more than one positional spec was supplied, and rejects
/// invocations with zero positional specs.
///
/// Extracted from `parseArgs` so tests can build an `Options` struct
/// directly and verify the rejection rules without constructing a real
/// `std.process.Args.Iterator`.
fn validateMultiTargetOptions(opts: *const Options, err_w: *Writer) !void {
    if (opts.targets.items.len == 0) {
        try err_w.print("error: 'ghr download' requires owner/repo[@tag] or owner/repo/file[@tag]\n", .{});
        try err_w.flush();
        return error.MissingTarget;
    }
    if (opts.targets.items.len > 1) {
        if (opts.output != null) {
            try err_w.print("error: '-o'/'--output' cannot be used with multiple specs\n", .{});
            try err_w.print("  hint: drop '-o' to land each download in cwd, or invoke 'ghr download' once per spec\n", .{});
            try err_w.flush();
            return error.ConflictingFlag;
        }
        if (opts.sha256 != null) {
            try err_w.print("error: '--sha256' cannot be used with multiple specs\n", .{});
            try err_w.print("  hint: a single digest cannot apply to N artifacts; rely on sigstore / per-asset .sha256 sidecars instead\n", .{});
            try err_w.flush();
            return error.ConflictingFlag;
        }
    }
}

fn takeValue(args: *Args.Iterator, flag: []const u8, err_w: *Writer) ![]const u8 {
    const v = args.next() orelse {
        try err_w.print("error: '{s}' requires a value\n", .{flag});
        try err_w.flush();
        return error.MissingValue;
    };
    return v;
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!ok) return false;
    }
    return true;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn printDownloadUsage(w: *Writer) !void {
    try w.print(
        \\ghr download - download one or more release assets
        \\
        \\USAGE:
        \\    ghr download <spec> [<minisign-pubkey>] [<spec> [<minisign-pubkey>] ...] [options]
        \\
        \\Each <spec> is one of:
        \\    owner/repo[@tag]              Auto-pick the asset 'ghr install' would pick
        \\    owner/repo/file[@tag]         Match a specific asset by name
        \\
        \\An optional minisign public key (56-char base64, starts with `RW` or
        \\`RU`) immediately after a spec attaches to that spec only and
        \\overrides `--minisign` for that one download. Otherwise the global
        \\`--minisign <pubkey>` default applies to every spec.
        \\
        \\Picks the asset that 'ghr install' would install (first form), or the
        \\named asset (second form, exact match preferred, otherwise unique
        \\substring). Downloads are auto-verified against any sigstore bundle
        \\or checksum sidecar published with the release. Pass a minisign key
        \\(inline or `--minisign`) to also require minisign signature
        \\verification against a `<asset>.minisig` sidecar.
        \\
        \\Multi-spec invocations share a single HTTP client + auth context.
        \\
        \\OPTIONS:
        \\    -o, --output <path>        Output file path (single-spec only)
        \\        --extract <dir>        Extract archive(s) into <dir> after download
        \\        --strip-components <N> Strip N leading path components when extracting
        \\        --sha256 <hex>         Verify download against literal SHA-256 digest (single-spec only)
        \\        --minisign <pubkey>    Default minisign key, applied to specs without an inline key
        \\        --skip-verify          Skip every verification step (checksum, minisign, sigstore, authenticode)
        \\        --skip-checksum        Skip checksum verification (GitHub asset digest + .sha256 sidecar)
        \\        --skip-minisign        Skip just the minisign verification step
        \\        --skip-sigstore        Skip just the sigstore-bundle verification step
        \\        --skip-authenticode    Skip just the Authenticode (Windows PE) verification step
        \\        --keep-archive         Keep archive on disk after extraction
        \\        --keep-going           For multi-spec, continue past per-spec failures
        \\        --quiet                Suppress progress output
        \\        --no-auth              Do not send GitHub auth even for github.com URLs
        \\        --debug                Verbose diagnostic output
        \\
        \\Run 'ghr download help' to show this help.
        \\
        \\EXAMPLES:
        \\    ghr download burntsushi/ripgrep@15.1.0
        \\    ghr download burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0 --extract ./bin
        \\    ghr download jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
        \\
        \\EXIT CODES:
        \\    0 success
        \\    1 argument or IO error
        \\    2 HTTP / network error after retries
        \\    3 sha256 mismatch
        \\
    , .{});
    try w.flush();
}

// Public helpers re-exported for tests in main.
const Options_for_test = Options;

// ---------- tests ----------

test "derivedFilename extracts last path segment" {
    const cases = [_]struct { url: []const u8, want: []const u8 }{
        .{ .url = "https://github.com/foo/bar/baz.tar.gz", .want = "baz.tar.gz" },
        .{ .url = "https://example.com/path/to/file.zip", .want = "file.zip" },
        .{ .url = "https://example.com/file.txt?token=abc", .want = "file.txt" },
        .{ .url = "https://example.com/file.txt#frag", .want = "file.txt" },
        .{ .url = "https://example.com/dir/", .want = "dir" },
    };
    for (cases) |c| {
        const uri = try std.Uri.parse(c.url);
        const got = try derivedFilename(uri);
        try std.testing.expectEqualStrings(c.want, got);
    }
}

test "derivedFilename rejects empty or unsafe names" {
    const bad_urls = [_][]const u8{
        "https://example.com/",
        "https://example.com",
        "https://example.com/..",
        "https://example.com/path/.",
    };
    for (bad_urls) |u| {
        const uri = try std.Uri.parse(u);
        try std.testing.expectError(error.NoFilename, derivedFilename(uri));
    }
}

test "isHex accepts only hex digits" {
    try std.testing.expect(isHex("0123456789abcdefABCDEF"));
    try std.testing.expect(isHex(""));
    try std.testing.expect(!isHex("g"));
    try std.testing.expect(!isHex("0x123"));
    try std.testing.expect(!isHex(" "));
}

test "bytesToHexLower formats sha256 output" {
    var buf: [4]u8 = undefined;
    const got = bytesToHexLower(&[_]u8{ 0x0a, 0xff }, &buf);
    try std.testing.expectEqualStrings("0aff", got);
}

test "isHttpScheme accepts http and https" {
    try std.testing.expect(isHttpScheme("http"));
    try std.testing.expect(isHttpScheme("https"));
    try std.testing.expect(isHttpScheme("HTTPS"));
    try std.testing.expect(!isHttpScheme("ftp"));
    try std.testing.expect(!isHttpScheme("file"));
    try std.testing.expect(!isHttpScheme(""));
}

test "validateMultiTargetOptions rejects zero targets" {
    var err_buf: [256]u8 = undefined;
    var err_w = std.Io.Writer.Discarding.init(&err_buf);

    var opts: Options = .{};
    defer opts.deinit(std.testing.allocator);

    try std.testing.expectError(error.MissingTarget, validateMultiTargetOptions(&opts, &err_w.writer));
}

test "validateMultiTargetOptions accepts single target with -o" {
    var err_buf: [256]u8 = undefined;
    var err_w = std.Io.Writer.Discarding.init(&err_buf);

    var opts: Options = .{ .output = "/tmp/out.tar.gz" };
    defer opts.deinit(std.testing.allocator);
    try opts.targets.append(std.testing.allocator, .{ .spec = "owner/repo@1.0" });

    try validateMultiTargetOptions(&opts, &err_w.writer);
}

test "validateMultiTargetOptions accepts single target with --sha256" {
    var err_buf: [256]u8 = undefined;
    var err_w = std.Io.Writer.Discarding.init(&err_buf);

    var opts: Options = .{ .sha256 = "0000000000000000000000000000000000000000000000000000000000000000" };
    defer opts.deinit(std.testing.allocator);
    try opts.targets.append(std.testing.allocator, .{ .spec = "owner/repo@1.0" });

    try validateMultiTargetOptions(&opts, &err_w.writer);
}

test "validateMultiTargetOptions accepts multi-target with uniform flags" {
    var err_buf: [256]u8 = undefined;
    var err_w = std.Io.Writer.Discarding.init(&err_buf);

    var opts: Options = .{
        .extract = "/tmp/extract",
        .strip_components = 1,
        .minisign_pubkey = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
        .skip_verify = false,
        .keep_going = true,
    };
    defer opts.deinit(std.testing.allocator);
    try opts.targets.append(std.testing.allocator, .{ .spec = "owner/repo@1.0" });
    try opts.targets.append(std.testing.allocator, .{ .spec = "other/repo@2.0" });

    try validateMultiTargetOptions(&opts, &err_w.writer);
}

test "validateMultiTargetOptions rejects -o with multi-target" {
    var err_buf: [256]u8 = undefined;
    var err_w = std.Io.Writer.Discarding.init(&err_buf);

    var opts: Options = .{ .output = "/tmp/out.tar.gz" };
    defer opts.deinit(std.testing.allocator);
    try opts.targets.append(std.testing.allocator, .{ .spec = "owner/repo@1.0" });
    try opts.targets.append(std.testing.allocator, .{ .spec = "other/repo@2.0" });

    try std.testing.expectError(error.ConflictingFlag, validateMultiTargetOptions(&opts, &err_w.writer));
}

test "validateMultiTargetOptions rejects --sha256 with multi-target" {
    var err_buf: [256]u8 = undefined;
    var err_w = std.Io.Writer.Discarding.init(&err_buf);

    var opts: Options = .{ .sha256 = "0000000000000000000000000000000000000000000000000000000000000000" };
    defer opts.deinit(std.testing.allocator);
    try opts.targets.append(std.testing.allocator, .{ .spec = "owner/repo@1.0" });
    try opts.targets.append(std.testing.allocator, .{ .spec = "other/repo@2.0" });

    try std.testing.expectError(error.ConflictingFlag, validateMultiTargetOptions(&opts, &err_w.writer));
}
