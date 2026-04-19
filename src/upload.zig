//! `ghr upload` — create a GitHub Release and upload artifacts to it.
//!
//! Provides feature parity with tcnksm/ghr's single-command interface so
//! existing users can migrate by changing `ghr ...` to `ghr upload ...`.
//!
//! Usage: ghr upload [options] TAG [PATH]
const std = @import("std");
const builtin = @import("builtin");
const version = @import("build_options").version;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const Environ = std.process.Environ;
const EnvironMap = Environ.Map;

const user_agent = "ghr/" ++ version;

pub const Options = struct {
    token: ?[]const u8 = null,
    owner: ?[]const u8 = null,
    repo: ?[]const u8 = null,
    commitish: ?[]const u8 = null,
    name: ?[]const u8 = null,
    body: ?[]const u8 = null,
    parallelism: u32 = 0, // 0 => auto (CPU count)
    delete: bool = false, // -delete / -recreate: delete release+tag first
    replace: bool = false, // replace existing assets
    draft: bool = false,
    soft: bool = false, // stop if tag already exists
    prerelease: bool = false,
    generate_notes: bool = false,
    tag: []const u8 = "",
    path: ?[]const u8 = null,
};

pub fn cmdUpload(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    args: *std.process.Args.Iterator,
    stdout: *Writer,
    stderr: *Writer,
) !void {
    var opts = Options{};
    parseArgs(args, &opts) catch |err| switch (err) {
        error.MissingValue, error.UnknownFlag, error.MissingTag => {
            try printUsage(stderr);
            try stderr.flush();
            std.process.exit(1);
        },
    };

    if (opts.tag.len == 0) {
        try stderr.print("error: 'ghr upload' requires a TAG\n\n", .{});
        try printUsage(stderr);
        try stderr.flush();
        std.process.exit(1);
    }

    // Resolve owner/repo: explicit flags > git config remote origin.
    var owner_buf: ?[]u8 = null;
    var repo_buf: ?[]u8 = null;
    defer if (owner_buf) |b| allocator.free(b);
    defer if (repo_buf) |b| allocator.free(b);

    if (opts.owner == null or opts.repo == null) {
        if (readGitOriginRepo(allocator, io)) |parsed| {
            defer {
                allocator.free(parsed.owner);
                allocator.free(parsed.repo);
            }
            if (opts.owner == null) {
                owner_buf = try allocator.dupe(u8, parsed.owner);
                opts.owner = owner_buf.?;
            }
            if (opts.repo == null) {
                repo_buf = try allocator.dupe(u8, parsed.repo);
                opts.repo = repo_buf.?;
            }
        } else |_| {}
    }

    if (opts.owner == null or opts.repo == null) {
        try stderr.print(
            "error: could not determine owner/repo — set them with -u and -r, or run inside a git repo with a github.com remote\n",
            .{},
        );
        try stderr.flush();
        std.process.exit(1);
    }

    // Resolve token.
    var token_owned: ?[]const u8 = null;
    defer if (token_owned) |t| allocator.free(t);
    const token: []const u8 = blk: {
        if (opts.token) |t| break :blk t;
        if (environ.get("GITHUB_TOKEN")) |t| if (t.len > 0) break :blk t;
        if (environ.get("GH_TOKEN")) |t| if (t.len > 0) break :blk t;
        if (ghAuthToken(allocator, io)) |t| {
            token_owned = t;
            break :blk t;
        }
        try stderr.print(
            "error: no GitHub token found. Set GITHUB_TOKEN, use -t, or run `gh auth login`.\n",
            .{},
        );
        try stderr.flush();
        std.process.exit(1);
    };

    // Resolve API base (GitHub Enterprise via GITHUB_API).
    const api_base = normalizeApiBase(environ.get("GITHUB_API") orelse "https://api.github.com/");

    const auth_hdr_buf = try std.fmt.allocPrint(allocator, "Bearer {s}", .{token});
    defer allocator.free(auth_hdr_buf);

    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
        .write_buffer_size = 4096,
    };
    defer client.deinit();

    const owner = opts.owner.?;
    const repo = opts.repo.?;

    try stdout.print("ghr upload -> {s}/{s} tag={s}\n", .{ owner, repo, opts.tag });

    // Delete/recreate path.
    if (opts.delete) {
        if (try getReleaseByTag(allocator, &client, api_base, owner, repo, opts.tag, auth_hdr_buf)) |rel| {
            defer freeRelease(allocator, rel);
            try stdout.print("  deleting existing release id={d} ...\n", .{rel.id});
            try deleteRelease(&client, api_base, owner, repo, rel.id, auth_hdr_buf);
        }
        // Best-effort tag delete — ignore 422/404.
        deleteTagRef(&client, api_base, owner, repo, opts.tag, auth_hdr_buf) catch |err| {
            try stdout.print("  note: could not delete tag ref: {s}\n", .{@errorName(err)});
        };
    }

    // Find or create release.
    const release: ReleaseInfo = blk: {
        if (!opts.delete) {
            if (try getReleaseByTag(allocator, &client, api_base, owner, repo, opts.tag, auth_hdr_buf)) |existing| {
                if (opts.soft) {
                    defer freeRelease(allocator, existing);
                    try stdout.print("  release already exists for tag {s}; -soft set, stopping.\n", .{opts.tag});
                    return;
                }
                try stdout.print("  using existing release id={d}\n", .{existing.id});
                break :blk existing;
            }
        }
        const created = try createRelease(allocator, &client, api_base, owner, repo, opts, auth_hdr_buf);
        try stdout.print("  created release id={d}\n", .{created.id});
        break :blk created;
    };
    defer freeRelease(allocator, release);

    // Collect files to upload.
    var files = std.ArrayListUnmanaged(FileEntry).empty;
    defer {
        for (files.items) |f| allocator.free(f.abs_path);
        files.deinit(allocator);
    }
    if (opts.path) |p| {
        try collectPath(allocator, io, p, &files);
    }

    if (files.items.len == 0) {
        try stdout.print("  no files to upload\n", .{});
        return;
    }

    try stdout.print("  uploading {d} file(s) ...\n", .{files.items.len});

    // Upload (optionally in parallel).
    const cpu_count: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    const par: u32 = if (opts.parallelism == 0) cpu_count else opts.parallelism;
    try uploadAll(allocator, io, &client, api_base, owner, repo, release, files.items, opts.replace, par, auth_hdr_buf, stdout);
}

// --- arg parsing ---

fn parseArgs(args: *std.process.Args.Iterator, opts: *Options) !void {
    var positional_idx: u2 = 0;
    while (args.next()) |arg| {
        if (arg.len == 0) continue;
        if (arg[0] == '-' and arg.len > 1) {
            // tcnksm/ghr uses single-dash long flags (e.g. `-delete`). Accept
            // both single- and double-dash forms.
            const name = if (arg.len >= 2 and arg[1] == '-') arg[2..] else arg[1..];
            if (eql(name, "h") or eql(name, "help")) {
                // caller will re-print usage via error
                return error.UnknownFlag;
            } else if (eql(name, "t") or eql(name, "token")) {
                opts.token = args.next() orelse return error.MissingValue;
            } else if (eql(name, "u") or eql(name, "user") or eql(name, "username") or eql(name, "owner")) {
                opts.owner = args.next() orelse return error.MissingValue;
            } else if (eql(name, "r") or eql(name, "repo") or eql(name, "repository")) {
                opts.repo = args.next() orelse return error.MissingValue;
            } else if (eql(name, "c") or eql(name, "commitish") or eql(name, "target")) {
                opts.commitish = args.next() orelse return error.MissingValue;
            } else if (eql(name, "n") or eql(name, "name") or eql(name, "title")) {
                opts.name = args.next() orelse return error.MissingValue;
            } else if (eql(name, "b") or eql(name, "body")) {
                opts.body = args.next() orelse return error.MissingValue;
            } else if (eql(name, "p") or eql(name, "parallel") or eql(name, "parallelism")) {
                const v = args.next() orelse return error.MissingValue;
                opts.parallelism = std.fmt.parseInt(u32, v, 10) catch return error.MissingValue;
            } else if (eql(name, "delete") or eql(name, "recreate")) {
                opts.delete = true;
            } else if (eql(name, "replace")) {
                opts.replace = true;
            } else if (eql(name, "draft")) {
                opts.draft = true;
            } else if (eql(name, "soft")) {
                opts.soft = true;
            } else if (eql(name, "prerelease")) {
                opts.prerelease = true;
            } else if (eql(name, "generatenotes") or eql(name, "generate-notes")) {
                opts.generate_notes = true;
            } else {
                return error.UnknownFlag;
            }
        } else {
            switch (positional_idx) {
                0 => opts.tag = arg,
                1 => opts.path = arg,
                else => return error.UnknownFlag,
            }
            positional_idx += 1;
        }
    }
    if (opts.tag.len == 0) return error.MissingTag;
}

fn printUsage(w: *Writer) !void {
    try w.print(
        \\ghr upload — create a GitHub Release and upload artifacts.
        \\
        \\USAGE:
        \\    ghr upload [options] TAG [PATH]
        \\
        \\OPTIONS:
        \\    -t TOKEN         GitHub API token (else $GITHUB_TOKEN, $GH_TOKEN, or `gh auth token`)
        \\    -u USERNAME      Owner (default: parsed from .git/config origin URL)
        \\    -r REPO          Repository name (default: parsed from .git/config)
        \\    -c COMMIT        Target commit-ish (branch or SHA)
        \\    -n TITLE         Release title
        \\    -b BODY          Release body text
        \\    -p NUM           Parallel uploads (default: NumCPU)
        \\    -delete          Delete existing release and tag before creating (alias: -recreate)
        \\    -replace         Replace assets that already exist
        \\    -draft           Create as draft
        \\    -soft            Stop (don't re-upload) if the release already exists
        \\    -prerelease      Mark as prerelease
        \\    -generatenotes   Ask GitHub to generate release notes
        \\
        \\POSITIONAL:
        \\    TAG              Git tag for the release (required)
        \\    PATH             File or directory of artifacts to upload (optional)
        \\
        \\For GitHub Enterprise, set $GITHUB_API (e.g. https://github.company.com/api/v3/).
        \\
    , .{});
}

// --- types & helpers ---

const FileEntry = struct {
    abs_path: []u8, // owned
};

const AssetInfo = struct {
    id: u64,
    name: []const u8,
};

const ReleaseInfo = struct {
    id: u64,
    // assets: list of {id, name}; name is owned.
    assets: []AssetInfo,
    assets_buf: []u8, // backing storage for all asset names
};

fn freeRelease(allocator: std.mem.Allocator, r: ReleaseInfo) void {
    allocator.free(r.assets);
    allocator.free(r.assets_buf);
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn normalizeApiBase(s: []const u8) []const u8 {
    // Strip trailing slash for consistent concat.
    if (s.len > 0 and s[s.len - 1] == '/') return s[0 .. s.len - 1];
    return s;
}

// --- git config parsing ---

const ParsedRepo = struct {
    owner: []u8,
    repo: []u8,
};

fn readGitOriginRepo(allocator: std.mem.Allocator, io: Io) !ParsedRepo {
    // Walk up from cwd until a `.git/config` is found.
    var cwd_buf: [4096]u8 = undefined;
    const cwd_len = try Dir.cwd().realPath(io, &cwd_buf);
    const cwd = cwd_buf[0..cwd_len];
    var dir_path = try allocator.dupe(u8, cwd);
    defer allocator.free(dir_path);

    var config_path: ?[]u8 = null;
    defer if (config_path) |p| allocator.free(p);

    while (true) {
        const candidate = try std.fs.path.join(allocator, &.{ dir_path, ".git", "config" });
        if (pathIsFile(io, candidate)) {
            config_path = candidate;
            break;
        }
        allocator.free(candidate);
        const parent = std.fs.path.dirname(dir_path) orelse return error.NotInGitRepo;
        if (parent.len == dir_path.len or parent.len == 0) return error.NotInGitRepo;
        const parent_copy = try allocator.dupe(u8, parent);
        allocator.free(dir_path);
        dir_path = parent_copy;
    }

    const parent_path = std.fs.path.dirname(config_path.?) orelse return error.NotInGitRepo;
    const base_name = std.fs.path.basename(config_path.?);
    var parent_dir = try Dir.openDirAbsolute(io, parent_path, .{});
    defer parent_dir.close(io);
    const contents = try parent_dir.readFileAlloc(io, base_name, allocator, Io.Limit.limited(1024 * 1024));
    defer allocator.free(contents);

    const origin_url = findRemoteOriginUrl(contents) orelse return error.NoOriginRemote;
    return try parseOwnerRepoFromUrl(allocator, origin_url);
}

fn pathIsFile(io: Io, abs: []const u8) bool {
    const parent_path = std.fs.path.dirname(abs) orelse return false;
    const name = std.fs.path.basename(abs);
    var parent = Dir.openDirAbsolute(io, parent_path, .{}) catch return false;
    defer parent.close(io);
    const st = parent.statFile(io, name, .{}) catch return false;
    return st.kind == .file;
}

fn findRemoteOriginUrl(contents: []const u8) ?[]const u8 {
    // Minimal INI scan: look for [remote "origin"] then first url = ... under it.
    var it = std.mem.splitScalar(u8, contents, '\n');
    var in_origin = false;
    while (it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        if (line[0] == '[') {
            in_origin = std.mem.eql(u8, line, "[remote \"origin\"]");
            continue;
        }
        if (!in_origin) continue;
        // Parse "key = value"
        const eq_idx = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq_idx], " \t");
        if (!std.mem.eql(u8, key, "url")) continue;
        const val = std.mem.trim(u8, line[eq_idx + 1 ..], " \t");
        return val;
    }
    return null;
}

fn parseOwnerRepoFromUrl(allocator: std.mem.Allocator, url: []const u8) !ParsedRepo {
    // Accept forms:
    //   https://github.com/owner/repo(.git)?
    //   https://host/owner/repo(.git)? (enterprise)
    //   git@github.com:owner/repo(.git)?
    //   ssh://git@github.com/owner/repo(.git)?
    var path: []const u8 = url;
    if (std.mem.startsWith(u8, url, "http://") or std.mem.startsWith(u8, url, "https://")) {
        const scheme_end = std.mem.indexOfScalar(u8, url, ':').?;
        const after_scheme = url[scheme_end + 3 ..];
        const slash = std.mem.indexOfScalar(u8, after_scheme, '/') orelse return error.UnsupportedUrl;
        path = after_scheme[slash + 1 ..];
    } else if (std.mem.startsWith(u8, url, "ssh://")) {
        const after = url["ssh://".len..];
        const slash = std.mem.indexOfScalar(u8, after, '/') orelse return error.UnsupportedUrl;
        path = after[slash + 1 ..];
    } else if (std.mem.indexOfScalar(u8, url, '@')) |at_idx| {
        // git@host:owner/repo
        const after_at = url[at_idx + 1 ..];
        const colon = std.mem.indexOfScalar(u8, after_at, ':') orelse return error.UnsupportedUrl;
        path = after_at[colon + 1 ..];
    } else {
        return error.UnsupportedUrl;
    }

    // Strip trailing ".git" and any trailing slash/whitespace.
    var p = std.mem.trim(u8, path, " \t\r\n/");
    if (std.mem.endsWith(u8, p, ".git")) p = p[0 .. p.len - 4];

    const slash_idx = std.mem.indexOfScalar(u8, p, '/') orelse return error.UnsupportedUrl;
    const owner = p[0..slash_idx];
    const repo = p[slash_idx + 1 ..];
    if (owner.len == 0 or repo.len == 0) return error.UnsupportedUrl;
    // Reject nested paths.
    if (std.mem.indexOfScalar(u8, repo, '/') != null) return error.UnsupportedUrl;

    return .{
        .owner = try allocator.dupe(u8, owner),
        .repo = try allocator.dupe(u8, repo),
    };
}

// --- token discovery ---

fn ghAuthToken(allocator: std.mem.Allocator, io: Io) ?[]const u8 {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "gh", "auth", "token" },
        .stdout_limit = Io.Limit.limited(256),
        .stderr_limit = Io.Limit.limited(0),
    }) catch return null;
    defer allocator.free(result.stderr);

    if (result.term != .exited or result.term.exited != 0) {
        allocator.free(result.stdout);
        return null;
    }
    const trimmed = std.mem.trimEnd(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) {
        allocator.free(result.stdout);
        return null;
    }
    const token = allocator.dupe(u8, trimmed) catch {
        allocator.free(result.stdout);
        return null;
    };
    allocator.free(result.stdout);
    return token;
}

// --- GitHub API calls ---

fn jsonHeaders(auth: []const u8) [3]std.http.Header {
    return .{
        .{ .name = "Accept", .value = "application/vnd.github+json" },
        .{ .name = "Authorization", .value = auth },
        .{ .name = "Content-Type", .value = "application/json" },
    };
}

fn acceptAndAuth(auth: []const u8) [2]std.http.Header {
    return .{
        .{ .name = "Accept", .value = "application/vnd.github+json" },
        .{ .name = "Authorization", .value = auth },
    };
}

fn getReleaseByTag(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_base: []const u8,
    owner: []const u8,
    repo: []const u8,
    tag: []const u8,
    auth: []const u8,
) !?ReleaseInfo {
    const encoded = try urlEncode(allocator, tag);
    defer allocator.free(encoded);
    const url = try std.fmt.allocPrint(allocator, "{s}/repos/{s}/{s}/releases/tags/{s}", .{ api_base, owner, repo, encoded });
    defer allocator.free(url);

    var body = std.Io.Writer.Allocating.init(allocator);
    defer body.deinit();

    const hdrs = acceptAndAuth(auth);
    const res = try client.fetch(.{
        .location = .{ .url = url },
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = &hdrs,
        .response_writer = &body.writer,
    });
    if (res.status == .not_found) return null;
    if (res.status != .ok) {
        std.log.err("GET release by tag failed: HTTP {d}: {s}", .{ @intFromEnum(res.status), body.written() });
        return error.GitHubApiError;
    }
    return try parseReleaseJson(allocator, body.written());
}

fn createRelease(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    api_base: []const u8,
    owner: []const u8,
    repo: []const u8,
    opts: Options,
    auth: []const u8,
) !ReleaseInfo {
    const url = try std.fmt.allocPrint(allocator, "{s}/repos/{s}/{s}/releases", .{ api_base, owner, repo });
    defer allocator.free(url);

    var body_buf = std.Io.Writer.Allocating.init(allocator);
    defer body_buf.deinit();
    const bw = &body_buf.writer;
    try bw.writeAll("{\"tag_name\":");
    try writeJsonString(bw, opts.tag);
    if (opts.commitish) |c| {
        try bw.writeAll(",\"target_commitish\":");
        try writeJsonString(bw, c);
    }
    if (opts.name) |n| {
        try bw.writeAll(",\"name\":");
        try writeJsonString(bw, n);
    }
    if (opts.body) |b| {
        try bw.writeAll(",\"body\":");
        try writeJsonString(bw, b);
    }
    if (opts.draft) try bw.writeAll(",\"draft\":true");
    if (opts.prerelease) try bw.writeAll(",\"prerelease\":true");
    if (opts.generate_notes) try bw.writeAll(",\"generate_release_notes\":true");
    try bw.writeAll("}");

    var resp = std.Io.Writer.Allocating.init(allocator);
    defer resp.deinit();

    const hdrs = jsonHeaders(auth);
    const res = try client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body_buf.written(),
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = &hdrs,
        .response_writer = &resp.writer,
    });
    if (res.status != .created and res.status != .ok) {
        std.log.err("create release failed: HTTP {d}: {s}", .{ @intFromEnum(res.status), resp.written() });
        return error.GitHubApiError;
    }
    return try parseReleaseJson(allocator, resp.written());
}

fn deleteRelease(
    client: *std.http.Client,
    api_base: []const u8,
    owner: []const u8,
    repo: []const u8,
    release_id: u64,
    auth: []const u8,
) !void {
    var buf: [512]u8 = undefined;
    const url = try std.fmt.bufPrint(&buf, "{s}/repos/{s}/{s}/releases/{d}", .{ api_base, owner, repo, release_id });
    const hdrs = acceptAndAuth(auth);
    const res = try client.fetch(.{
        .location = .{ .url = url },
        .method = .DELETE,
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = &hdrs,
    });
    if (res.status != .no_content and res.status != .not_found) {
        std.log.err("delete release failed: HTTP {d}", .{@intFromEnum(res.status)});
        return error.GitHubApiError;
    }
}

fn deleteTagRef(
    client: *std.http.Client,
    api_base: []const u8,
    owner: []const u8,
    repo: []const u8,
    tag: []const u8,
    auth: []const u8,
) !void {
    var buf: [1024]u8 = undefined;
    const url = try std.fmt.bufPrint(&buf, "{s}/repos/{s}/{s}/git/refs/tags/{s}", .{ api_base, owner, repo, tag });
    const hdrs = acceptAndAuth(auth);
    const res = try client.fetch(.{
        .location = .{ .url = url },
        .method = .DELETE,
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = &hdrs,
    });
    if (res.status != .no_content and res.status != .not_found and res.status != .unprocessable_entity) {
        return error.GitHubApiError;
    }
}

fn deleteAsset(
    client: *std.http.Client,
    api_base: []const u8,
    owner: []const u8,
    repo: []const u8,
    asset_id: u64,
    auth: []const u8,
) !void {
    var buf: [512]u8 = undefined;
    const url = try std.fmt.bufPrint(&buf, "{s}/repos/{s}/{s}/releases/assets/{d}", .{ api_base, owner, repo, asset_id });
    const hdrs = acceptAndAuth(auth);
    const res = try client.fetch(.{
        .location = .{ .url = url },
        .method = .DELETE,
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = &hdrs,
    });
    if (res.status != .no_content and res.status != .not_found) {
        return error.GitHubApiError;
    }
}

fn uploadAsset(
    allocator: std.mem.Allocator,
    io: Io,
    client: *std.http.Client,
    api_base: []const u8,
    owner: []const u8,
    repo: []const u8,
    release_id: u64,
    file_abs_path: []const u8,
    auth: []const u8,
) !void {
    const uploads_base = try apiBaseToUploadsBase(allocator, api_base);
    defer allocator.free(uploads_base);

    const basename = std.fs.path.basename(file_abs_path);
    const encoded_name = try urlEncode(allocator, basename);
    defer allocator.free(encoded_name);
    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/repos/{s}/{s}/releases/{d}/assets?name={s}",
        .{ uploads_base, owner, repo, release_id, encoded_name },
    );
    defer allocator.free(url);

    // Read entire file into memory. GitHub Releases asset limit is 2 GiB;
    // typical artifacts are tens of MB, so this is acceptable for now.
    const parent_path = std.fs.path.dirname(file_abs_path) orelse ".";
    const base_name = std.fs.path.basename(file_abs_path);
    var parent = try Dir.openDirAbsolute(io, parent_path, .{});
    defer parent.close(io);
    const bytes = try parent.readFileAlloc(io, base_name, allocator, Io.Limit.limited(2 * 1024 * 1024 * 1024));
    defer allocator.free(bytes);

    const hdrs = [_]std.http.Header{
        .{ .name = "Accept", .value = "application/vnd.github+json" },
        .{ .name = "Authorization", .value = auth },
        .{ .name = "Content-Type", .value = "application/octet-stream" },
    };

    var resp = std.Io.Writer.Allocating.init(allocator);
    defer resp.deinit();

    const res = try client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = bytes,
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = &hdrs,
        .response_writer = &resp.writer,
    });
    if (res.status != .created and res.status != .ok) {
        std.log.err("upload {s} failed: HTTP {d}: {s}", .{ basename, @intFromEnum(res.status), resp.written() });
        return error.UploadFailed;
    }
}

fn apiBaseToUploadsBase(allocator: std.mem.Allocator, api_base: []const u8) ![]u8 {
    // github.com: https://api.github.com -> https://uploads.github.com
    // enterprise: https://host/api/v3 -> https://host/api/uploads
    if (std.mem.eql(u8, api_base, "https://api.github.com")) {
        return allocator.dupe(u8, "https://uploads.github.com");
    }
    // Enterprise: swap trailing "/api/v3" (or "/api/vX") with "/api/uploads".
    if (std.mem.indexOf(u8, api_base, "/api/")) |i| {
        const before = api_base[0 .. i + "/api/".len];
        return std.fmt.allocPrint(allocator, "{s}uploads", .{before});
    }
    return allocator.dupe(u8, api_base);
}

// --- JSON helpers ---

fn writeJsonString(w: *Writer, s: []const u8) !void {
    try w.writeByte('"');
    const hex = "0123456789ABCDEF";
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x08 => try w.writeAll("\\b"),
            0x0C => try w.writeAll("\\f"),
            else => {
                if (c < 0x20) {
                    var esc: [6]u8 = [_]u8{ '\\', 'u', '0', '0', 0, 0 };
                    esc[4] = hex[(c >> 4) & 0xF];
                    esc[5] = hex[c & 0xF];
                    try w.writeAll(&esc);
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
    try w.writeByte('"');
}

fn parseReleaseJson(allocator: std.mem.Allocator, body: []const u8) !ReleaseInfo {
    const ReleaseJson = struct {
        id: u64,
        assets: []struct { id: u64, name: []const u8 } = &.{},
    };
    const parsed = try std.json.parseFromSlice(ReleaseJson, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    // Copy asset names into a single owned buffer so the ReleaseInfo outlives `parsed`.
    var total: usize = 0;
    for (parsed.value.assets) |a| total += a.name.len;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);
    const assets = try allocator.alloc(AssetInfo, parsed.value.assets.len);
    errdefer allocator.free(assets);

    var cursor: usize = 0;
    for (parsed.value.assets, 0..) |a, i| {
        @memcpy(buf[cursor .. cursor + a.name.len], a.name);
        assets[i] = .{ .id = a.id, .name = buf[cursor .. cursor + a.name.len] };
        cursor += a.name.len;
    }

    return .{ .id = parsed.value.id, .assets = assets, .assets_buf = buf };
}

fn urlEncode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const hex = "0123456789ABCDEF";
    for (s) |c| {
        const safe = (c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~';
        if (safe) {
            try buf.append(allocator, c);
        } else {
            try buf.append(allocator, '%');
            try buf.append(allocator, hex[(c >> 4) & 0xF]);
            try buf.append(allocator, hex[c & 0xF]);
        }
    }
    return try buf.toOwnedSlice(allocator);
}

// --- file collection ---

fn collectPath(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    out: *std.ArrayListUnmanaged(FileEntry),
) !void {
    // Resolve to absolute.
    const abs = if (std.fs.path.isAbsolute(path)) try allocator.dupe(u8, path) else blk: {
        var cwd_buf: [4096]u8 = undefined;
        const cwd_len = try Dir.cwd().realPath(io, &cwd_buf);
        break :blk try std.fs.path.join(allocator, &.{ cwd_buf[0..cwd_len], path });
    };

    const parent_path = std.fs.path.dirname(abs) orelse {
        allocator.free(abs);
        return error.InvalidPath;
    };
    const basename = std.fs.path.basename(abs);
    var parent = try Dir.openDirAbsolute(io, parent_path, .{});
    defer parent.close(io);
    const st = try parent.statFile(io, basename, .{});

    if (st.kind == .file) {
        try out.append(allocator, .{ .abs_path = abs });
        return;
    }
    if (st.kind != .directory) {
        allocator.free(abs);
        return error.InvalidPath;
    }
    defer allocator.free(abs);
    var dir = try Dir.openDirAbsolute(io, abs, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const joined = try std.fs.path.join(allocator, &.{ abs, entry.name });
        try out.append(allocator, .{ .abs_path = joined });
    }
}

// --- parallel upload driver ---

const UploadJob = struct {
    allocator: std.mem.Allocator,
    io: Io,
    client: *std.http.Client,
    api_base: []const u8,
    owner: []const u8,
    repo: []const u8,
    release: ReleaseInfo,
    file: *const FileEntry,
    replace: bool,
    auth: []const u8,
    result: anyerror!void = {},
};

fn runJob(job: *UploadJob) void {
    job.result = runJobInner(job);
}

fn runJobInner(job: *UploadJob) !void {
    const basename = std.fs.path.basename(job.file.abs_path);
    if (findAssetByName(job.release.assets, basename)) |existing_id| {
        if (!job.replace) return error.AssetExists;
        try deleteAsset(job.client, job.api_base, job.owner, job.repo, existing_id, job.auth);
    }
    try uploadAsset(job.allocator, job.io, job.client, job.api_base, job.owner, job.repo, job.release.id, job.file.abs_path, job.auth);
}

fn findAssetByName(assets: []const AssetInfo, name: []const u8) ?u64 {
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, name)) return a.id;
    }
    return null;
}

fn uploadAll(
    allocator: std.mem.Allocator,
    io: Io,
    client: *std.http.Client,
    api_base: []const u8,
    owner: []const u8,
    repo: []const u8,
    release: ReleaseInfo,
    files: []const FileEntry,
    replace: bool,
    parallelism: u32,
    auth: []const u8,
    out_w: *Writer,
) !void {
    const par = @max(parallelism, 1);

    const jobs = try allocator.alloc(UploadJob, files.len);
    defer allocator.free(jobs);
    for (files, 0..) |*f, i| {
        jobs[i] = .{
            .allocator = allocator,
            .io = io,
            .client = client,
            .api_base = api_base,
            .owner = owner,
            .repo = repo,
            .release = release,
            .file = f,
            .replace = replace,
            .auth = auth,
        };
    }

    var any_error = false;

    if (par == 1) {
        for (jobs) |*j| {
            runJob(j);
            try reportResult(j, out_w, &any_error);
        }
    } else {
        // Spawn in batches of `par` and join each batch.
        var i: usize = 0;
        while (i < jobs.len) {
            const batch_end = @min(i + par, jobs.len);
            const threads = try allocator.alloc(std.Thread, batch_end - i);
            defer allocator.free(threads);
            for (threads, jobs[i..batch_end]) |*t, *j| {
                t.* = try std.Thread.spawn(.{}, runJob, .{j});
            }
            for (threads) |t| t.join();
            for (jobs[i..batch_end]) |*j| try reportResult(j, out_w, &any_error);
            i = batch_end;
        }
    }

    if (any_error) return error.SomeUploadsFailed;
}

fn reportResult(j: *UploadJob, out_w: *Writer, any_error: *bool) !void {
    const basename = std.fs.path.basename(j.file.abs_path);
    if (j.result) |_| {
        try out_w.print("    uploaded: {s}\n", .{basename});
    } else |err| switch (err) {
        error.AssetExists => {
            try out_w.print("    skipped (already uploaded; use -replace): {s}\n", .{basename});
        },
        else => {
            any_error.* = true;
            try out_w.print("    failed: {s}: {s}\n", .{ basename, @errorName(err) });
        },
    }
}

// --- tests ---

test "parseOwnerRepoFromUrl handles common forms" {
    const a = std.testing.allocator;
    {
        const r = try parseOwnerRepoFromUrl(a, "https://github.com/cataggar/ghr.git");
        defer {
            a.free(r.owner);
            a.free(r.repo);
        }
        try std.testing.expectEqualStrings("cataggar", r.owner);
        try std.testing.expectEqualStrings("ghr", r.repo);
    }
    {
        const r = try parseOwnerRepoFromUrl(a, "git@github.com:cataggar/ghr.git");
        defer {
            a.free(r.owner);
            a.free(r.repo);
        }
        try std.testing.expectEqualStrings("cataggar", r.owner);
        try std.testing.expectEqualStrings("ghr", r.repo);
    }
    {
        const r = try parseOwnerRepoFromUrl(a, "ssh://git@github.com/cataggar/ghr");
        defer {
            a.free(r.owner);
            a.free(r.repo);
        }
        try std.testing.expectEqualStrings("cataggar", r.owner);
        try std.testing.expectEqualStrings("ghr", r.repo);
    }
    {
        const r = try parseOwnerRepoFromUrl(a, "https://github.company.com/acme/widget.git");
        defer {
            a.free(r.owner);
            a.free(r.repo);
        }
        try std.testing.expectEqualStrings("acme", r.owner);
        try std.testing.expectEqualStrings("widget", r.repo);
    }
}

test "findRemoteOriginUrl picks the origin section" {
    const cfg =
        \\[core]
        \\    repositoryformatversion = 0
        \\[remote "upstream"]
        \\    url = https://github.com/other/other.git
        \\[remote "origin"]
        \\    url = https://github.com/cataggar/ghr.git
        \\    fetch = +refs/heads/*:refs/remotes/origin/*
        \\
    ;
    const got = findRemoteOriginUrl(cfg) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("https://github.com/cataggar/ghr.git", got);
}

test "apiBaseToUploadsBase maps github.com and enterprise" {
    const a = std.testing.allocator;
    {
        const u = try apiBaseToUploadsBase(a, "https://api.github.com");
        defer a.free(u);
        try std.testing.expectEqualStrings("https://uploads.github.com", u);
    }
    {
        const u = try apiBaseToUploadsBase(a, "https://github.company.com/api/v3");
        defer a.free(u);
        try std.testing.expectEqualStrings("https://github.company.com/api/uploads", u);
    }
}

test "urlEncode percent-encodes unsafe chars" {
    const a = std.testing.allocator;
    const got = try urlEncode(a, "v1.0 beta/+");
    defer a.free(got);
    try std.testing.expectEqualStrings("v1.0%20beta%2F%2B", got);
}

test "normalizeApiBase strips trailing slash" {
    try std.testing.expectEqualStrings("https://api.github.com", normalizeApiBase("https://api.github.com/"));
    try std.testing.expectEqualStrings("https://api.github.com", normalizeApiBase("https://api.github.com"));
}
