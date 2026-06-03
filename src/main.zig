const std = @import("std");
const build_options = @import("build_options");
const Dirs = @import("dirs.zig").Dirs;
const install = @import("install.zig");
const download = @import("download.zig");
const ensurepath = @import("ensurepath.zig");
const validate = @import("validate.zig");
const release_mod = @import("release.zig");

pub const version = build_options.version;

const Io = std.Io;
const Writer = Io.Writer;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const environ = init.environ_map;

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.skip();

    var stdout_buf: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &stdout_buf);
    defer stdout.interface.flush() catch {};

    var stderr_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &stderr_buf);
    defer stderr.interface.flush() catch {};

    const cmd_str = args.next() orelse {
        try printUsage(&stdout.interface);
        return;
    };

    if (eql(cmd_str, "version")) {
        try stdout.interface.print("{s}\n", .{version});
        return;
    }
    if (eql(cmd_str, "help")) {
        try printUsage(&stdout.interface);
        return;
    }

    if (eql(cmd_str, "path")) {
        try cmdPath(allocator, io, environ, &args, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "list")) {
        if (args.next()) |arg| {
            if (eql(arg, "help")) {
                try printListUsage(&stdout.interface);
                return;
            }
            try stderr.interface.print("error: unexpected argument '{s}' for 'ghr list'\n", .{arg});
            try stderr.interface.flush();
            std.process.exit(1);
        }
        try cmdList(allocator, environ, io, &stdout.interface);
    } else if (eql(cmd_str, "install")) {
        var debug = false;
        var no_auth = false;
        var skip_verify = false;
        var skip_checksum = false;
        var skip_minisign = false;
        var skip_sigstore = false;
        var skip_authenticode = false;
        var keep_going = false;
        var minisign_pubkey: ?[]const u8 = null;
        var entries: std.ArrayListUnmanaged(release_mod.SpecWithKey) = .empty;
        defer entries.deinit(allocator);
        while (args.next()) |arg| {
            if (eql(arg, "--debug")) {
                debug = true;
            } else if (eql(arg, "--no-auth")) {
                no_auth = true;
            } else if (eql(arg, "--skip-verify")) {
                skip_verify = true;
            } else if (eql(arg, "--skip-checksum")) {
                skip_checksum = true;
            } else if (eql(arg, "--skip-minisign")) {
                skip_minisign = true;
            } else if (eql(arg, "--skip-sigstore")) {
                skip_sigstore = true;
            } else if (eql(arg, "--skip-authenticode")) {
                skip_authenticode = true;
            } else if (eql(arg, "--keep-going")) {
                keep_going = true;
            } else if (eql(arg, "--minisign")) {
                const v = args.next() orelse {
                    try stderr.interface.print("error: '--minisign' requires a base64 minisign public key value\n", .{});
                    try stderr.interface.flush();
                    std.process.exit(1);
                };
                minisign_pubkey = v;
            } else if (eql(arg, "help") and entries.items.len == 0) {
                try printInstallUsage(&stdout.interface);
                return;
            } else {
                switch (release_mod.classifySpecOrKey(arg, entries.items)) {
                    .spec => |s| try entries.append(allocator, .{ .spec = s }),
                    .key => |k| entries.items[entries.items.len - 1].key = k,
                    .lone_key => {
                        try stderr.interface.print(
                            "error: positional minisign key '{s}' must follow a spec\n",
                            .{arg},
                        );
                        try stderr.interface.print(
                            "  hint: write `<owner/repo[@tag]> <pubkey>` (key attaches to the preceding spec)\n",
                            .{},
                        );
                        try stderr.interface.flush();
                        std.process.exit(1);
                    },
                    .double_key => {
                        const last_spec = entries.items[entries.items.len - 1].spec;
                        try stderr.interface.print(
                            "error: spec '{s}' already has an inline minisign key; second key '{s}' is not allowed\n",
                            .{ last_spec, arg },
                        );
                        try stderr.interface.flush();
                        std.process.exit(1);
                    },
                }
            }
        }
        if (entries.items.len == 0) {
            try stderr.interface.print("error: 'ghr install' requires <owner/repo[@tag]> or <owner/repo/file[@tag]>\n", .{});
            try stderr.interface.flush();
            std.process.exit(1);
        }
        const gates: release_mod.VerifyGates = .{
            .skip_verify = skip_verify,
            .skip_checksum = skip_checksum,
            .skip_minisign = skip_minisign,
            .skip_sigstore = skip_sigstore,
            .skip_authenticode = skip_authenticode,
        };
        try install.cmdInstallMany(
            allocator,
            io,
            environ,
            entries.items,
            &stdout.interface,
            &stderr.interface,
            debug,
            no_auth,
            gates,
            minisign_pubkey,
            keep_going,
        );
    } else if (eql(cmd_str, "uninstall")) {
        const spec = args.next() orelse {
            try stderr.interface.print("error: 'ghr uninstall' requires <owner/repo>\n", .{});
            try stderr.interface.flush();
            std.process.exit(1);
        };
        if (eql(spec, "help")) {
            try printUninstallUsage(&stdout.interface);
            return;
        }
        try install.cmdUninstall(allocator, io, environ, spec, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "download")) {
        try download.cmdDownload(allocator, io, environ, &args, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "validate")) {
        try validate.cmdValidate(allocator, io, &args, &stdout.interface, &stderr.interface);
    } else {
        try stderr.interface.print("error: unknown command '{s}'\n\n", .{cmd_str});
        try printUsage(&stderr.interface);
        try stderr.interface.flush();
        std.process.exit(1);
    }
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn cmdPath(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const std.process.Environ.Map,
    args: *std.process.Args.Iterator,
    w: *Writer,
    err_w: *Writer,
) !void {
    const sub = args.next() orelse {
        try printPathUsage(err_w);
        try err_w.flush();
        std.process.exit(1);
    };

    if (eql(sub, "ensure")) {
        var dry_run = false;
        while (args.next()) |arg| {
            if (eql(arg, "--dry-run")) {
                dry_run = true;
            } else {
                try err_w.print("error: unknown flag '{s}' for 'ghr path ensure'\n", .{arg});
                try err_w.flush();
                std.process.exit(1);
            }
        }
        try ensurepath.cmdEnsurePath(allocator, io, environ, dry_run, w, err_w);
        return;
    }

    if (eql(sub, "bin") or eql(sub, "tools") or eql(sub, "cache")) {
        if (args.next()) |arg| {
            try err_w.print("error: unexpected argument '{s}' for 'ghr path {s}'\n", .{ arg, sub });
            try err_w.flush();
            std.process.exit(1);
        }
        const d = try Dirs.detect(allocator, environ);
        defer d.deinit();
        if (eql(sub, "bin")) {
            try w.print("{s}\n", .{d.bin});
        } else if (eql(sub, "tools")) {
            try w.print("{s}\n", .{d.tools});
        } else {
            try w.print("{s}\n", .{d.cache});
        }
        return;
    }

    if (eql(sub, "help")) {
        try printPathUsage(w);
        return;
    }

    try err_w.print("error: unknown subcommand '{s}' for 'ghr path'\n\n", .{sub});
    try printPathUsage(err_w);
    try err_w.flush();
    std.process.exit(1);
}

fn printPathUsage(w: *Writer) !void {
    try w.print(
        \\ghr path - Show ghr directories and manage PATH
        \\
        \\USAGE:
        \\    ghr path <SUBCOMMAND> [OPTIONS]
        \\
        \\SUBCOMMANDS:
        \\    ensure [--dry-run]   Add ghr's bin dir to your user PATH
        \\    bin                  Print the bin directory
        \\    tools                Print the tool storage directory
        \\    cache                Print the cache directory
        \\    help                 Show this help
        \\
    , .{});
}

fn printListUsage(w: *Writer) !void {
    try w.print(
        \\ghr list - List installed tools
        \\
        \\USAGE:
        \\    ghr list
        \\
        \\Prints each installed tool as 'owner/repo[@tag]', one per line.
        \\When the install actually verified the asset with a minisign key
        \\(inline or via --minisign), the pubkey is appended on the same line
        \\so it is directly pasteable back as `ghr install <line>`.
        \\
        \\Run 'ghr list help' to show this help.
        \\
    , .{});
}

fn printInstallUsage(w: *Writer) !void {
    try w.print(
        \\ghr install - install one or more tools from GitHub releases
        \\
        \\USAGE:
        \\    ghr install <spec> [<minisign-pubkey>] [<spec> [<minisign-pubkey>] ...] [options]
        \\
        \\Each <spec> is one of:
        \\    owner/repo[@tag]              Auto-pick the best asset for this platform
        \\    owner/repo/file[@tag]         Install a specific asset by name
        \\
        \\An optional minisign public key (56-char base64, starts with `RW` or
        \\`RU`) immediately after a spec attaches to that spec only and
        \\overrides `--minisign` for that one install. Otherwise the global
        \\`--minisign <pubkey>` default applies to every spec.
        \\
        \\Downloads the matching release asset(s), extracts each if needed,
        \\and installs the resulting binaries into ghr's bin directory.
        \\Multi-spec invocations share a single HTTP client + auth context.
        \\
        \\OPTIONS:
        \\    --debug                 Show diagnostic output for debugging
        \\    --no-auth               Skip GitHub authentication
        \\    --skip-verify           Skip every verification step (checksum, minisign, sigstore, authenticode)
        \\    --skip-checksum         Skip just the checksum-sidecar verification step
        \\    --skip-minisign         Skip just the minisign verification step
        \\    --skip-sigstore         Skip just the sigstore-bundle verification step
        \\    --skip-authenticode     Skip just the Authenticode (Windows PE) verification step
        \\    --minisign <pubkey>     Default minisign key, applied to specs without an inline key;
        \\                            <pubkey> is a base64 minisign public key string
        \\    --keep-going            Continue past per-spec failures; exit non-zero
        \\                            with a summary at the end if any spec failed
        \\
        \\EXAMPLES:
        \\    ghr install burntsushi/ripgrep@15.1.0
        \\    ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0
        \\    ghr install jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
        \\
        \\Run 'ghr install help' to show this help.
        \\
    , .{});
}

fn printUninstallUsage(w: *Writer) !void {
    try w.print(
        \\ghr uninstall - remove an installed tool
        \\
        \\USAGE:
        \\    ghr uninstall <owner/repo>
        \\
        \\Removes the installed tool's binaries from ghr's bin directory and
        \\its tool storage directory.
        \\
        \\Run 'ghr uninstall help' to show this help.
        \\
    , .{});
}

fn cmdList(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map, io: Io, w: *Writer) !void {
    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    var dir = Io.Dir.openDirAbsolute(io, d.tools, .{ .iterate = true }) catch {
        try w.print("No tools installed.\n", .{});
        return;
    };
    defer dir.close(io);

    var lines: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.endsWith(u8, entry.name, ".old")) continue; // skip tombstones
        var owner_dir = dir.openDir(io, entry.name, .{ .iterate = true }) catch continue;
        defer owner_dir.close(io);
        var repo_iter = owner_dir.iterate();
        while (try repo_iter.next(io)) |repo_entry| {
            if (repo_entry.kind != .directory) continue;
            if (std.mem.endsWith(u8, repo_entry.name, ".old")) continue; // skip tombstones
            const meta = readToolMeta(allocator, io, owner_dir, repo_entry.name);
            defer if (meta) |m| m.deinit(allocator);
            const line = try formatToolLine(allocator, entry.name, repo_entry.name, meta);
            errdefer allocator.free(line);
            try lines.append(allocator, line);
        }
    }

    if (lines.items.len == 0) {
        try w.print("No tools installed.\n", .{});
        return;
    }

    std.mem.sort([]u8, lines.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    for (lines.items) |line| {
        try w.print("{s}\n", .{line});
    }
}

/// Subset of `ghr.json` surfaced by `ghr list`. Owned strings.
const ToolListMeta = struct {
    tag: ?[]const u8 = null,
    minisign: ?[]const u8 = null,

    fn deinit(self: ToolListMeta, allocator: std.mem.Allocator) void {
        if (self.tag) |t| allocator.free(t);
        if (self.minisign) |k| allocator.free(k);
    }
};

/// Read the `tag` and `minisign` fields from a tool's `ghr.json`.
/// Returns `null` when the file is missing or malformed.
fn readToolMeta(allocator: std.mem.Allocator, io: Io, owner_dir: Io.Dir, repo_name: []const u8) ?ToolListMeta {
    var repo_dir = owner_dir.openDir(io, repo_name, .{}) catch return null;
    defer repo_dir.close(io);

    const json_bytes = repo_dir.readFileAlloc(io, "ghr.json", allocator, Io.Limit.limited(8192)) catch return null;
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(
        struct {
            tag: ?[]const u8 = null,
            minisign: ?[]const u8 = null,
        },
        allocator,
        json_bytes,
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    defer parsed.deinit();

    var result: ToolListMeta = .{};
    if (parsed.value.tag) |t| {
        result.tag = allocator.dupe(u8, t) catch {
            result.deinit(allocator);
            return null;
        };
    }
    if (parsed.value.minisign) |k| {
        if (k.len > 0) {
            result.minisign = allocator.dupe(u8, k) catch {
                result.deinit(allocator);
                return null;
            };
        }
    }
    return result;
}

/// Format a single `ghr list` line. The whole line is designed to be
/// directly pasteable as arguments to `ghr install`, so the optional
/// minisign pubkey is appended after a space (matching the per-spec
/// positional inline-key form accepted by `ghr install`).
///
/// `owner` and `repo` are ASCII-lowercased so output is canonical even
/// when the on-disk dir is still a pre-migration mixed-case name like
/// `AzureAD/foo` (GitHub is case-insensitive on slugs; we standardize).
/// `tag` is preserved verbatim — tags are case-sensitive on GitHub.
fn formatToolLine(
    allocator: std.mem.Allocator,
    owner: []const u8,
    repo: []const u8,
    meta: ?ToolListMeta,
) ![]u8 {
    const tag: ?[]const u8 = if (meta) |m| m.tag else null;
    const key: ?[]const u8 = if (meta) |m| m.minisign else null;
    var owner_buf: [256]u8 = undefined;
    var repo_buf: [256]u8 = undefined;
    const owner_lc = asciiLowerInto(&owner_buf, owner);
    const repo_lc = asciiLowerInto(&repo_buf, repo);
    if (tag) |t| {
        if (key) |k| {
            return std.fmt.allocPrint(allocator, "{s}/{s}@{s} {s}", .{ owner_lc, repo_lc, t, k });
        }
        return std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ owner_lc, repo_lc, t });
    }
    if (key) |k| {
        return std.fmt.allocPrint(allocator, "{s}/{s} {s}", .{ owner_lc, repo_lc, k });
    }
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ owner_lc, repo_lc });
}

/// ASCII-lowercase `src` into the start of `dst`. Falls back to returning
/// `src` verbatim when it doesn't fit (slug-length names always do in
/// practice; this just keeps the helper allocation-free for the common
/// case).
fn asciiLowerInto(dst: []u8, src: []const u8) []const u8 {
    if (src.len > dst.len) return src;
    for (src, 0..) |c, i| dst[i] = std.ascii.toLower(c);
    return dst[0..src.len];
}

test "formatToolLine: tag and key" {
    const line = try formatToolLine(std.testing.allocator, "cataggar", "ghr", .{
        .tag = "v0.3.0-dev.1",
        .minisign = "RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0",
    });
    defer std.testing.allocator.free(line);
    try std.testing.expectEqualStrings(
        "cataggar/ghr@v0.3.0-dev.1 RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0",
        line,
    );
}

test "formatToolLine: tag without key" {
    const line = try formatToolLine(std.testing.allocator, "BurntSushi", "ripgrep", .{
        .tag = "14.1.0",
    });
    defer std.testing.allocator.free(line);
    try std.testing.expectEqualStrings("burntsushi/ripgrep@14.1.0", line);
}

test "formatToolLine: no metadata" {
    const line = try formatToolLine(std.testing.allocator, "foo", "bar", null);
    defer std.testing.allocator.free(line);
    try std.testing.expectEqualStrings("foo/bar", line);
}

test "formatToolLine: key without tag" {
    const line = try formatToolLine(std.testing.allocator, "foo", "bar", .{
        .minisign = "RWSXXXX",
    });
    defer std.testing.allocator.free(line);
    try std.testing.expectEqualStrings("foo/bar RWSXXXX", line);
}

test "formatToolLine: lowercases mixed-case owner and repo, preserves tag" {
    const line = try formatToolLine(std.testing.allocator, "AzureAD", "Microsoft-Authentication-CLI", .{
        .tag = "0.9.6",
    });
    defer std.testing.allocator.free(line);
    try std.testing.expectEqualStrings("azuread/microsoft-authentication-cli@0.9.6", line);
}

fn printUsage(w: *Writer) !void {
    try w.print(
        \\ghr - A toolkit for GitHub releases
        \\
        \\USAGE:
        \\    ghr <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    list                                 List installed tools
        \\    install <spec> [<spec> ...]          Install one or more tools from GitHub releases
        \\    uninstall <owner/repo>               Remove an installed tool
        \\    download <spec> [<spec> ...]         Download one or more release assets
        \\    path ensure [--dry-run]              Add ghr's bin dir to your user PATH
        \\    path [bin|tools|cache]               Show ghr directories
        \\    validate <SUBCOMMAND>                Run validations against published artifacts
        \\    version                              Print version and exit
        \\    help                                 Print this help and exit
        \\
        \\Each <spec> is `owner/repo[@tag]` (auto-pick asset) or
        \\`owner/repo/file[@tag]` (specific asset).
        \\Run 'ghr <COMMAND> help' to show help for a specific command.
        \\
        \\OPTIONS:
        \\    --debug                 Show diagnostic output for debugging
        \\    --no-auth               Skip GitHub authentication
        \\    --skip-verify           Skip sigstore + SHA256 + minisign verification
        \\    --minisign <pubkey>     Require minisign signature (install/download only);
        \\                            <pubkey> is a base64 minisign public key string
        \\    --keep-going            For multi-spec install/download, continue past
        \\                            per-spec failures and exit non-zero with a summary
        \\
    , .{});
}

test {
    // Ensure tests in imported modules are discovered by `zig build test`.
    // Zig 0.16 does not auto-include tests from indirectly referenced files.
    _ = @import("install.zig");
    _ = @import("release.zig");
    _ = @import("ensurepath.zig");
    _ = @import("dirs.zig");
    _ = @import("http.zig");
    _ = @import("archive.zig");
    _ = @import("auth.zig");
    _ = @import("download.zig");
    _ = @import("validate.zig");
}
