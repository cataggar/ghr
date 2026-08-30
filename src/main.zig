const std = @import("std");
const build_options = @import("build_options");
const Dirs = @import("dirs.zig").Dirs;
const dns = @import("dns.zig");
const install = @import("install.zig");
const download = @import("download.zig");
const ensurepath = @import("ensurepath.zig");
const validate = @import("validate.zig");
const minisign_cmd = @import("minisign_cmd.zig");
const release_mod = @import("release.zig");
const link = @import("link.zig");

pub const version = build_options.version;

const Io = std.Io;
const Writer = Io.Writer;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    // Resolve host names even where `/etc/resolv.conf` defeats the standard
    // library's parser, such as WSL on a corporate network. See `dns.zig`.
    // Remove this once ghr builds against a Zig release that fixes
    // https://codeberg.org/ziglang/zig/issues/35371 (milestone 0.17.0).
    const io = dns.wrap(init.io);
    const environ = init.environ_map;

    var stdout_buf: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &stdout_buf);
    defer stdout.interface.flush() catch {};

    var stderr_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &stderr_buf);
    defer stderr.interface.flush() catch {};

    {
        var help_args_iter = try init.minimal.args.iterateAllocator(allocator);
        defer help_args_iter.deinit();
        _ = help_args_iter.skip();

        var help_args: std.ArrayListUnmanaged([]const u8) = .empty;
        defer help_args.deinit(allocator);
        while (help_args_iter.next()) |arg| {
            try help_args.append(allocator, arg);
        }
        if (detectHelpTopic(help_args.items)) |topic| {
            try printHelpTopic(topic, &stdout.interface);
            return;
        }
    }

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.skip();

    const cmd_str = args.next() orelse {
        try printUsage(&stdout.interface);
        return;
    };

    if (eql(cmd_str, "version")) {
        try stdout.interface.print("{s}\n", .{version});
        return;
    }
    if (eql(cmd_str, "path")) {
        try cmdPath(allocator, io, environ, &args, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "list")) {
        if (args.next()) |arg| {
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
        var skip_attestation = false;
        var skip_authenticode = false;
        var keep_going = false;
        var minisign_pubkey: ?[]const u8 = null;
        var entries: std.ArrayListUnmanaged(release_mod.SpecWithKey) = .empty;
        defer entries.deinit(allocator);
        var bin_filters: std.ArrayListUnmanaged([]const u8) = .empty;
        defer bin_filters.deinit(allocator);
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
            } else if (eql(arg, "--skip-attestation")) {
                skip_attestation = true;
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
            } else if (eql(arg, "--bin")) {
                const v = args.next() orelse {
                    try stderr.interface.print("error: '--bin' requires an installed command name\n", .{});
                    try stderr.interface.flush();
                    std.process.exit(1);
                };
                try bin_filters.append(allocator, v);
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
        const gates: release_mod.VerifyGates = .{
            .skip_verify = skip_verify,
            .skip_checksum = skip_checksum,
            .skip_minisign = skip_minisign,
            .skip_sigstore = skip_sigstore,
            .skip_attestation = skip_attestation,
            .skip_authenticode = skip_authenticode,
        };
        install.cmdInstallMany(
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
            bin_filters.items,
            keep_going,
        ) catch |err| switch (err) {
            error.MissingInstallSpec, error.BinFilterRequiresSingleSpec => std.process.exit(1),
            else => return err,
        };
    } else if (eql(cmd_str, "uninstall")) {
        const spec = args.next() orelse {
            try stderr.interface.print("error: 'ghr uninstall' requires <owner/repo>\n", .{});
            try stderr.interface.flush();
            std.process.exit(1);
        };
        try install.cmdUninstall(allocator, io, environ, spec, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "download")) {
        try download.cmdDownload(allocator, io, environ, &args, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "link")) {
        try runLinkCmd(allocator, io, environ, &args, &stdout.interface, &stderr.interface, .link);
    } else if (eql(cmd_str, "unlink")) {
        try runLinkCmd(allocator, io, environ, &args, &stdout.interface, &stderr.interface, .unlink);
    } else if (eql(cmd_str, "validate")) {
        try validate.cmdValidate(allocator, io, &args, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "minisign")) {
        try minisign_cmd.cmdMinisign(allocator, io, environ, &args, &stdout.interface, &stderr.interface);
    } else {
        try stderr.interface.print("error: unknown command '{s}'\n\n", .{cmd_str});
        try printUsage(&stderr.interface);
        try stderr.interface.flush();
        std.process.exit(1);
    }
}

const HelpTopic = enum {
    root,
    list,
    install,
    uninstall,
    download,
    link,
    unlink,
    path,
    path_add,
    path_bin,
    path_tools,
    path_cache,
    validate,
    validate_strip_authenticode,
    minisign,
    minisign_sign,
    version,
};

fn detectHelpTopic(args: []const []const u8) ?HelpTopic {
    if (args.len == 0) return null;
    if (isHelpFlag(args[0])) return .root;

    const command = args[0];
    if (eql(command, "path")) {
        return detectNestedHelpTopic(args[1..], &.{
            .{ "add", .path_add },
            .{ "bin", .path_bin },
            .{ "tools", .path_tools },
            .{ "cache", .path_cache },
        }, .path);
    }
    if (eql(command, "validate")) {
        return detectNestedHelpTopic(args[1..], &.{
            .{ "strip-authenticode", .validate_strip_authenticode },
        }, .validate);
    }
    if (eql(command, "minisign")) {
        return detectNestedHelpTopic(args[1..], &.{
            .{ "sign", .minisign_sign },
        }, .minisign);
    }
    if (!containsHelpFlag(args[1..])) return null;

    if (eql(command, "list")) return .list;
    if (eql(command, "install")) return .install;
    if (eql(command, "uninstall")) return .uninstall;
    if (eql(command, "download")) return .download;
    if (eql(command, "link")) return .link;
    if (eql(command, "unlink")) return .unlink;
    if (eql(command, "version")) return .version;
    return null;
}

fn detectNestedHelpTopic(
    args: []const []const u8,
    subcommands: []const struct { []const u8, HelpTopic },
    parent: HelpTopic,
) ?HelpTopic {
    if (args.len == 0) return null;
    if (isHelpFlag(args[0])) return parent;
    if (!containsHelpFlag(args[1..])) return null;

    for (subcommands) |subcommand| {
        if (eql(args[0], subcommand[0])) return subcommand[1];
    }
    return null;
}

fn containsHelpFlag(args: []const []const u8) bool {
    for (args) |arg| {
        if (isHelpFlag(arg)) return true;
    }
    return false;
}

fn isHelpFlag(arg: []const u8) bool {
    return eql(arg, "-h") or eql(arg, "--help");
}

fn printHelpTopic(topic: HelpTopic, w: *Writer) !void {
    switch (topic) {
        .root => try printUsage(w),
        .list => try printListUsage(w),
        .install => try printInstallUsage(w),
        .uninstall => try printUninstallUsage(w),
        .download => try download.printDownloadUsage(w),
        .link => try printLinkUsage(w),
        .unlink => try printUnlinkUsage(w),
        .path => try printPathUsage(w),
        .path_add => try printPathAddUsage(w),
        .path_bin => try printPathDirectoryUsage(w, "bin", "Print the bin directory"),
        .path_tools => try printPathDirectoryUsage(w, "tools", "Print the tool storage directory"),
        .path_cache => try printPathDirectoryUsage(w, "cache", "Print the download cache directory"),
        .validate => try validate.printUsage(w),
        .validate_strip_authenticode => try validate.printStripUsage(w),
        .minisign => try minisign_cmd.printUsage(w),
        .minisign_sign => try minisign_cmd.printSignUsage(w),
        .version => try printVersionUsage(w),
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

    if (eql(sub, "add") or eql(sub, "ensure")) {
        var dry_run = false;
        while (args.next()) |arg| {
            if (eql(arg, "--dry-run")) {
                dry_run = true;
            } else {
                try err_w.print("error: unknown flag '{s}' for 'ghr path {s}'\n", .{ arg, sub });
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

    try err_w.print("error: unknown subcommand '{s}' for 'ghr path'\n\n", .{sub});
    try printPathUsage(err_w);
    try err_w.flush();
    std.process.exit(1);
}

const LinkKind = enum { link, unlink };

fn runLinkCmd(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const std.process.Environ.Map,
    args: *std.process.Args.Iterator,
    w: *Writer,
    err_w: *Writer,
    kind: LinkKind,
) !void {
    var spec: ?[]const u8 = null;
    var filters: std.ArrayListUnmanaged([]const u8) = .empty;
    defer filters.deinit(allocator);

    while (args.next()) |arg| {
        if (eql(arg, "--bin")) {
            const v = args.next() orelse {
                try err_w.print("error: '--bin' requires a bin name\n", .{});
                try err_w.flush();
                std.process.exit(1);
            };
            try filters.append(allocator, v);
        } else if (std.mem.startsWith(u8, arg, "--")) {
            try err_w.print("error: unknown flag '{s}' for 'ghr {s}'\n", .{ arg, @tagName(kind) });
            try err_w.flush();
            std.process.exit(1);
        } else {
            if (spec != null) {
                try err_w.print(
                    "error: 'ghr {s}' accepts a single spec (got '{s}' and '{s}')\n",
                    .{ @tagName(kind), spec.?, arg },
                );
                try err_w.flush();
                std.process.exit(1);
            }
            spec = arg;
        }
    }

    const spec_str = spec orelse {
        try err_w.print("error: 'ghr {s}' requires <owner/repo> or a bare executable name\n", .{@tagName(kind)});
        try err_w.flush();
        std.process.exit(1);
    };

    // A spec with no `/` is interpreted as a bare Windows-PATH executable
    // name (e.g. `ghr link git`). An owner/repo spec must contain `/`.
    // Reject `@` in bare form upfront so `git@1.0` doesn't slip through.
    const looks_bare = std.mem.indexOfScalar(u8, spec_str, '/') == null;
    if (looks_bare and std.mem.indexOfScalar(u8, spec_str, '@') != null) {
        try err_w.print(
            "error: bare executable names cannot contain '@' (got '{s}')\n",
            .{spec_str},
        );
        try err_w.flush();
        std.process.exit(1);
    }

    const result = if (looks_bare) switch (kind) {
        .link => link.cmdLinkBareExe(allocator, io, environ, spec_str, filters.items, w, err_w),
        .unlink => link.cmdUnlinkBareExe(allocator, io, environ, spec_str, filters.items, w, err_w),
    } else switch (kind) {
        .link => link.cmdLink(allocator, io, environ, spec_str, filters.items, w, err_w),
        .unlink => link.cmdUnlink(allocator, io, environ, spec_str, filters.items, w, err_w),
    };
    result catch |err| switch (err) {
        link.LinkCmdError.LinkStepFailed => std.process.exit(1),
        else => return err,
    };
}

fn printLinkUsage(w: *Writer) !void {
    try w.print(
        \\ghr link - link Windows-side bins or PATH executables into WSL
        \\
        \\USAGE:
        \\    ghr link <owner/repo> [--bin <name>] [--bin <name> ...]
        \\    ghr link <name>                              (e.g. 'ghr link git')
        \\
        \\With <owner/repo>, reads `ghr.json` from the Windows-side install
        \\of that tool and creates Linux symlinks in ghr's bin directory
        \\pointing at the original `.exe` binaries (via `/mnt/c/...`). WSL
        \\interop executes the `.exe` transparently.
        \\
        \\Without `--bin`, links every bin advertised by the Windows
        \\install and removes any previously-linked bins that no longer
        \\exist (the command is a reconciler).
        \\
        \\With one or more `--bin <name>` filters, only the named bins
        \\are touched; other previously-linked entries are left alone.
        \\
        \\With a bare <name> (no `/`), looks up the Windows `%PATH%` via
        \\`where.exe`, converts the result with `wslpath -u`, and creates
        \\an entry in ghr's bin directory:
        \\  * `.exe` / `.com` targets  → symlink (WSL interop direct-executes)
        \\  * `.cmd` / `.bat` targets  → bash wrapper invoking cmd.exe
        \\`.ps1` and other extensions are rejected. `--bin` is not
        \\supported with the bare form.
        \\
        \\Requires WSL_INTEROP to be set (i.e., running in WSL).
        \\
        \\Environment:
        \\    GHR_WIN_TOOLS_DIR    Override Windows tools dir discovery.
        \\                         Accepts either a WSL path
        \\                         (e.g. /mnt/c/Users/x/AppData/Roaming/ghr/data/tools)
        \\                         or a Windows path (e.g. C:\Users\x\AppData\Roaming\ghr\data\tools).
        \\
        \\EXAMPLES:
        \\    ghr link AzureAD/microsoft-authentication-cli
        \\    ghr link cataggar/microsoft-authentication-cli --bin azureauth
        \\    ghr link git
        \\    ghr link az
        \\
        \\OPTIONS:
        \\    -h, --help  Show this help
        \\
    , .{});
}

fn printUnlinkUsage(w: *Writer) !void {
    try w.print(
        \\ghr unlink - remove WSL symlinks created by 'ghr link'
        \\
        \\USAGE:
        \\    ghr unlink <owner/repo> [--bin <name> ...]
        \\    ghr unlink <name>                            (bare executable form)
        \\
        \\With <owner/repo>, removes every symlink ghr created for that
        \\tool from the bin directory. Verifies each symlink still points
        \\where the manifest recorded before deleting, so a user-rewritten
        \\symlink is never clobbered.
        \\
        \\With `--bin <name>` filters, only the named entries are
        \\removed.
        \\
        \\With a bare <name> (no `/`), removes the single symlink that
        \\was created by `ghr link <name>`. `--bin` is not supported
        \\with the bare form.
        \\
        \\Requires WSL_INTEROP to be set (i.e., running in WSL).
        \\
        \\OPTIONS:
        \\    -h, --help  Show this help
        \\
    , .{});
}

fn printPathUsage(w: *Writer) !void {
    try w.print(
        \\ghr path - Show ghr directories and manage PATH
        \\
        \\USAGE:
        \\    ghr path <SUBCOMMAND> [OPTIONS]
        \\
        \\SUBCOMMANDS:
        \\    add [--dry-run]      Add ghr's bin dir to your user PATH
        \\    bin                  Print the bin directory
        \\    tools                Print the tool storage directory
        \\    cache                Print the cache directory
        \\
        \\OPTIONS:
        \\    -h, --help           Show this help
        \\
    , .{});
}

fn printPathAddUsage(w: *Writer) !void {
    try w.print(
        \\ghr path add - add ghr's bin directory to your user PATH
        \\
        \\USAGE:
        \\    ghr path add [--dry-run]
        \\
        \\OPTIONS:
        \\    --dry-run   Print the change without modifying shell configuration
        \\    -h, --help  Show this help
        \\
    , .{});
}

fn printPathDirectoryUsage(w: *Writer, subcommand: []const u8, description: []const u8) !void {
    try w.print(
        \\ghr path {s} - {s}
        \\
        \\USAGE:
        \\    ghr path {s}
        \\
        \\OPTIONS:
        \\    -h, --help  Show this help
        \\
    , .{ subcommand, description, subcommand });
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
        \\OPTIONS:
        \\    -h, --help  Show this help
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
        \\`--bin` filters links and metadata after extraction; archive contents
        \\remain fully extracted in the tool directory.
        \\Multi-spec invocations share a single HTTP client + auth context.
        \\
        \\OPTIONS:
        \\    --bin <name>            Link and record only this installed command (repeatable);
        \\                            requires exactly one spec and is not supported for wasm modules
        \\    --debug                 Show diagnostic output for debugging
        \\    --no-auth               Skip GitHub authentication
        \\    --skip-verify           Skip every verification step (checksum, minisign, sigstore, attestation, authenticode)
        \\    --skip-checksum         Skip checksum verification (GitHub asset digest + .sha256/.sha512 sidecar)
        \\    --skip-minisign         Skip just the minisign verification step
        \\    --skip-sigstore         Skip just the published .sigstore.json sidecar verification step
        \\    --skip-attestation      Skip just the GitHub-native artifact attestation verification step
        \\    --skip-authenticode     Skip just the Authenticode (Windows PE) verification step
        \\    --minisign <pubkey>     Default minisign key, applied to specs without an inline key;
        \\                            <pubkey> is a base64 minisign public key string
        \\    --keep-going            Continue past per-spec failures; exit non-zero
        \\                            with a summary at the end if any spec failed
        \\    -h, --help              Show this help
        \\
        \\EXAMPLES:
        \\    ghr install burntsushi/ripgrep@15.1.0
        \\    ghr install azuread/microsoft-authentication-cli --bin azureauth
        \\    ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0
        \\    ghr install jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
        \\
    , .{});
}

fn printUninstallUsage(w: *Writer) !void {
    try w.print(
        \\ghr uninstall - remove an installed tool
        \\
        \\USAGE:
        \\    ghr uninstall <owner/repo>
        \\    ghr uninstall <owner/repo/wasm-stem>
        \\
        \\Removes the installed tool's binaries from ghr's bin directory and
        \\its tool storage directory.
        \\
        \\A wasm release installs each module as its own unit. Pass
        \\<owner/repo/wasm-stem> to remove a single module. Plain
        \\<owner/repo> removes only the repo-level (archive) install and
        \\leaves any wasm modules in place.
        \\
        \\OPTIONS:
        \\    -h, --help  Show this help
        \\
    , .{});
}

fn printVersionUsage(w: *Writer) !void {
    try w.print(
        \\ghr version - print the ghr version
        \\
        \\USAGE:
        \\    ghr version
        \\
        \\OPTIONS:
        \\    -h, --help  Show this help
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
        if (std.mem.endsWith(u8, entry.name, ".old") or
            (std.mem.startsWith(u8, entry.name, ".") and std.mem.endsWith(u8, entry.name, ".staging"))) continue;
        var owner_dir = dir.openDir(io, entry.name, .{ .iterate = true }) catch continue;
        defer owner_dir.close(io);
        var repo_iter = owner_dir.iterate();
        while (try repo_iter.next(io)) |repo_entry| {
            if (repo_entry.kind != .directory) continue;
            if (std.mem.endsWith(u8, repo_entry.name, ".old") or
                (std.mem.startsWith(u8, repo_entry.name, ".") and std.mem.endsWith(u8, repo_entry.name, ".staging"))) continue;

            // Repo-level (archive / bare binary) install: `<owner>/<repo>/ghr.json`.
            const repo_meta = readToolMeta(allocator, io, owner_dir, repo_entry.name);
            defer if (repo_meta) |m| m.deinit(allocator);
            if (repo_meta != null) {
                const line = try formatToolLine(allocator, entry.name, repo_entry.name, repo_meta);
                errdefer allocator.free(line);
                try lines.append(allocator, line);
            }

            // Descend into per-module wasm units: `<owner>/<repo>/<stem>/ghr.json`.
            var module_count: usize = 0;
            if (owner_dir.openDir(io, repo_entry.name, .{ .iterate = true })) |*repo_dir| {
                defer repo_dir.close(io);
                var mod_iter = repo_dir.iterate();
                while (try mod_iter.next(io)) |mod_entry| {
                    if (mod_entry.kind != .directory) continue;
                    if (std.mem.endsWith(u8, mod_entry.name, ".old") or
                        (std.mem.startsWith(u8, mod_entry.name, ".") and std.mem.endsWith(u8, mod_entry.name, ".staging"))) continue;
                    const mod_meta = readToolMeta(allocator, io, repo_dir.*, mod_entry.name);
                    defer if (mod_meta) |m| m.deinit(allocator);
                    if (mod_meta == null) continue;
                    const combined = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ repo_entry.name, mod_entry.name });
                    defer allocator.free(combined);
                    const line = try formatToolLine(allocator, entry.name, combined, mod_meta);
                    errdefer allocator.free(line);
                    try lines.append(allocator, line);
                    module_count += 1;
                }
            } else |_| {}

            // Preserve the old fallback: a repo dir with neither a repo-level
            // manifest nor any module units still lists as a bare entry.
            if (repo_meta == null and module_count == 0) {
                const line = try formatToolLine(allocator, entry.name, repo_entry.name, null);
                errdefer allocator.free(line);
                try lines.append(allocator, line);
            }
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
        \\    link <owner/repo>|<name>             (WSL) Symlink Windows bins/PATH exes into ghr's bin dir
        \\    unlink <owner/repo>|<name>           (WSL) Remove ghr-created WSL symlinks
        \\    path add [--dry-run]                 Add ghr's bin dir to your user PATH
        \\    path [bin|tools|cache]               Show ghr directories
        \\    validate <SUBCOMMAND>                Run validations against published artifacts
        \\    minisign <SUBCOMMAND>                Sign release artifacts with a minisign key
        \\    version                              Print version and exit
        \\
        \\Each <spec> is `owner/repo[@tag]` (auto-pick asset) or
        \\`owner/repo/file[@tag]` (specific asset).
        \\Run 'ghr <COMMAND> --help' to show help for a specific command.
        \\
        \\OPTIONS:
        \\    -h, --help              Show this help
        \\    --debug                 Show diagnostic output for debugging
        \\    --no-auth               Skip GitHub authentication
        \\    --skip-verify           Skip every verification step: checksum, minisign,
        \\                            sigstore sidecar, GitHub attestation, authenticode
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
    _ = @import("attestation.zig");
    _ = @import("install.zig");
    _ = @import("release.zig");
    _ = @import("ensurepath.zig");
    _ = @import("dirs.zig");
    _ = @import("dns.zig");
    _ = @import("http.zig");
    _ = @import("archive.zig");
    _ = @import("auth.zig");
    _ = @import("download.zig");
    _ = @import("validate.zig");
    _ = @import("link.zig");
    _ = @import("minisign_cmd.zig");
    _ = @import("der.zig");
    _ = @import("rfc3161.zig");
    _ = @import("snappy.zig");
    _ = @import("install_request.zig");
    _ = @import("install_state.zig");
}
