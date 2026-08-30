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
const install_state = @import("install_state.zig");
const minisign = @import("minisign.zig");

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
        const version_arg = args.next();
        if (version_arg == null) {
            try stdout.interface.print("{s}\n", .{version});
            return;
        }
        if (!eql(version_arg.?, "--target")) {
            try stderr.interface.print("error: unexpected argument '{s}' for 'ghr version'\n", .{version_arg.?});
            try stderr.interface.flush();
            std.process.exit(1);
        }
        if (args.next()) |arg| {
            try stderr.interface.print("error: unexpected argument '{s}' for 'ghr version'\n", .{arg});
            try stderr.interface.flush();
            std.process.exit(1);
        }
        const builtin = @import("builtin");
        try stdout.interface.print("{t}-{t}-{t}\n", .{
            builtin.os.tag,
            builtin.cpu.arch,
            builtin.abi,
        });
        return;
    }
    if (eql(cmd_str, "path")) {
        try cmdPath(allocator, io, environ, &args, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "list")) {
        var format: ListFormat = .human;
        while (args.next()) |arg| {
            if (eql(arg, "--ids")) {
                if (format == .json) {
                    try stderr.interface.print("error: '--ids' and '--json' cannot be combined\n", .{});
                    try stderr.interface.print("  hint: '--ids' prints bare ids; '--json' prints full records\n", .{});
                    try stderr.interface.flush();
                    std.process.exit(1);
                }
                format = .ids;
            } else if (eql(arg, "--json")) {
                if (format == .ids) {
                    try stderr.interface.print("error: '--ids' and '--json' cannot be combined\n", .{});
                    try stderr.interface.print("  hint: '--ids' prints bare ids; '--json' prints full records\n", .{});
                    try stderr.interface.flush();
                    std.process.exit(1);
                }
                format = .json;
            } else {
                try stderr.interface.print("error: unexpected argument '{s}' for 'ghr list'\n", .{arg});
                try stderr.interface.flush();
                std.process.exit(1);
            }
        }
        const damaged = try cmdList(allocator, environ, io, &stdout.interface, &stderr.interface, format);
        try stdout.interface.flush();
        try stderr.interface.flush();
        if (damaged) std.process.exit(1);
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
        var print_cache_key = false;
        var single_request = false;
        var minisign_pubkey: ?[]const u8 = null;
        // Positional tokens are handed to `install_request` verbatim: sources,
        // quoted query tokens, and bare minisign keys are classified there so
        // one grammar governs the whole invocation.
        var tokens: std.ArrayListUnmanaged([]const u8) = .empty;
        defer tokens.deinit(allocator);
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
            } else if (eql(arg, "--print-cache-key")) {
                print_cache_key = true;
            } else if (eql(arg, "--single-request")) {
                single_request = true;
            } else if (eql(arg, "--minisign")) {
                const v = args.next() orelse {
                    try stderr.interface.print("error: '--minisign' requires a base64 minisign public key value\n", .{});
                    try stderr.interface.flush();
                    std.process.exit(1);
                };
                // Checked here so a malformed key fails before any download,
                // and identically to a per-request `?minisign=` value.
                if (!minisign.looksLikePubKey(v)) {
                    try stderr.interface.print(
                        "error: '--minisign' value is not a base64 minisign public key\n",
                        .{},
                    );
                    try stderr.interface.flush();
                    std.process.exit(1);
                }
                minisign_pubkey = v;
            } else if (eql(arg, "--bin")) {
                const v = args.next() orelse {
                    try stderr.interface.print("error: '--bin' requires an installed command name\n", .{});
                    try stderr.interface.flush();
                    std.process.exit(1);
                };
                try bin_filters.append(allocator, v);
            } else {
                try tokens.append(allocator, arg);
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
        if (single_request and !print_cache_key) {
            try stderr.interface.print(
                "error: '--single-request' requires '--print-cache-key'\n",
                .{},
            );
            try stderr.interface.flush();
            std.process.exit(1);
        }
        const install_options: install.InstallOptions = .{
            .debug = debug,
            .no_auth = no_auth,
            .gates = gates,
            .minisign_pubkey_b64 = minisign_pubkey,
            .bin_filters = bin_filters.items,
            .keep_going = keep_going,
        };
        const result = if (print_cache_key)
            install.cmdInstallCacheKey(
                allocator,
                tokens.items,
                &stdout.interface,
                &stderr.interface,
                install_options,
                single_request,
            )
        else
            install.cmdInstallRequests(
                allocator,
                io,
                environ,
                tokens.items,
                &stdout.interface,
                &stderr.interface,
                install_options,
            );
        result catch |err| switch (err) {
            error.MissingInstallSpec,
            error.BinFilterRequiresSingleSpec,
            error.InvalidInstallRequest,
            error.InstallPlanRejected,
            error.InstallFailed,
            => {
                try stdout.interface.flush();
                try stderr.interface.flush();
                std.process.exit(1);
            },
            else => return err,
        };
    } else if (eql(cmd_str, "uninstall")) {
        const spec = args.next() orelse {
            try stderr.interface.print("error: 'ghr uninstall' requires <id>\n", .{});
            try stderr.interface.flush();
            std.process.exit(1);
        };
        if (args.next()) |arg| {
            try stderr.interface.print("error: unexpected argument '{s}' for 'ghr uninstall'\n", .{arg});
            try stderr.interface.flush();
            std.process.exit(1);
        }
        install.cmdUninstall(allocator, io, environ, spec, &stdout.interface, &stderr.interface) catch |err| switch (err) {
            error.UninstallTargetNotFound,
            error.UninstallStateUnusable,
            error.UninstallFailed,
            => {
                try stdout.interface.flush();
                try stderr.interface.flush();
                std.process.exit(1);
            },
            else => return err,
        };
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
    var force_path = false;
    var force_id = false;
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
        } else if (eql(arg, "--path")) {
            force_path = true;
        } else if (eql(arg, "--id")) {
            force_id = true;
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
        try err_w.print("error: 'ghr {s}' requires <id> or a bare executable name\n", .{@tagName(kind)});
        try err_w.flush();
        std.process.exit(1);
    };
    if (force_path and force_id) {
        try err_w.print("error: '--id' and '--path' are mutually exclusive\n", .{});
        try err_w.flush();
        std.process.exit(1);
    }

    const result = switch (kind) {
        .link => link.cmdLinkAuto(allocator, io, environ, spec_str, filters.items, force_path, force_id, w, err_w),
        .unlink => link.cmdUnlinkAuto(allocator, io, environ, spec_str, filters.items, force_path, force_id, w, err_w),
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
        \\    ghr link <id> [--bin <name>] [--bin <name> ...]
        \\    ghr link [--path] <name>                     (e.g. 'ghr link git')
        \\
        \\With <id>, reads the exact Windows-side install from ghr's inventory
        \\and creates Linux symlinks in ghr's bin directory for the commands
        \\owned by that ID. The links point at the original `.exe` binaries
        \\(via `/mnt/c/...`), which WSL interop executes transparently.
        \\
        \\Without `--bin`, links every bin advertised by the Windows
        \\install and removes any previously-linked bins that no longer
        \\exist (the command is a reconciler).
        \\
        \\With one or more `--bin <name>` filters, only the named bins
        \\are touched; other previously-linked entries are left alone.
        \\
        \\When a one-segment name is not an installed ID, it retains the
        \\historical Windows `%PATH%` lookup. Use `--path` to force this mode
        \\when an installed ID has the same name. It resolves via `where.exe`
        \\and `wslpath -u`, then creates an entry in ghr's bin directory:
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
        \\    ghr link zigb
        \\    ghr link zigb --bin zigb
        \\    ghr link git
        \\    ghr link --path az
        \\
        \\OPTIONS:
        \\    --id        Force install-ID mode for an ambiguous one-segment name
        \\    --path      Force Windows PATH executable mode
        \\    -h, --help  Show this help
        \\
    , .{});
}

fn printUnlinkUsage(w: *Writer) !void {
    try w.print(
        \\ghr unlink - remove WSL symlinks created by 'ghr link'
        \\
        \\USAGE:
        \\    ghr unlink <id> [--bin <name> ...]
        \\    ghr unlink [--path] <name>                   (bare executable form)
        \\
        \\With <id>, removes every symlink recorded for that exact install ID.
        \\Verifies each symlink still points where the ID manifest recorded
        \\before deleting, so a user-rewritten symlink is never clobbered.
        \\
        \\With `--bin <name>` filters, only the named entries are
        \\removed.
        \\
        \\When a one-segment name has no install ID state, removes the bare
        \\Windows PATH entry created by `ghr link <name>`. Use `--path` to
        \\force bare mode. `--bin` is not supported with the bare form.
        \\
        \\Requires WSL_INTEROP to be set (i.e., running in WSL).
        \\
        \\OPTIONS:
        \\    --id        Force install-ID mode for an ambiguous one-segment name
        \\    --path      Force Windows PATH executable mode
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
        \\ghr list - Report installed units
        \\
        \\USAGE:
        \\    ghr list [--ids | --json]
        \\
        \\The default output is a human report, not pasteable install arguments:
        \\each line names the install id, whether the unit is v1 (legacy) or v2,
        \\its status, its source and tag, and the commands it publishes.
        \\
        \\Conflicting, corrupt, and unsupported units are always shown, and
        \\`ghr list` exits non-zero when any unit is not healthy.
        \\
        \\OPTIONS:
        \\    --ids       Print one healthy canonical install id per line
        \\    --json      Print deterministic records, including the reproducible
        \\                install definition (source intent plus configuration)
        \\                for v2 units; legacy v1 units report a null definition
        \\    -h, --help  Show this help
        \\
        \\`--ids` and `--json` cannot be combined: a bare id and a full
        \\definition are not interchangeable.
        \\
    , .{});
}

fn printInstallUsage(w: *Writer) !void {
    try w.print(
        \\ghr install - install one or more tools by install id
        \\
        \\USAGE:
        \\    ghr install <source> ["?<query>"] [<minisign-pubkey>] [...] [options]
        \\
        \\Each <source> is one of:
        \\    owner/repo[@tag]              Auto-pick the best asset for this platform
        \\    owner/repo/file[@tag]         Install a specific asset by name
        \\    https://github.com/.../download/<tag>/<file>
        \\                                  A GitHub release download URL
        \\    https://<host>/<path>/<file>  A direct URL; requires an explicit id
        \\
        \\An install id is the stable name used by list and uninstall. GitHub
        \\sources derive `lowercase(owner)/lowercase(repo)`; a direct URL has no
        \\repository identity and must set one explicitly.
        \\
        \\An optional quoted query token configures the source it follows:
        \\    "?id=<id>"                    Explicit stable install id
        \\    "?alias=<from>:<to>"          Publish command <from> as <to> (repeatable)
        \\    "?minisign=<pubkey>"          Minisign key required for this source
        \\Pairs split at their first `=`, are percent-decoded, and `+` stays a
        \\literal plus. An id never renames a command by itself.
        \\
        \\An optional bare minisign public key (56-char base64, starts with `RW`
        \\or `RU`) immediately after a source attaches to that source only and
        \\overrides `--minisign` for it. Otherwise the global `--minisign
        \\<pubkey>` default applies to every source that has no key.
        \\
        \\Installing an id that already exists replaces it transactionally: the
        \\new unit and its complete command set appear together, or the previous
        \\install is restored. Commands owned by another id, and bin entries ghr
        \\does not manage, are reported before anything is changed.
        \\
        \\OPTIONS:
        \\    --bin <name>            Publish and record only this discovered command
        \\                            (repeatable, applied before aliases); requires
        \\                            exactly one source and is not supported for wasm
        \\    --debug                 Show diagnostic output for debugging
        \\    --no-auth               Skip GitHub authentication
        \\    --skip-verify           Skip every verification step (checksum, minisign, sigstore, attestation, authenticode)
        \\    --skip-checksum         Skip checksum verification (GitHub asset digest + .sha256/.sha512 sidecar)
        \\    --skip-minisign         Skip just the minisign verification step
        \\    --skip-sigstore         Skip just the published .sigstore.json sidecar verification step
        \\    --skip-attestation      Skip just the GitHub-native artifact attestation verification step
        \\    --skip-authenticode     Skip just the Authenticode (Windows PE) verification step
        \\    --minisign <pubkey>     Default minisign key, applied to sources without a key;
        \\                            <pubkey> is a base64 minisign public key string
        \\    --keep-going            Continue past per-source resolution failures; the
        \\                            surviving sources are still planned together and
        \\                            the command exits non-zero with a summary
        \\    --print-cache-key       Print a normalized state/cache fingerprint and exit
        \\                            without network or filesystem access
        \\    --single-request        With --print-cache-key, require exactly one request
        \\    -h, --help              Show this help
        \\
        \\A direct URL publishes no GitHub digest, sigstore sidecar, or
        \\attestation, so those steps report that they cannot run instead of
        \\claiming success. With `--minisign`, a direct URL is verified against
        \\the sibling `<url>.minisig`.
        \\
        \\EXAMPLES:
        \\    ghr install burntsushi/ripgrep@15.1.0
        \\    ghr install azuread/microsoft-authentication-cli --bin azureauth
        \\    ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0
        \\    ghr install jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
        \\    ghr install cataggar/zig@zigb-0.16.1 "?id=zigb&alias=zig:zigb"
        \\
    , .{});
}

fn printUninstallUsage(w: *Writer) !void {
    try w.print(
        \\ghr uninstall - remove one installed unit by id
        \\
        \\USAGE:
        \\    ghr uninstall <id>
        \\
        \\<id> is a canonical install id, not a source spec or a path. GitHub
        \\installs derive `owner/repo`, so existing `ghr uninstall owner/repo`
        \\and `ghr uninstall owner/repo/<wasm-stem>` commands keep working.
        \\
        \\Exactly that id is removed: its commands, its app bundles, and its unit
        \\directory. Prefixes are not recursive, so removing `owner/repo` leaves
        \\`owner/repo/<module>` installed. Missing, conflicting, corrupt, and
        \\unsupported state is reported instead of guessed at.
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
        \\    ghr version [--target]
        \\
        \\OPTIONS:
        \\    --target     Print the build OS, architecture, and ABI
        \\    -h, --help  Show this help
        \\
    , .{});
}

/// Output shape for `ghr list`. The three forms are deliberately distinct:
/// the default is a human report, `--ids` is a bare identity list for
/// scripting, and `--json` is a machine-readable record set. A definition line
/// and a bare id are never interchangeable, so no form may be mistaken for the
/// other.
const ListFormat = enum { human, ids, json };

/// List installed units from the inventory reader. Returns true when any record
/// is not healthy, so the caller can exit non-zero instead of silently
/// presenting damaged state as installable.
fn cmdList(
    allocator: std.mem.Allocator,
    environ: *const std.process.Environ.Map,
    io: Io,
    w: *Writer,
    err_w: *Writer,
    format: ListFormat,
) !bool {
    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    var inventory = install_state.scan(allocator, io, d.tools, .{}) catch |err| {
        try err_w.print("error: failed to read install state under '{s}': {t}\n", .{ d.tools, err });
        return true;
    };
    defer inventory.deinit(allocator);

    var damaged = false;
    for (inventory.records) |rec| {
        if (rec.status != .ok) damaged = true;
    }

    switch (format) {
        .ids => try printListIds(inventory, w, err_w),
        .json => try printListJson(inventory, w),
        .human => try printListHuman(inventory, w),
    }
    return damaged;
}

fn unitKindLabel(kind: install_state.UnitKind) []const u8 {
    return switch (kind) {
        .v1_repo => "v1",
        .v1_wasm => "v1-wasm",
        .v2 => "v2",
        .unknown => "unknown",
    };
}

fn printListHuman(inventory: install_state.Inventory, w: *Writer) !void {
    if (inventory.records.len == 0) {
        try w.print("No tools installed.\n", .{});
        return;
    }
    // Stated explicitly so a line is never mistaken for pasteable install
    // arguments: an id can carry aliases, a selector, and configuration that a
    // plain slug cannot express.
    try w.print("installed units (report, not install arguments):\n", .{});
    for (inventory.records) |rec| {
        const id = rec.id orelse "<unknown id>";
        try w.print("  {s}  [{s}] {t}", .{ id, unitKindLabel(rec.kind), rec.status });
        if (rec.status != .ok) try w.print(" ({t})", .{rec.reason});
        if (rec.source) |src| {
            switch (src.kind) {
                .github => try w.print("  source: github:{s}/{s}", .{
                    src.owner orelse "?",
                    src.repo orelse "?",
                }),
                .generic_url => try w.print("  source: url:{s}", .{src.url orelse "?"}),
            }
        } else if (rec.kind == .v1_repo or rec.kind == .v1_wasm) {
            try w.print("  source: legacy:{s}", .{rec.path});
        }
        const tag: ?[]const u8 = if (rec.resolved) |r| r.tag orelse rec.tag else rec.tag;
        if (tag) |t| {
            if (t.len > 0) try w.print("  tag: {s}", .{t});
        }
        if (rec.commands.len > 0) {
            try w.print("  commands:", .{});
            for (rec.commands) |cmd| try w.print(" {s}", .{cmd.name});
        }
        try w.print("\n", .{});
    }
    try w.print("\nrun 'ghr list --ids' for bare ids or 'ghr list --json' for definitions\n", .{});
}

fn printListIds(inventory: install_state.Inventory, w: *Writer, err_w: *Writer) !void {
    for (inventory.records) |rec| {
        if (rec.status != .ok) continue;
        const id = rec.id orelse continue;
        try w.print("{s}\n", .{id});
    }
    // A damaged record must never be silently dropped: `--ids` output feeds
    // scripts that mutate state, so the caller is told and the exit code is
    // non-zero.
    for (inventory.records) |rec| {
        if (rec.status == .ok) continue;
        try err_w.print("error: {s}: {t} ({t}) at {s}\n", .{
            rec.id orelse "<unknown id>",
            rec.status,
            rec.reason,
            rec.path,
        });
    }
}

fn writeJsonString(w: *Writer, s: []const u8) !void {
    try w.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => {
                if (c < 0x20 or c == 0x7f) {
                    try w.print("\\u{x:0>4}", .{c});
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
    try w.writeAll("\"");
}

fn writeJsonOptString(w: *Writer, value: ?[]const u8) !void {
    if (value) |v| {
        try writeJsonString(w, v);
    } else {
        try w.writeAll("null");
    }
}

/// Deterministic machine-readable records. `definition` is the reproducible
/// install definition: durable SOURCE INTENT plus effective configuration,
/// never a resolved URL. A v1 record is explicitly legacy and its definition is
/// null, because v1 metadata does not record the intent needed to rebuild one.
fn printListJson(inventory: install_state.Inventory, w: *Writer) !void {
    try w.print("{{\"schema\":1,\"form\":\"install-records\",\"units\":[", .{});
    for (inventory.records, 0..) |rec, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"id\":");
        try writeJsonOptString(w, rec.id);
        try w.print(",\"kind\":\"{s}\",\"status\":\"{t}\",\"reason\":\"{t}\",\"legacy\":{},\"path\":", .{
            unitKindLabel(rec.kind),
            rec.status,
            rec.reason,
            rec.kind == .v1_repo or rec.kind == .v1_wasm,
        });
        try writeJsonString(w, rec.path);

        try w.writeAll(",\"definition\":");
        if (rec.source) |src| {
            try w.writeAll("{\"source\":{\"kind\":");
            try writeJsonString(w, switch (src.kind) {
                .github => "github",
                .generic_url => "generic_url",
            });
            try w.writeAll(",\"owner\":");
            try writeJsonOptString(w, src.owner);
            try w.writeAll(",\"repo\":");
            try writeJsonOptString(w, src.repo);
            try w.writeAll(",\"tag\":");
            try writeJsonOptString(w, src.tag);
            try w.writeAll(",\"asset_selector\":");
            try writeJsonOptString(w, src.asset_selector);
            try w.writeAll(",\"url\":");
            try writeJsonOptString(w, src.url);
            try w.writeAll("},\"config\":{\"aliases\":[");
            if (rec.config) |cfg| {
                for (cfg.aliases, 0..) |alias, ai| {
                    if (ai > 0) try w.writeAll(",");
                    try w.writeAll("{\"from\":");
                    try writeJsonString(w, alias.from);
                    try w.writeAll(",\"to\":");
                    try writeJsonString(w, alias.to);
                    try w.writeAll("}");
                }
            }
            try w.writeAll("],\"selected_commands\":");
            if (rec.config) |cfg| {
                if (cfg.selected_commands) |sel| {
                    try w.writeAll("[");
                    for (sel, 0..) |c, si| {
                        if (si > 0) try w.writeAll(",");
                        try writeJsonString(w, c);
                    }
                    try w.writeAll("]");
                } else try w.writeAll("null");
            } else try w.writeAll("null");
            try w.writeAll(",\"minisign\":");
            if (rec.config) |cfg| {
                try writeJsonOptString(w, cfg.minisign);
            } else try w.writeAll("null");
            try w.writeAll("}}");
        } else {
            try w.writeAll("null");
        }

        try w.writeAll(",\"resolved\":");
        if (rec.resolved) |res| {
            try w.writeAll("{\"tag\":");
            try writeJsonOptString(w, res.tag);
            try w.writeAll(",\"asset\":");
            try writeJsonOptString(w, res.asset);
            try w.writeAll(",\"api_asset_id\":");
            if (res.api_asset_id) |id| {
                try w.print("{d}", .{id});
            } else try w.writeAll("null");
            try w.writeAll(",\"download_url\":");
            try writeJsonOptString(w, res.download_url);
            try w.writeAll("}");
        } else {
            try w.writeAll("{\"tag\":");
            try writeJsonOptString(w, rec.tag);
            try w.writeAll(",\"asset\":");
            try writeJsonOptString(w, rec.asset);
            try w.writeAll(",\"api_asset_id\":null,\"download_url\":null}");
        }

        try w.writeAll(",\"commands\":[");
        for (rec.commands, 0..) |cmd, ci| {
            if (ci > 0) try w.writeAll(",");
            try w.writeAll("{\"name\":");
            try writeJsonString(w, cmd.name);
            try w.writeAll(",\"relative_target\":");
            try writeJsonString(w, cmd.relative_target);
            try w.writeAll(",\"kind\":");
            try writeJsonOptString(w, cmd.kind);
            try w.writeAll("}");
        }
        try w.writeAll("],\"apps\":[");
        for (rec.apps, 0..) |app, ai| {
            if (ai > 0) try w.writeAll(",");
            try writeJsonString(w, app);
        }
        try w.writeAll("],\"verified\":");
        if (rec.verification) |v| {
            try writeJsonOptString(w, v.result);
        } else {
            try writeJsonOptString(w, rec.verified);
        }
        try w.writeAll("}");
    }
    try w.print("]}}\n", .{});
}

// ---------------------------------------------------------------------------
// `ghr list` output tests
// ---------------------------------------------------------------------------

const t_list_alloc = std.testing.allocator;

fn tListRender(
    records: []install_state.InventoryRecord,
    format: ListFormat,
) ![]u8 {
    var out: Io.Writer.Allocating = .init(t_list_alloc);
    errdefer out.deinit();
    var errs: Io.Writer.Allocating = .init(t_list_alloc);
    defer errs.deinit();
    const inventory: install_state.Inventory = .{ .records = records };
    switch (format) {
        .human => try printListHuman(inventory, &out.writer),
        .ids => try printListIds(inventory, &out.writer, &errs.writer),
        .json => try printListJson(inventory, &out.writer),
    }
    var list = out.toArrayList();
    return list.toOwnedSlice(t_list_alloc);
}

fn tListRenderIdsErr(records: []install_state.InventoryRecord) !struct { out: []u8, err: []u8 } {
    var out: Io.Writer.Allocating = .init(t_list_alloc);
    errdefer out.deinit();
    var errs: Io.Writer.Allocating = .init(t_list_alloc);
    errdefer errs.deinit();
    const inventory: install_state.Inventory = .{ .records = records };
    try printListIds(inventory, &out.writer, &errs.writer);
    var out_list = out.toArrayList();
    var err_list = errs.toArrayList();
    return .{
        .out = try out_list.toOwnedSlice(t_list_alloc),
        .err = try err_list.toOwnedSlice(t_list_alloc),
    };
}

fn tV2Record() install_state.InventoryRecord {
    return .{
        .kind = .v2,
        .status = .ok,
        .reason = .none,
        .path = "_v2/units/u-zigb/_unit",
        .id = "zigb",
        .source = .{
            .kind = .github,
            .owner = "cataggar",
            .repo = "zig",
            .tag = "zigb-0.16.1",
        },
        .config = .{ .aliases = &.{}, .selected_commands = null, .minisign = null },
        .resolved = .{ .tag = "zigb-0.16.1", .asset = "zig.tar.xz", .api_asset_id = 7 },
        .verification = .{ .result = "checksum" },
    };
}

fn tV1Record() install_state.InventoryRecord {
    return .{
        .kind = .v1_repo,
        .status = .ok,
        .reason = .none,
        .path = "burntsushi/ripgrep",
        .id = "burntsushi/ripgrep",
        .tag = "14.1.0",
    };
}

test "list human output identifies id, kind, status, source, and commands" {
    var commands = [_]install_state.OwnedCommand{
        .{ .name = "zigb", .source_name = "zig", .relative_target = "bin/zig", .kind = "native" },
    };
    var v2 = tV2Record();
    v2.commands = &commands;
    var records = [_]install_state.InventoryRecord{v2};

    const text = try tListRender(&records, .human);
    defer t_list_alloc.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "zigb") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "[v2]") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "github:cataggar/zig") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "commands: zigb") != null);
    // The human report must not masquerade as pasteable install arguments.
    try std.testing.expect(std.mem.indexOf(u8, text, "report, not install arguments") != null);
}

test "list human output marks legacy units and non-ok state" {
    var broken: install_state.InventoryRecord = .{
        .kind = .v2,
        .status = .corrupt,
        .reason = .malformed_json,
        .path = "_v2/units/u-bad/_unit",
        .id = "bad",
    };
    var records = [_]install_state.InventoryRecord{ tV1Record(), broken };

    const text = try tListRender(&records, .human);
    defer t_list_alloc.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "[v1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "legacy:burntsushi/ripgrep") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "corrupt") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "malformed_json") != null);
    _ = &broken;
}

test "list of empty inventory is unambiguous" {
    var records = [_]install_state.InventoryRecord{};
    const text = try tListRender(&records, .human);
    defer t_list_alloc.free(text);
    try std.testing.expectEqualStrings("No tools installed.\n", text);

    const ids = try tListRender(&records, .ids);
    defer t_list_alloc.free(ids);
    try std.testing.expectEqualStrings("", ids);

    const json = try tListRender(&records, .json);
    defer t_list_alloc.free(json);
    try std.testing.expectEqualStrings("{\"schema\":1,\"form\":\"install-records\",\"units\":[]}\n", json);
}

test "list --ids prints healthy ids and reports damaged ones" {
    const broken: install_state.InventoryRecord = .{
        .kind = .v2,
        .status = .conflict,
        .reason = .duplicate_id,
        .path = "_v2/units/u-bad/_unit",
        .id = "bad",
    };
    var records = [_]install_state.InventoryRecord{ tV2Record(), broken, tV1Record() };

    const result = try tListRenderIdsErr(&records);
    defer t_list_alloc.free(result.out);
    defer t_list_alloc.free(result.err);
    try std.testing.expectEqualStrings("zigb\nburntsushi/ripgrep\n", result.out);
    // A conflicted id must never appear in a list that invites mutation.
    try std.testing.expect(std.mem.indexOf(u8, result.out, "bad\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.err, "conflict") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.err, "duplicate_id") != null);
}

test "list --json separates source intent from resolved provenance" {
    var commands = [_]install_state.OwnedCommand{
        .{ .name = "zigb", .source_name = "zig", .relative_target = "bin/zig", .kind = "native" },
    };
    var aliases = [_]install_state.OwnedAlias{.{ .from = "zig", .to = "zigb" }};
    var v2 = tV2Record();
    v2.commands = &commands;
    v2.config = .{ .aliases = &aliases, .selected_commands = null, .minisign = null };
    v2.resolved = .{
        .tag = "zigb-0.16.1",
        .asset = "zig.tar.xz",
        .api_asset_id = 7,
        .download_url = "https://github.com/cataggar/zig/releases/download/zigb-0.16.1/zig.tar.xz",
    };
    var records = [_]install_state.InventoryRecord{v2};

    const text = try tListRender(&records, .json);
    defer t_list_alloc.free(text);

    var parsed = try std.json.parseFromSlice(std.json.Value, t_list_alloc, text, .{});
    defer parsed.deinit();
    const unit = parsed.value.object.get("units").?.array.items[0];
    try std.testing.expectEqualStrings("install-records", parsed.value.object.get("form").?.string);
    try std.testing.expectEqualStrings("zigb", unit.object.get("id").?.string);
    try std.testing.expectEqualStrings("v2", unit.object.get("kind").?.string);
    try std.testing.expectEqual(false, unit.object.get("legacy").?.bool);

    const definition = unit.object.get("definition").?.object;
    const source = definition.get("source").?.object;
    try std.testing.expectEqualStrings("github", source.get("kind").?.string);
    try std.testing.expectEqualStrings("cataggar", source.get("owner").?.string);
    // The reproducible definition uses source intent, never the resolved URL.
    try std.testing.expect(source.get("url").? == .null);
    try std.testing.expectEqualStrings(
        "zigb",
        definition.get("config").?.object.get("aliases").?.array.items[0].object.get("to").?.string,
    );
    // Provenance is reported separately.
    try std.testing.expect(std.mem.indexOf(
        u8,
        unit.object.get("resolved").?.object.get("download_url").?.string,
        "releases/download",
    ) != null);
}

test "list --json reports a legacy unit with a null definition" {
    var records = [_]install_state.InventoryRecord{tV1Record()};
    const text = try tListRender(&records, .json);
    defer t_list_alloc.free(text);

    var parsed = try std.json.parseFromSlice(std.json.Value, t_list_alloc, text, .{});
    defer parsed.deinit();
    const unit = parsed.value.object.get("units").?.array.items[0];
    try std.testing.expectEqualStrings("v1", unit.object.get("kind").?.string);
    try std.testing.expectEqual(true, unit.object.get("legacy").?.bool);
    // v1 never records the intent needed to rebuild an install, so nothing is
    // invented for it.
    try std.testing.expect(unit.object.get("definition").? == .null);
    try std.testing.expectEqualStrings("14.1.0", unit.object.get("resolved").?.object.get("tag").?.string);
}

test "list --json reports damaged units with their status and reason" {
    const broken: install_state.InventoryRecord = .{
        .kind = .v2,
        .status = .unsupported,
        .reason = .unsupported_schema,
        .path = "_v2/units/u-future/_unit",
        .id = "future",
    };
    var records = [_]install_state.InventoryRecord{broken};
    const text = try tListRender(&records, .json);
    defer t_list_alloc.free(text);

    var parsed = try std.json.parseFromSlice(std.json.Value, t_list_alloc, text, .{});
    defer parsed.deinit();
    const unit = parsed.value.object.get("units").?.array.items[0];
    try std.testing.expectEqualStrings("unsupported", unit.object.get("status").?.string);
    try std.testing.expectEqualStrings("unsupported_schema", unit.object.get("reason").?.string);
}

test "list --json escapes control bytes in metadata values" {
    var v2 = tV2Record();
    v2.source = .{ .kind = .github, .owner = "o", .repo = "r", .tag = "v1\"x" };
    var records = [_]install_state.InventoryRecord{v2};
    const text = try tListRender(&records, .json);
    defer t_list_alloc.free(text);

    var parsed = try std.json.parseFromSlice(std.json.Value, t_list_alloc, text, .{});
    defer parsed.deinit();
    const unit = parsed.value.object.get("units").?.array.items[0];
    try std.testing.expectEqualStrings(
        "v1\"x",
        unit.object.get("definition").?.object.get("source").?.object.get("tag").?.string,
    );
}

fn printUsage(w: *Writer) !void {
    try w.print(
        \\ghr - A toolkit for GitHub releases
        \\
        \\USAGE:
        \\    ghr <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    list [--ids|--json]                  Report installed units
        \\    install <source> [<source> ...]      Install one or more tools by install id
        \\    uninstall <id>                       Remove one installed unit by id
        \\    download <spec> [<spec> ...]         Download one or more release assets
        \\    link <id>|[--path] <name>            (WSL) Link Windows install/PATH commands by ID or name
        \\    unlink <id>|[--path] <name>          (WSL) Remove ghr-created WSL links by ID or name
        \\    path add [--dry-run]                 Add ghr's bin dir to your user PATH
        \\    path [bin|tools|cache]               Show ghr directories
        \\    validate <SUBCOMMAND>                Run validations against published artifacts
        \\    minisign <SUBCOMMAND>                Sign release artifacts with a minisign key
        \\    version                              Print version and exit
        \\
        \\Each <source> is `owner/repo[@tag]` (auto-pick asset),
        \\`owner/repo/file[@tag]` (specific asset), a GitHub release URL, or a
        \\direct URL with an explicit `"?id=<id>"`.
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
    _ = @import("command_plan.zig");
    _ = @import("install_state_write.zig");
    _ = @import("install_txn.zig");
}
