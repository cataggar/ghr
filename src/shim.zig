/// Cross-platform shim executable for ghr.
///
/// Each installed tool gets a copy of this exe (e.g. `zig.exe` on Windows or a
/// bare `zig` on Unix). Next to it, in the same bin dir, ghr writes a
/// `<stem>.ghr` manifest (ZON) describing what to run:
///   * `.target` — an absolute path to a native executable; the shim spawns
///     it directly, forwarding args.
///   * `.targetWasm` — an absolute path to a `.wasm` module; the shim resolves
///     the WebAssembly runtime + its arguments from the same manifest and runs
///     `<runtime> <runtimeArgs...> <target.wasm> <user args...>`.
///
/// For backward compatibility the shim also still reads a legacy `<stem>.shim`
/// text file (a single-line native target path) when no `.ghr` manifest is
/// present. New installs only write `.ghr`.
///
/// This is the same general technique used by npm and Scoop on Windows, with
/// the wasm-launcher behavior layered on so a `.wasm` is runnable as a
/// first-class command on Windows, Linux, and macOS.
const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;

extern "kernel32" fn GetModuleFileNameW(
    hModule: ?*anyopaque,
    lpFilename: [*]u16,
    nSize: u32,
) callconv(.winapi) u32;

/// WebAssembly runtimes the shim is allowed to launch. A `.ghr` manifest may
/// only name one of these; anything else is rejected. This hardcoded allow
/// list is the security boundary — a manifest cannot coerce the shim into
/// running an arbitrary program.
const allowed_runtimes = [_][]const u8{ "wasmtime", "wamr" };

/// Highest `.version` the shim understands. Only version 1 exists today.
const max_manifest_version: u32 = 1;

/// Parsed representation of a `<stem>.ghr` manifest (ZON) sitting next to the
/// shim in the bin dir.
const Manifest = struct {
    /// Manifest schema version. Required; must be `1`.
    version: u32,
    /// Absolute path to a native executable to spawn directly. Optional.
    /// Replaces the legacy `.shim` file's single-line target path.
    target: []const u8 = "",
    /// Absolute path to a `.wasm` module to run via a WebAssembly runtime.
    /// Optional. Takes precedence over `target` when both are set.
    targetWasm: []const u8 = "",
    /// WebAssembly runtime command, resolved via PATH at launch time.
    /// Optional; defaults to `wasmtime`. Must be in `allowed_runtimes`.
    runtime: []const u8 = "wasmtime",
    /// Arguments passed to the runtime before the wasm path.
    runtimeArgs: []const []const u8 = &.{},
};

fn exitWithError(stderr: *Io.Writer, comptime fmt: []const u8, args: anytype) noreturn {
    stderr.print(fmt, args) catch {};
    stderr.flush() catch {};
    std.process.exit(1);
}

/// Resolve the absolute path of the running shim executable into `buf`.
fn selfExePath(io: Io, buf: []u8) ![]const u8 {
    switch (builtin.os.tag) {
        .windows => {
            var wbuf: [Io.Dir.max_path_bytes / 2]u16 = undefined;
            const len = GetModuleFileNameW(null, &wbuf, wbuf.len);
            if (len == 0) return error.SelfPath;
            const n = std.unicode.wtf16LeToWtf8(buf, wbuf[0..len]);
            return buf[0..n];
        },
        .macos, .ios, .tvos, .watchos, .visionos => {
            var size: u32 = @intCast(buf.len);
            if (std.c._NSGetExecutablePath(buf.ptr, &size) != 0) return error.SelfPath;
            return std.mem.sliceTo(buf, 0);
        },
        else => {
            // Linux and other procfs-based systems.
            const n = try Io.Dir.readLinkAbsolute(io, "/proc/self/exe", buf);
            return buf[0..n];
        },
    }
}

fn isRuntimeAllowed(name: []const u8) bool {
    for (allowed_runtimes) |r| {
        if (std.mem.eql(u8, r, name)) return true;
    }
    return false;
}

fn fileExists(io: Io, abs_path: []const u8) bool {
    Io.Dir.cwd().access(io, abs_path, .{}) catch return false;
    return true;
}

/// Resolve `name` to an absolute executable path by scanning `PATH`. Returns a
/// freshly-allocated path owned by `allocator`, or null if not found.
///
/// `std.process.spawnPath` is unimplemented on this Zig version, so the shim
/// does the PATH lookup itself and spawns the resolved absolute path.
fn resolveOnPath(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const std.process.Environ.Map,
    name: []const u8,
) ?[]const u8 {
    const path_val = environ.get("PATH") orelse return null;
    const list_sep: u8 = if (builtin.os.tag == .windows) ';' else ':';
    const path_sep: u8 = if (builtin.os.tag == .windows) '\\' else '/';
    // On Windows, an executable may carry one of these extensions.
    const exts: []const []const u8 = if (builtin.os.tag == .windows)
        &.{ ".exe", ".cmd", ".bat", ".com", "" }
    else
        &.{""};

    var it = std.mem.tokenizeScalar(u8, path_val, list_sep);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        for (exts) |ext| {
            const cand = std.fmt.allocPrint(allocator, "{s}{c}{s}{s}", .{ dir, path_sep, name, ext }) catch return null;
            if (fileExists(io, cand)) return cand;
            allocator.free(cand);
        }
    }
    return null;
}

/// Append this process's arguments (excluding argv[0]) onto `argv`.
fn appendUserArgs(
    allocator: std.mem.Allocator,
    stderr: *Io.Writer,
    argv: *std.ArrayListUnmanaged([]const u8),
    init: std.process.Init,
) void {
    var args = init.minimal.args.iterateAllocator(allocator) catch {
        exitWithError(stderr, "shim: out of memory\n", .{});
    };
    _ = args.skip(); // skip shim's own name
    while (args.next()) |arg| {
        argv.append(allocator, arg) catch {
            exitWithError(stderr, "shim: out of memory\n", .{});
        };
    }
}

/// Spawn `argv` (with `argv[0]` an absolute path), wait, and exit with its
/// status. Never returns.
fn spawnDirectAndExit(io: Io, stderr: *Io.Writer, argv: []const []const u8) noreturn {
    var child = std.process.spawn(io, .{ .argv = argv }) catch {
        exitWithError(stderr, "shim: cannot start {s}\n", .{argv[0]});
    };
    const term = child.wait(io) catch {
        exitWithError(stderr, "shim: wait failed\n", .{});
    };
    switch (term) {
        .exited => |code| std.process.exit(code),
        else => std.process.exit(1),
    }
}

/// Run a wasm target named in the manifest:
/// `<runtime> <runtimeArgs...> <targetWasm> <user args...>`. Never returns.
fn runWasm(
    allocator: std.mem.Allocator,
    io: Io,
    stderr: *Io.Writer,
    manifest: Manifest,
    init: std.process.Init,
) noreturn {
    if (!isRuntimeAllowed(manifest.runtime)) {
        exitWithError(
            stderr,
            "shim: runtime '{s}' is not allowed (allowed: wasmtime, wamr)\n",
            .{manifest.runtime},
        );
    }

    // Resolve the runtime via PATH from the parent environment.
    const runtime_path = resolveOnPath(allocator, io, init.environ_map, manifest.runtime) orelse {
        exitWithError(stderr, "shim: cannot find runtime '{s}' on PATH\n", .{manifest.runtime});
    };

    // Build argv: <runtime> <runtimeArgs...> <targetWasm> <user args...>
    var argv = std.ArrayListUnmanaged([]const u8).empty;
    argv.append(allocator, runtime_path) catch {
        exitWithError(stderr, "shim: out of memory\n", .{});
    };
    for (manifest.runtimeArgs) |a| {
        argv.append(allocator, a) catch {
            exitWithError(stderr, "shim: out of memory\n", .{});
        };
    }
    argv.append(allocator, manifest.targetWasm) catch {
        exitWithError(stderr, "shim: out of memory\n", .{});
    };
    appendUserArgs(allocator, stderr, &argv, init);

    spawnDirectAndExit(io, stderr, argv.items);
}

/// Run a native target directly: `<target_path> <user args...>`. Never returns.
fn runNative(
    allocator: std.mem.Allocator,
    io: Io,
    stderr: *Io.Writer,
    target_path: []const u8,
    init: std.process.Init,
) noreturn {
    var argv = std.ArrayListUnmanaged([]const u8).empty;
    argv.append(allocator, target_path) catch {
        exitWithError(stderr, "shim: out of memory\n", .{});
    };
    appendUserArgs(allocator, stderr, &argv, init);
    spawnDirectAndExit(io, stderr, argv.items);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var stderr_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &stderr_buf);

    // Resolve own exe path.
    var self_path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const self_path = selfExePath(io, &self_path_buf) catch {
        exitWithError(&stderr.interface, "shim: cannot determine own path\n", .{});
    };

    // Strip a trailing .exe (if any) to get the stem shared by the companion
    // `.ghr` / `.shim` files.
    const stem = if (std.mem.endsWith(u8, self_path, ".exe") or std.mem.endsWith(u8, self_path, ".EXE"))
        self_path[0 .. self_path.len - 4]
    else
        self_path;

    // Preferred path: a `<stem>.ghr` manifest sitting next to the shim.
    var ghr_path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const ghr_path = std.fmt.bufPrint(&ghr_path_buf, "{s}.ghr", .{stem}) catch {
        exitWithError(&stderr.interface, "shim: path too long\n", .{});
    };

    if (Io.Dir.cwd().readFileAlloc(io, ghr_path, allocator, Io.Limit.limited(64 * 1024))) |raw| {
        // ZON parsing requires a sentinel-terminated source.
        const source = allocator.dupeZ(u8, raw) catch {
            exitWithError(&stderr.interface, "shim: out of memory\n", .{});
        };
        const manifest = std.zon.parse.fromSliceAlloc(
            Manifest,
            allocator,
            source,
            null,
            .{ .ignore_unknown_fields = true },
        ) catch {
            exitWithError(&stderr.interface, "shim: invalid manifest {s}\n", .{ghr_path});
        };

        if (manifest.version != max_manifest_version) {
            exitWithError(
                &stderr.interface,
                "shim: unsupported manifest version {d} in {s} (only version 1 is supported)\n",
                .{ manifest.version, ghr_path },
            );
        }

        if (manifest.targetWasm.len > 0) {
            runWasm(allocator, io, &stderr.interface, manifest, init);
        }
        if (manifest.target.len > 0) {
            runNative(allocator, io, &stderr.interface, manifest.target, init);
        }
        exitWithError(&stderr.interface, "shim: manifest {s} has neither .target nor .targetWasm\n", .{ghr_path});
    } else |_| {
        // No `.ghr` manifest — fall through to the legacy `.shim` file.
    }

    // Backward-compatibility path: a `<stem>.shim` text file naming a native
    // target. Retained only so installs created before the `.ghr` format keep
    // working; new installs write a `.ghr` instead.
    var shim_path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const shim_path = std.fmt.bufPrint(&shim_path_buf, "{s}.shim", .{stem}) catch {
        exitWithError(&stderr.interface, "shim: path too long\n", .{});
    };

    const shim_contents = Io.Dir.cwd().readFileAlloc(io, shim_path, allocator, Io.Limit.limited(Io.Dir.max_path_bytes)) catch {
        exitWithError(&stderr.interface, "shim: cannot read {s}\n", .{shim_path});
    };

    // Trim whitespace/CRLF
    const target_path = std.mem.trim(u8, shim_contents, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (target_path.len == 0) {
        exitWithError(&stderr.interface, "shim: empty target in {s}\n", .{shim_path});
    }

    runNative(allocator, io, &stderr.interface, target_path, init);
}
