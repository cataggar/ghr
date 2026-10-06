const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const strip = b.option(bool, "strip", "Strip debug info");
    const version_str = b.option([]const u8, "version", "Override version string") orelse "0.8.0";

    const exe_options = b.addOptions();
    exe_options.addOption([]const u8, "version", version_str);
    const minizign = b.dependency("minizign", .{
        .target = target,
        .optimize = optimize,
        .@"no-cli" = true,
    }).module("minizign");

    const exe = b.addExecutable(.{
        .name = "ghr",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .imports = &.{
                .{ .name = "build_options", .module = exe_options.createModule() },
                .{ .name = "minizign", .module = minizign },
            },
        }),
    });
    b.installArtifact(exe);

    // Build a small shim exe and embed it inside ghr. The shim reads a
    // companion .shim file to find the real target; on Windows it stands in
    // for the missing native exe, and on every platform it acts as the
    // launcher for installed `.wasm` modules (loading their `.ghr` manifest).
    // This is the same general technique used by npm and Scoop on Windows.
    const resolved_target = target.result;
    const shim = b.addExecutable(.{
        .name = "shim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shim.zig"),
            .target = target,
            .optimize = .small,
            .strip = true,
            // macOS needs libc for `_NSGetExecutablePath`.
            .link_libc = resolved_target.os.tag.isDarwin(),
        }),
    });
    // Embed the compiled shim binary so it's always available at runtime,
    // regardless of how ghr is installed (PyPI, GitHub release, etc.)
    exe.root_module.addAnonymousImport("shim_exe", .{
        .root_source_file = b.addWriteFiles().add(
            "shim_exe.zig",
            "pub const bytes = @embedFile(\"shim.bin\");",
        ),
        .imports = &.{.{
            .name = "shim.bin",
            .module = b.createModule(.{ .root_source_file = shim.getEmittedBin() }),
        }},
    });

    const run_step = b.step("run", "Run ghr");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

    const shim_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shim.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = resolved_target.os.tag.isDarwin(),
        }),
    });
    test_step.dependOn(&b.addRunArtifact(shim_tests).step);

    const help_cases = [_]struct {
        args: []const []const u8,
        usage: []const u8,
    }{
        .{ .args = &.{}, .usage = "    ghr <COMMAND> [OPTIONS]" },
        .{ .args = &.{"list"}, .usage = "    ghr list" },
        .{ .args = &.{"install"}, .usage = "    ghr install <source>" },
        .{ .args = &.{"uninstall"}, .usage = "    ghr uninstall <id>" },
        .{ .args = &.{"download"}, .usage = "    ghr download <spec>" },
        .{ .args = &.{"link"}, .usage = "    ghr link <id>" },
        .{ .args = &.{"unlink"}, .usage = "    ghr unlink <id>" },
        .{ .args = &.{"path"}, .usage = "    ghr path <SUBCOMMAND> [OPTIONS]" },
        .{ .args = &.{ "path", "add" }, .usage = "    ghr path add [--dry-run]" },
        .{ .args = &.{ "path", "bin" }, .usage = "    ghr path bin" },
        .{ .args = &.{ "path", "tools" }, .usage = "    ghr path tools" },
        .{ .args = &.{ "path", "cache" }, .usage = "    ghr path cache" },
        .{ .args = &.{"validate"}, .usage = "    ghr validate <SUBCOMMAND> [OPTIONS]" },
        .{ .args = &.{ "validate", "strip-authenticode" }, .usage = "    ghr validate strip-authenticode <input.exe> <output.exe>" },
        .{ .args = &.{"minisign"}, .usage = "    ghr minisign <SUBCOMMAND> [OPTIONS]" },
        .{ .args = &.{ "minisign", "generate" }, .usage = "    ghr minisign generate" },
        .{ .args = &.{ "minisign", "sign" }, .usage = "    ghr minisign sign <file>" },
        .{ .args = &.{"version"}, .usage = "    ghr version" },
        // Help must win after positional arguments so no command reaches IO.
        .{ .args = &.{ "install", "example/tool" }, .usage = "    ghr install <source>" },
        .{ .args = &.{ "download", "example/tool" }, .usage = "    ghr download <spec>" },
        .{ .args = &.{ "link", "example/tool" }, .usage = "    ghr link <id>" },
        .{ .args = &.{ "uninstall", "example/tool" }, .usage = "    ghr uninstall <id>" },
        .{ .args = &.{ "validate", "strip-authenticode", "input.exe", "output.exe" }, .usage = "    ghr validate strip-authenticode <input.exe> <output.exe>" },
        .{ .args = &.{ "minisign", "sign", "input" }, .usage = "    ghr minisign sign <file>" },
        .{ .args = &.{ "minisign", "generate", "--repo", "example/tool" }, .usage = "    ghr minisign generate" },
    };
    for (help_cases) |case| {
        addHelpFlagTests(b, test_step, exe, case.args, case.usage);
    }

    const removed_help_cases = [_]struct {
        args: []const []const u8,
        stderr: []const u8,
    }{
        .{ .args = &.{"help"}, .stderr = "error: unknown command 'help'" },
        .{ .args = &.{ "path", "help" }, .stderr = "error: unknown subcommand 'help' for 'ghr path'" },
        .{ .args = &.{ "validate", "help" }, .stderr = "error: unknown subcommand 'help' for 'ghr validate'" },
        .{ .args = &.{ "minisign", "help" }, .stderr = "error: unknown subcommand 'help' for 'ghr minisign'" },
        .{ .args = &.{ "list", "help" }, .stderr = "error: unexpected argument 'help' for 'ghr list'" },
    };
    for (removed_help_cases) |case| {
        const removed_help = b.addRunArtifact(exe);
        removed_help.addArgs(case.args);
        removed_help.expectExitCode(1);
        removed_help.expectStdOutEqual("");
        removed_help.expectStdErrMatch(case.stderr);
        test_step.dependOn(&removed_help.step);
    }

    const list_fixture_dir = b.root.joinString(b.allocator, "src/testdata/list") catch @panic("OOM");
    const list_cases = [_]struct {
        args: []const []const u8,
        stdout: []const u8,
    }{
        .{ .args = &.{"list"}, .stdout = "example/tool\n" },
        .{ .args = &.{ "list", "--ids" }, .stdout = "example/tool\n" },
        .{ .args = &.{ "list", "--tags" }, .stdout = "example/tool@v1\n" },
        .{
            .args = &.{ "list", "--full" },
            .stdout = "installed units (report, not install arguments):\n" ++
                "  example/tool  [v1] ok  source: legacy:example/tool  tag: v1\n" ++
                "\nrun 'ghr list' for bare ids, 'ghr list --tags' for install arguments, or 'ghr list --json' for definitions\n",
        },
    };
    for (list_cases) |case| {
        const list = b.addRunArtifact(exe);
        list.addArgs(case.args);
        list.setEnvironmentVariable("GHR_TOOL_DIR", list_fixture_dir);
        list.setEnvironmentVariable("GHR_BIN_DIR", list_fixture_dir);
        list.setEnvironmentVariable("GHR_CACHE_DIR", list_fixture_dir);
        list.addFileInput(b.path("src/testdata/list/example/tool/ghr.json"));
        list.expectExitCode(0);
        list.expectStdOutEqual(case.stdout);
        list.expectStdErrEqual("");
        test_step.dependOn(&list.step);
    }

    const list_json = b.addRunArtifact(exe);
    list_json.addArgs(&.{ "list", "--json" });
    list_json.setEnvironmentVariable("GHR_TOOL_DIR", list_fixture_dir);
    list_json.setEnvironmentVariable("GHR_BIN_DIR", list_fixture_dir);
    list_json.setEnvironmentVariable("GHR_CACHE_DIR", list_fixture_dir);
    list_json.addFileInput(b.path("src/testdata/list/example/tool/ghr.json"));
    list_json.expectExitCode(0);
    list_json.expectStdOutMatch("\"form\":\"install-records\"");
    list_json.expectStdErrEqual("");
    test_step.dependOn(&list_json.step);

    const list_format_flags = [_][]const u8{ "--ids", "--tags", "--full", "--json" };
    for (list_format_flags) |first| {
        for (list_format_flags) |second| {
            if (std.mem.eql(u8, first, second)) continue;
            const conflict = b.addRunArtifact(exe);
            conflict.addArgs(&.{ "list", first, second });
            conflict.expectExitCode(1);
            conflict.expectStdOutEqual("");
            conflict.expectStdErrMatch(b.fmt("error: '{s}' and '{s}' cannot be combined", .{ first, second }));
            test_step.dependOn(&conflict.step);
        }
    }
}

fn addHelpFlagTests(
    b: *std.Build,
    test_step: *std.Build.Step,
    exe: *std.Build.Step.Compile,
    args: []const []const u8,
    usage: []const u8,
) void {
    for ([_][]const u8{ "-h", "--help" }) |flag| {
        const help = b.addRunArtifact(exe);
        help.addArgs(args);
        help.addArg(flag);
        help.expectExitCode(0);
        help.expectStdOutMatch(usage);
        help.expectStdErrEqual("");
        test_step.dependOn(&help.step);
    }
}
