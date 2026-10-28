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
        short_help: bool = true,
    }{
        .{ .args = &.{}, .usage = "    ghr <COMMAND> [OPTIONS]" },
        .{ .args = &.{"list"}, .usage = "    ghr list" },
        .{ .args = &.{"install"}, .usage = "    ghr install <source>", .short_help = false },
        .{ .args = &.{"uninstall"}, .usage = "    ghr uninstall <id>" },
        .{ .args = &.{"download"}, .usage = "    ghr download <spec>", .short_help = false },
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
        .{ .args = &.{ "minisign", "generate" }, .usage = "    ghr minisign generate", .short_help = false },
        .{ .args = &.{ "minisign", "sign" }, .usage = "    ghr minisign sign <file>" },
        .{ .args = &.{"version"}, .usage = "    ghr version" },
        // Help must win after positional arguments so no command reaches IO.
        .{ .args = &.{ "install", "example/tool" }, .usage = "    ghr install <source>", .short_help = false },
        .{ .args = &.{ "download", "example/tool" }, .usage = "    ghr download <spec>", .short_help = false },
        .{ .args = &.{ "link", "example/tool" }, .usage = "    ghr link <id>" },
        .{ .args = &.{ "uninstall", "example/tool" }, .usage = "    ghr uninstall <id>" },
        .{ .args = &.{ "validate", "strip-authenticode", "input.exe", "output.exe" }, .usage = "    ghr validate strip-authenticode <input.exe> <output.exe>" },
        .{ .args = &.{ "minisign", "sign", "input" }, .usage = "    ghr minisign sign <file>" },
        .{ .args = &.{ "minisign", "generate", "--repo", "example/tool" }, .usage = "    ghr minisign generate", .short_help = false },
    };
    for (help_cases) |case| {
        addHelpFlagTests(b, test_step, exe, case.args, case.usage, case.short_help);
    }

    const hostname_flag_cases = [_]struct {
        args: []const []const u8,
        stderr: []const u8,
    }{
        .{ .args = &.{ "install", "-h" }, .stderr = "error: '-h' requires a hostname value" },
        .{ .args = &.{ "install", "--hostname" }, .stderr = "error: '--hostname' requires a hostname value" },
        .{ .args = &.{ "download", "-h" }, .stderr = "error: '-h' requires a value" },
        .{ .args = &.{ "download", "--hostname" }, .stderr = "error: '--hostname' requires a value" },
        .{ .args = &.{ "minisign", "generate", "-h" }, .stderr = "error: -h requires HOST" },
        .{ .args = &.{ "minisign", "generate", "--hostname" }, .stderr = "error: --hostname requires HOST" },
    };
    for (hostname_flag_cases) |case| {
        const hostname_cmd = b.addRunArtifact(exe);
        hostname_cmd.addArgs(case.args);
        hostname_cmd.expectExitCode(1);
        hostname_cmd.expectStdOutEqual("");
        hostname_cmd.expectStdErrMatch(case.stderr);
        test_step.dependOn(&hostname_cmd.step);
    }

    const install_ghe_cache_key = b.addRunArtifact(exe);
    install_ghe_cache_key.addArgs(&.{
        "install",
        "--print-cache-key",
        "-h",
        "example.ghe.com",
        "https://example.ghe.com/octocat/hello-world/releases/download/v0.1.0/readme.zip",
    });
    install_ghe_cache_key.expectExitCode(0);
    install_ghe_cache_key.expectStdErrEqual("");
    test_step.dependOn(&install_ghe_cache_key.step);

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
        .{ .args = &.{"list"}, .stdout = "ghr install example/tool@v1\n" },
        .{ .args = &.{ "list", "--ids" }, .stdout = "example/tool\n" },
        .{ .args = &.{ "list", "--tags" }, .stdout = "example/tool@v1\n" },
        .{ .args = &.{ "list", "--install" }, .stdout = "ghr install example/tool@v1\n" },
        .{
            .args = &.{ "list", "--full" },
            .stdout = "installed units (report, not install arguments):\n" ++
                "  example/tool  [v1] ok  source: legacy:example/tool  tag: v1\n" ++
                "\nrun 'ghr list --ids' for bare ids, 'ghr list --install' for install commands, or 'ghr list --json' for definitions\n",
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

    const list_format_flags = [_][]const u8{ "--ids", "--tags", "--install", "--full", "--json" };
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
    short_help: bool,
) void {
    const flags: []const []const u8 = if (short_help) &.{ "-h", "--help" } else &.{"--help"};
    for (flags) |flag| {
        const help = b.addRunArtifact(exe);
        help.addArgs(args);
        help.addArg(flag);
        help.expectExitCode(0);
        help.expectStdOutMatch(usage);
        help.expectStdErrEqual("");
        test_step.dependOn(&help.step);
    }
}
