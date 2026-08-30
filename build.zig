const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const strip = b.option(bool, "strip", "Strip debug info");
    const version_str = b.option([]const u8, "version", "Override version string") orelse "0.8.0";

    const exe_options = b.addOptions();
    exe_options.addOption([]const u8, "version", version_str);

    const exe = b.addExecutable(.{
        .name = "ghr",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .imports = &.{
                .{ .name = "build_options", .module = exe_options.createModule() },
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
            .optimize = .ReleaseSmall,
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
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

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
        .{ .args = &.{ "minisign", "sign" }, .usage = "    ghr minisign sign <file>" },
        .{ .args = &.{"version"}, .usage = "    ghr version" },
        // Help must win after positional arguments so no command reaches IO.
        .{ .args = &.{ "install", "example/tool" }, .usage = "    ghr install <source>" },
        .{ .args = &.{ "download", "example/tool" }, .usage = "    ghr download <spec>" },
        .{ .args = &.{ "link", "example/tool" }, .usage = "    ghr link <id>" },
        .{ .args = &.{ "uninstall", "example/tool" }, .usage = "    ghr uninstall <id>" },
        .{ .args = &.{ "validate", "strip-authenticode", "input.exe", "output.exe" }, .usage = "    ghr validate strip-authenticode <input.exe> <output.exe>" },
        .{ .args = &.{ "minisign", "sign", "input" }, .usage = "    ghr minisign sign <file>" },
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
