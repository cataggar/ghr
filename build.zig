const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const strip = b.option(bool, "strip", "Strip debug info");
    const version_str = b.option([]const u8, "version", "Override version string") orelse "0.1.0-dev";

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

    // On Windows, build a small shim exe and embed it inside ghr.
    // The shim reads a companion .shim file to find the real executable.
    // This is the same technique used by npm and Scoop on Windows.
    const resolved_target = target.result;
    if (resolved_target.os.tag == .windows) {
        const shim = b.addExecutable(.{
            .name = "shim",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/shim.zig"),
                .target = target,
                .optimize = .ReleaseSmall,
                .strip = true,
            }),
        });
        // Embed the compiled shim binary so it's always available at runtime,
        // regardless of how ghr is installed (PyPI, GitHub release, etc.)
        exe.root_module.addAnonymousImport("shim_exe", .{
            .root_source_file = b.addWriteFiles().add(
                "shim_exe.zig",
                "pub const bytes = @embedFile(\"shim.exe\");",
            ),
            .imports = &.{.{
                .name = "shim.exe",
                .module = b.createModule(.{ .root_source_file = shim.getEmittedBin() }),
            }},
        });
    }

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
}
