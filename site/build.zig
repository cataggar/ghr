const std = @import("std");

pub fn build(b: *std.Build) void {
    // Track app/api presence as well as the contents of existing directories.
    b.dependOnDirectoryContents(b.path("."));
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const merjs_dep = b.dependency("merjs", .{});
    const mer_mod = merjs_dep.module("mer");
    const runtime_mod = merjs_dep.module("runtime");

    const main_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = if (optimize != .debug) true else null,
        .link_libc = true,
    });
    main_mod.addImport("mer", mer_mod);
    main_mod.addImport("runtime", runtime_mod);
    addDirModules(b, main_mod, mer_mod, "app");
    addDirModules(b, main_mod, mer_mod, "api");
    addRoutesModule(b, main_mod, mer_mod);

    const exe = b.addExecutable(.{ .name = "site", .root_module = main_mod });
    b.installArtifact(exe);

    // zig build codegen — scans app/ and writes src/generated/routes.zig.
    const codegen_mod = b.createModule(.{
        .root_source_file = b.path("tools/codegen.zig"),
        .target = b.graph.host,
        .optimize = .debug,
    });
    codegen_mod.addImport("runtime", runtime_mod);
    const codegen_exe = b.addExecutable(.{ .name = "codegen", .root_module = codegen_mod });
    const codegen_tests = b.addTest(.{ .root_module = codegen_mod });
    b.step("test", "Test route code generation").dependOn(&b.addRunArtifact(codegen_tests).step);
    const run_codegen = b.addRunArtifact(codegen_exe);
    run_codegen.setCwd(b.path("."));
    b.step("codegen", "Regenerate src/generated/routes.zig").dependOn(&run_codegen.step);

    // Auto-run codegen before compiling (fresh clones just work).
    exe.step.dependOn(&run_codegen.step);

    // zig build serve — dev server with hot reload.
    const run_exe = b.addRunArtifact(exe);
    run_exe.step.dependOn(b.getInstallStep());
    run_exe.addPassthruArgs();
    b.step("serve", "Start the dev server").dependOn(&run_exe.step);

    // zig build prerender — SSG: write dist/ for pages with `pub const prerender = true`.
    const run_prerender = b.addRunArtifact(exe);
    run_prerender.addArg("--prerender");
    run_prerender.step.dependOn(b.getInstallStep());
    b.step("prerender", "Pre-render pages to dist/").dependOn(&run_prerender.step);

    // zig build prod — full production build: codegen + compile + prerender to dist/.
    const prod_step = b.step("prod", "Full production build: codegen + compile + prerender to dist/");
    prod_step.dependOn(&run_codegen.step);
    prod_step.dependOn(b.getInstallStep());
    prod_step.dependOn(&run_prerender.step);
}

fn addRoutesModule(b: *std.Build, mod: *std.Build.Module, mer_mod: *std.Build.Module) void {
    const routes_mod = b.createModule(.{
        .root_source_file = b.path("src/generated/routes.zig"),
    });
    routes_mod.addImport("mer", mer_mod);
    addDirModules(b, routes_mod, mer_mod, "app");
    addDirModules(b, routes_mod, mer_mod, "api");
    mod.addImport("routes", routes_mod);
}

fn addDirModules(b: *std.Build, mod: *std.Build.Module, mer_mod: *std.Build.Module, dir: []const u8) void {
    // Directory inputs track optional layouts and route additions/removals.
    // The dependency is non-recursive, so register every walked directory too.
    const layout_path = b.fmt("{s}/layout.zig", .{dir});
    const layout_mod: ?*std.Build.Module = blk: {
        b.root.access(b.graph.io, layout_path, .{}) catch break :blk null;
        const m = b.createModule(.{ .root_source_file = b.path(layout_path) });
        m.addImport("mer", mer_mod);
        mod.addImport(b.fmt("{s}/layout", .{dir}), m);
        break :blk m;
    };
    var d = b.root.openDir(b.graph.io, dir, .{ .iterate = true }) catch return;
    defer d.close(b.graph.io);
    b.dependOnDirectoryContents(b.path(dir));
    var walker = d.walk(b.allocator) catch return;
    defer walker.deinit();
    while (walker.next(b.graph.io) catch null) |entry| {
        if (entry.kind == .directory) {
            b.dependOnDirectoryContents(b.path(b.fmt("{s}/{s}", .{ dir, entry.path })));
            continue;
        }
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;
        if (std.mem.eql(u8, entry.path, "layout.zig")) continue;
        const file_path = b.fmt("{s}/{s}", .{ dir, entry.path });
        const import_name_raw = b.fmt("{s}/{s}", .{ dir, entry.path[0 .. entry.path.len - 4] });
        // Normalize OS-native separators (backslash on Windows) to '/' so
        // this module name matches the @import string tools/codegen.zig
        // writes into src/generated/routes.zig for nested app/ directories.
        const import_name = if (std.fs.path.sep != '/') blk: {
            const buf = b.allocator.dupe(u8, import_name_raw) catch @panic("OOM");
            for (buf) |*c| {
                if (c.* == std.fs.path.sep) c.* = '/';
            }
            break :blk buf;
        } else import_name_raw;
        const route_mod = b.createModule(.{ .root_source_file = b.path(file_path) });
        route_mod.addImport("mer", mer_mod);
        if (layout_mod) |lm| route_mod.addImport(b.fmt("{s}/layout", .{dir}), lm);
        mod.addImport(import_name, route_mod);
    }
}
