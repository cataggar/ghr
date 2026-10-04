const std = @import("std");

const page =
    \\const mer = @import("mer");
    \\pub const prerender = true;
    \\pub const meta: mer.Meta = .{ .title = "Cache fixture" };
    \\pub fn render(_: mer.Request) mer.Response { return mer.html("cache-route-marker"); }
;
const layout =
    \\const std = @import("std");
    \\const mer = @import("mer");
    \\pub fn wrap(alloc: std.mem.Allocator, path: []const u8, body: []const u8, meta: mer.Meta) []const u8 {
    \\    _ = path; _ = meta;
    \\    return std.fmt.allocPrint(alloc, "cache-layout-marker:{s}", .{body}) catch @panic("OOM");
    \\}
;
const guide =
    \\# Guide
    \\## YÉS
    \\## YÉS
    \\| A | B |
    \\| - | - |
    \\| x | y |
    \\
    \\```zig
    \\const x = 1;
    \\```
    \\
;
const fixture_name = ".tmp-cache-freshness";

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 3) return error.ExpectedWebsiteAndCompiler;
    const source = try std.Io.Dir.cwd().openDir(init.io, args[1], .{});
    defer source.close(init.io);
    source.createDir(init.io, fixture_name, .default_dir) catch |err| {
        std.log.err("cannot create isolated fixture '{s}': {s}; existing fixtures are never overwritten", .{ fixture_name, @errorName(err) });
        return err;
    };
    exercise(allocator, init.io, source, args[2]) catch |err| {
        source.deleteTree(init.io, fixture_name) catch |cleanup_err| std.log.err("fixture cleanup failed: {s}", .{@errorName(cleanup_err)});
        return err;
    };
    try source.deleteTree(init.io, fixture_name);
    std.debug.print("Warm-cache routes, layouts, app/api presence, Markdown edits/additions/renames/deletions and stale-output checks passed\n", .{});
}

fn exercise(allocator: std.mem.Allocator, io: std.Io, source: std.Io.Dir, zig: []const u8) !void {
    const root = try source.openDir(io, fixture_name, .{});
    defer root.close(io);
    const project = try root.createDirPathOpen(io, "website", .{});
    defer project.close(io);
    for ([_][]const u8{ "build.zig", "build.zig.zon" }) |path| try source.copyFile(path, project, path, io, .{});
    for ([_][]const u8{ "src", "tools", "public" }) |path| try copyDirectory(allocator, io, source, project, path);
    const fixture: Fixture = .{ .allocator = allocator, .io = io, .project = project, .zig = zig };
    try fixture.write("app/index.zig", page);
    try fixture.write("../doc/README.md", "# Documentation\n[Guide](guide.md#yés)\n");
    try fixture.write("../doc/guide.md", guide);
    _ = try fixture.build();
    _ = try fixture.build();
    try fixture.contains("dist/index.html", "cache-route-marker");
    try fixture.contains("dist/docs.html", "/ghr/docs/guide.html#y%C3%A9s");
    try fixture.contains("dist/docs/guide.html", "id=\"yés-1\"");
    try fixture.contains("dist/docs/guide.html", "<table>");
    try fixture.contains("dist/docs/guide.html", "class=\"language-zig\"");
    try fixture.contains("dist/docs.html", "<summary>More documentation</summary>");
    try fixture.contains("dist/docs/guide.html", "href=\"/ghr/docs/guide.html\" aria-current=\"page\"");

    try fixture.write("app/nested/deep/page.zig", page);
    try require(try fixture.build(), "@import(\"app/nested/deep/page\")", true);
    try fixture.contains("dist/nested/deep/page.html", "cache-route-marker");
    try project.rename("app/nested/deep/page.zig", project, "app/nested/deep/renamed.zig", io);
    var routes = try fixture.build();
    try require(routes, "@import(\"app/nested/deep/renamed\")", true);
    try require(routes, "@import(\"app/nested/deep/page\")", false);
    try fixture.contains("dist/nested/deep/renamed.html", "cache-route-marker");
    try fixture.absent("dist/nested/deep/page.html");
    try project.rename("app/nested", project, "app/moved", io);
    routes = try fixture.build();
    try require(routes, "app/moved/deep/renamed", true);
    try require(routes, "app/nested/", false);
    try fixture.contains("dist/moved/deep/renamed.html", "cache-route-marker");
    try fixture.absent("dist/nested/deep/renamed.html");
    try project.deleteFile(io, "app/moved/deep/renamed.zig");
    try require(try fixture.build(), "app/moved/deep/renamed", false);
    try fixture.absent("dist/moved/deep/renamed.html");
    try project.deleteTree(io, "app/moved");
    try require(try fixture.build(), "app/moved/", false);

    try fixture.write("app/layout.zig", layout);
    try require(try fixture.build(), "pub const layout = app_layout.wrap;", true);
    try fixture.contains("dist/index.html", "cache-layout-marker");
    try project.deleteFile(io, "app/layout.zig");
    try require(try fixture.build(), "app_layout", false);
    try require(try fixture.read("dist/index.html"), "cache-layout-marker", false);
    try fixture.write("api/v1/ping.zig", page);
    try require(try fixture.build(), "@import(\"api/v1/ping\")", true);
    try fixture.contains("dist/api/v1/ping.html", "cache-route-marker");
    try project.deleteTree(io, "api");
    try require(try fixture.build(), "api/v1/ping", false);
    try fixture.absent("dist/api/v1/ping.html");
    try project.deleteTree(io, "app");
    try require(try fixture.build(), "const app_", false);
    try fixture.absent("dist/index.html");
    try fixture.write("app/recreated.zig", page);
    try require(try fixture.build(), "@import(\"app/recreated\")", true);
    try fixture.contains("dist/recreated.html", "cache-route-marker");

    try fixture.write("../doc/guide.md", guide ++ "\nedited-content-marker\n");
    _ = try fixture.build();
    try fixture.contains("dist/docs/guide.html", "edited-content-marker");
    try fixture.write("../doc/nested/new.md", "# New document\n[Guide](../guide.md#yés)\n");
    _ = try fixture.build();
    try fixture.contains("dist/docs/nested/new.html", "/ghr/docs/guide.html#y%C3%A9s");
    try fixture.contains("dist/docs.html", "/ghr/docs/nested/new.html");
    try fixture.contains("dist/docs/nested/new.html", "href=\"/ghr/docs/nested/new.html\" aria-current=\"page\"");
    try project.rename("../doc/nested/new.md", project, "../doc/nested/renamed.md", io);
    _ = try fixture.build();
    try fixture.contains("dist/docs/nested/renamed.html", "New document");
    try fixture.contains("dist/docs.html", "/ghr/docs/nested/renamed.html");
    try fixture.absent("dist/docs/nested/new.html");
    try project.deleteFile(io, "../doc/nested/renamed.md");
    _ = try fixture.build();
    try fixture.absent("dist/docs/nested/renamed.html");
    try require(try fixture.read("dist/docs.html"), "/ghr/docs/nested/renamed.html", false);
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    project: std.Io.Dir,
    zig: []const u8,

    fn write(self: Fixture, path: []const u8, contents: []const u8) !void {
        const parent = try self.project.createDirPathOpen(self.io, std.fs.path.dirname(path) orelse ".", .{});
        defer parent.close(self.io);
        const file = try parent.createFile(self.io, std.fs.path.basename(path), .{});
        defer file.close(self.io);
        try file.writePositionalAll(self.io, contents, 0);
    }

    fn read(self: Fixture, path: []const u8) ![]u8 {
        return self.project.readFileAlloc(self.io, path, self.allocator, .limited(4 * 1024 * 1024));
    }

    fn build(self: Fixture) ![]u8 {
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = &.{ self.zig, "build", "prod" },
            .cwd = .{ .dir = self.project },
            .stdout_limit = .limited(4 * 1024 * 1024),
            .stderr_limit = .limited(4 * 1024 * 1024),
        });
        if (result.term != .exited or result.term.exited != 0) {
            std.log.err("fixture production build failed:\n{s}\n{s}", .{ result.stdout, result.stderr });
            return error.FixtureBuildFailed;
        }
        return self.read("src/generated/routes.zig");
    }

    fn contains(self: Fixture, path: []const u8, marker: []const u8) !void {
        try require(try self.read(path), marker, true);
    }

    fn absent(self: Fixture, path: []const u8) !void {
        const file = self.project.openFile(self.io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        file.close(self.io);
        std.log.err("stale generated output: {s}", .{path});
        return error.StaleOutput;
    }
};

fn require(contents: []const u8, marker: []const u8, present: bool) !void {
    if ((std.mem.find(u8, contents, marker) != null) != present) {
        std.log.err("expected marker '{s}' to be {s}", .{ marker, if (present) "present" else "absent" });
        return error.UnexpectedGeneratedContent;
    }
}

fn copyDirectory(allocator: std.mem.Allocator, io: std.Io, source: std.Io.Dir, destination: std.Io.Dir, path: []const u8) !void {
    const dir = try source.openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const full = try std.fs.path.join(allocator, &.{ path, entry.path });
        const parent = try destination.createDirPathOpen(io, std.fs.path.dirname(full) orelse ".", .{});
        parent.close(io);
        try source.copyFile(full, destination, full, io, .{});
    }
}
