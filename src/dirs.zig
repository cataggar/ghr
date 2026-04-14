const std = @import("std");
const builtin = @import("builtin");
const EnvironMap = std.process.Environ.Map;

pub const Dirs = struct {
    bin: []const u8,
    tools: []const u8,
    cache: []const u8,
    allocator: std.mem.Allocator,

    pub fn detect(allocator: std.mem.Allocator, environ: *const EnvironMap) !Dirs {
        const bin = try binDir(allocator, environ);
        errdefer allocator.free(bin);
        const tools = try toolsDir(allocator, environ);
        errdefer allocator.free(tools);
        const cache = try cacheDir(allocator, environ);
        return .{ .bin = bin, .tools = tools, .cache = cache, .allocator = allocator };
    }

    pub fn deinit(self: Dirs) void {
        self.allocator.free(self.bin);
        self.allocator.free(self.tools);
        self.allocator.free(self.cache);
    }
};

fn getEnv(environ: *const EnvironMap, key: []const u8) ?[]const u8 {
    return environ.get(key);
}

fn homeDir(environ: *const EnvironMap) ![]const u8 {
    const key = if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    return getEnv(environ, key) orelse error.HomeNotFound;
}

fn binDir(allocator: std.mem.Allocator, environ: *const EnvironMap) ![]const u8 {
    if (getEnv(environ, "GHR_BIN_DIR")) |v| return allocator.dupe(u8, v);
    const h = try homeDir(environ);
    return std.fs.path.join(allocator, &.{ h, ".local", "bin" });
}

fn toolsDir(allocator: std.mem.Allocator, environ: *const EnvironMap) ![]const u8 {
    if (getEnv(environ, "GHR_TOOL_DIR")) |v| return allocator.dupe(u8, v);
    if (builtin.os.tag == .windows) {
        const appdata = getEnv(environ, "APPDATA") orelse return error.AppDataNotFound;
        return std.fs.path.join(allocator, &.{ appdata, "ghr", "data", "tools" });
    }
    if (getEnv(environ, "XDG_DATA_HOME")) |xdg| {
        return std.fs.path.join(allocator, &.{ xdg, "ghr", "tools" });
    }
    const h = try homeDir(environ);
    return std.fs.path.join(allocator, &.{ h, ".local", "share", "ghr", "tools" });
}

fn cacheDir(allocator: std.mem.Allocator, environ: *const EnvironMap) ![]const u8 {
    if (getEnv(environ, "GHR_CACHE_DIR")) |v| return allocator.dupe(u8, v);
    if (builtin.os.tag == .windows) {
        const localappdata = getEnv(environ, "LOCALAPPDATA") orelse return error.LocalAppDataNotFound;
        return std.fs.path.join(allocator, &.{ localappdata, "ghr", "cache" });
    }
    if (comptime builtin.os.tag.isDarwin()) {
        const h = try homeDir(environ);
        return std.fs.path.join(allocator, &.{ h, "Library", "Caches", "ghr" });
    }
    if (getEnv(environ, "XDG_CACHE_HOME")) |xdg| {
        return std.fs.path.join(allocator, &.{ xdg, "ghr" });
    }
    const h = try homeDir(environ);
    return std.fs.path.join(allocator, &.{ h, ".cache", "ghr" });
}

test "detect dirs" {
    const allocator = std.testing.allocator;
    var env_map = try std.testing.environ.createMap(allocator);
    defer env_map.deinit();
    const d = try Dirs.detect(allocator, &env_map);
    defer d.deinit();
    try std.testing.expect(d.bin.len > 0);
    try std.testing.expect(d.tools.len > 0);
    try std.testing.expect(d.cache.len > 0);
}
