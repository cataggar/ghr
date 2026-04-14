const std = @import("std");
const builtin = @import("builtin");

pub const Dirs = struct {
    bin: []const u8,
    tools: []const u8,
    cache: []const u8,
    allocator: std.mem.Allocator,

    pub fn detect(allocator: std.mem.Allocator) !Dirs {
        const bin = try binDir(allocator);
        errdefer allocator.free(bin);
        const tools = try toolsDir(allocator);
        errdefer allocator.free(tools);
        const cache = try cacheDir(allocator);
        return .{ .bin = bin, .tools = tools, .cache = cache, .allocator = allocator };
    }

    pub fn deinit(self: Dirs) void {
        self.allocator.free(self.bin);
        self.allocator.free(self.tools);
        self.allocator.free(self.cache);
    }
};

fn getEnv(key: [:0]const u8) ?[]const u8 {
    const val = std.c.getenv(key) orelse return null;
    return std.mem.sliceTo(val, 0);
}

fn homeDir() ![]const u8 {
    const key: [:0]const u8 = if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    return getEnv(key) orelse error.HomeNotFound;
}

fn binDir(allocator: std.mem.Allocator) ![]const u8 {
    if (getEnv("GHR_BIN_DIR")) |v| return allocator.dupe(u8, v);
    const h = try homeDir();
    return std.fs.path.join(allocator, &.{ h, ".local", "bin" });
}

fn toolsDir(allocator: std.mem.Allocator) ![]const u8 {
    if (getEnv("GHR_TOOL_DIR")) |v| return allocator.dupe(u8, v);
    if (builtin.os.tag == .windows) {
        const appdata = getEnv("APPDATA") orelse return error.AppDataNotFound;
        return std.fs.path.join(allocator, &.{ appdata, "ghr", "data", "tools" });
    }
    if (getEnv("XDG_DATA_HOME")) |xdg| {
        return std.fs.path.join(allocator, &.{ xdg, "ghr", "tools" });
    }
    const h = try homeDir();
    return std.fs.path.join(allocator, &.{ h, ".local", "share", "ghr", "tools" });
}

fn cacheDir(allocator: std.mem.Allocator) ![]const u8 {
    if (getEnv("GHR_CACHE_DIR")) |v| return allocator.dupe(u8, v);
    if (builtin.os.tag == .windows) {
        const localappdata = getEnv("LOCALAPPDATA") orelse return error.LocalAppDataNotFound;
        return std.fs.path.join(allocator, &.{ localappdata, "ghr", "cache" });
    }
    if (comptime builtin.os.tag.isDarwin()) {
        const h = try homeDir();
        return std.fs.path.join(allocator, &.{ h, "Library", "Caches", "ghr" });
    }
    if (getEnv("XDG_CACHE_HOME")) |xdg| {
        return std.fs.path.join(allocator, &.{ xdg, "ghr" });
    }
    const h = try homeDir();
    return std.fs.path.join(allocator, &.{ h, ".cache", "ghr" });
}

test "detect dirs" {
    const allocator = std.testing.allocator;
    const d = try Dirs.detect(allocator);
    defer d.deinit();
    try std.testing.expect(d.bin.len > 0);
    try std.testing.expect(d.tools.len > 0);
    try std.testing.expect(d.cache.len > 0);
}
