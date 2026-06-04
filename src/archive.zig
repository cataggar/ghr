const std = @import("std");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;

/// Validate that an archive entry path is safe (no path traversal, no
/// absolute paths, no Windows drive letters). Used by zip extraction;
/// std.tar already performs equivalent validation internally.
pub fn isSafePath(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '/' or name[0] == '\\') return false;
    if (name.len >= 2 and name[1] == ':') return false;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

pub fn extractZip(io: Io, dest_dir: Dir, file: *File) !void {
    var buf: [8192]u8 = undefined;
    var reader = file.reader(io, &buf);
    try std.zip.extract(dest_dir, &reader, .{ .allow_backslashes = true });
}

pub fn extractTarGz(io: Io, dest_dir: Dir, file: *File, strip_components: u32) !void {
    var file_buf: [8192]u8 = undefined;
    var file_reader = file.reader(io, &file_buf);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(
        &file_reader.interface,
        .gzip,
        &decompress_buf,
    );
    try std.tar.extract(io, dest_dir, &decompress.reader, .{ .strip_components = strip_components });
}

pub fn extractTarXz(allocator: std.mem.Allocator, io: Io, dest_dir: Dir, file: *File, strip_components: u32) !void {
    var file_buf: [8192]u8 = undefined;
    var file_reader = file.reader(io, &file_buf);
    const xz_buf = try allocator.alloc(u8, 8192);
    var xz_decompress = try std.compress.xz.Decompress.init(&file_reader.interface, allocator, xz_buf);
    defer xz_decompress.deinit();
    try std.tar.extract(io, dest_dir, &xz_decompress.reader, .{ .strip_components = strip_components });
}

fn parseDebMember(bytes: []const u8, member_name: []const u8) ![]const u8 {
    if (!std.mem.startsWith(u8, bytes, "!<arch>\n")) return error.InvalidDebArchive;

    var pos: usize = 8;
    while (pos + 60 <= bytes.len) {
        const header = bytes[pos .. pos + 60];
        if (header[0] == 0 and header[1] == 0) break;

        const name_field = std.mem.trimEnd(u8, header[0..16], " /");
        var name: []const u8 = name_field;
        var data_pos = pos + 60;

        if (std.mem.startsWith(u8, name_field, "#1/")) {
            const name_len = try std.fmt.parseUnsigned(usize, name_field[3..], 10);
            name = bytes[data_pos .. data_pos + name_len];
            data_pos += name_len;
        }

        const size = try std.fmt.parseUnsigned(usize, std.mem.trim(u8, header[48..58], " "), 10);
        if (std.mem.eql(u8, name, member_name)) {
            return bytes[data_pos .. data_pos + size];
        }

        pos = data_pos + size;
        if (size % 2 != 0) pos += 1;
    }

    return error.DebMemberNotFound;
}

pub fn extractDeb(allocator: std.mem.Allocator, io: Io, dest_dir: Dir, file: *File) !void {
    const stat = try file.stat(io);
    const bytes = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(bytes);

    var file_buf: [8192]u8 = undefined;
    var file_reader = file.reader(io, &file_buf);
    try file_reader.interface.readSliceAll(bytes);

    const data = try parseDebMember(bytes, "data.tar.zst");
    var in: std.Io.Reader = .fixed(data);
    var zstd_buf: [std.compress.zstd.default_window_len + std.compress.zstd.block_size_max]u8 = undefined;
    var zstd_stream = std.compress.zstd.Decompress.init(&in, &zstd_buf, .{});
    try std.tar.extract(io, dest_dir, &zstd_stream.reader, .{});
}

pub const Format = enum {
    zip,
    tar_gz,
    tar_xz,
    deb,
    unknown,
};

/// Detect archive format from a filename. Returns `.unknown` for anything
/// that isn't a recognised archive suffix (case-insensitive).
pub fn detectFormat(name: []const u8) Format {
    if (endsWithIgnoreCase(name, ".zip")) return .zip;
    if (endsWithIgnoreCase(name, ".tar.gz") or endsWithIgnoreCase(name, ".tgz")) return .tar_gz;
    if (endsWithIgnoreCase(name, ".tar.xz") or endsWithIgnoreCase(name, ".txz")) return .tar_xz;
    if (endsWithIgnoreCase(name, ".deb")) return .deb;
    return .unknown;
}

fn endsWithIgnoreCase(haystack: []const u8, suffix: []const u8) bool {
    if (haystack.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - suffix.len ..], suffix);
}

pub const ExtractError = error{
    UnknownArchiveFormat,
} || std.mem.Allocator.Error || std.fs.File.OpenError ||
    std.fs.Dir.OpenError || std.fs.Dir.MakeError;

/// Extract `archive_path` into `dest_dir` based on its filename suffix.
/// `strip_components` is honoured for tar archives (zip ignores it).
pub fn extractAuto(
    allocator: std.mem.Allocator,
    io: Io,
    dest_dir: Dir,
    archive_path: []const u8,
    strip_components: u32,
) !void {
    const format = detectFormat(archive_path);
    var file = try Dir.openFileAbsolute(io, archive_path, .{});
    defer file.close(io);
    switch (format) {
        .zip => try extractZip(io, dest_dir, &file),
        .tar_gz => try extractTarGz(io, dest_dir, &file, strip_components),
        .tar_xz => try extractTarXz(allocator, io, dest_dir, &file, strip_components),
        .deb => try extractDeb(allocator, io, dest_dir, &file),
        .unknown => return error.UnknownArchiveFormat,
    }
}

test "detectFormat recognises common archive suffixes" {
    try std.testing.expectEqual(Format.zip, detectFormat("foo.zip"));
    try std.testing.expectEqual(Format.zip, detectFormat("FOO.ZIP"));
    try std.testing.expectEqual(Format.tar_gz, detectFormat("foo.tar.gz"));
    try std.testing.expectEqual(Format.tar_gz, detectFormat("foo.tgz"));
    try std.testing.expectEqual(Format.tar_gz, detectFormat("foo.TGZ"));
    try std.testing.expectEqual(Format.tar_xz, detectFormat("foo.tar.xz"));
    try std.testing.expectEqual(Format.tar_xz, detectFormat("foo.txz"));
    try std.testing.expectEqual(Format.deb, detectFormat("foo.deb"));
    try std.testing.expectEqual(Format.deb, detectFormat("FOO.DEB"));
    try std.testing.expectEqual(Format.unknown, detectFormat("foo.exe"));
    try std.testing.expectEqual(Format.unknown, detectFormat("foo"));
    try std.testing.expectEqual(Format.unknown, detectFormat(""));
    try std.testing.expectEqual(Format.unknown, detectFormat("foo.tar"));
}

test "isSafePath rejects path traversal and absolute paths" {
    try std.testing.expect(isSafePath("foo/bar"));
    try std.testing.expect(isSafePath("foo"));
    try std.testing.expect(!isSafePath(""));
    try std.testing.expect(!isSafePath("/etc/passwd"));
    try std.testing.expect(!isSafePath("\\windows\\system32"));
    try std.testing.expect(!isSafePath("C:\\windows"));
    try std.testing.expect(!isSafePath("../escape"));
    try std.testing.expect(!isSafePath("foo/../escape"));
    try std.testing.expect(!isSafePath("foo/.."));
}

/// Create a tar.gz test fixture using the system tar command.
fn createTestTarGz(tmp: *std.testing.TmpDir, names: []const []const u8, contents: []const []const u8) !File {
    const tio = std.testing.io;
    for (names, contents) |name, content| {
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.createDirPath(tio, parent) catch {};
        }
        var f = try tmp.dir.createFile(tio, name, .{ .permissions = .executable_file });
        try f.writeStreamingAll(tio, content);
        f.close(tio);
    }

    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(std.testing.allocator);
    try argv.appendSlice(std.testing.allocator, &.{ "tar", "czf", "archive.tar.gz" });
    try argv.appendSlice(std.testing.allocator, names);

    var child = try std.process.spawn(tio, .{
        .argv = argv.items,
        .cwd = .{ .dir = tmp.dir },
    });
    _ = try child.wait(tio);

    for (names) |name| {
        tmp.dir.deleteFile(tio, name) catch {};
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.deleteDir(tio, parent) catch {};
        }
    }

    return try tmp.dir.openFile(tio, "archive.tar.gz", .{});
}

fn createTestTarXz(tmp: *std.testing.TmpDir, names: []const []const u8, contents: []const []const u8) !File {
    const tio = std.testing.io;
    for (names, contents) |name, content| {
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.createDirPath(tio, parent) catch {};
        }
        var f = try tmp.dir.createFile(tio, name, .{ .permissions = .executable_file });
        try f.writeStreamingAll(tio, content);
        f.close(tio);
    }

    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(std.testing.allocator);
    try argv.appendSlice(std.testing.allocator, &.{ "tar", "cJf", "archive.tar.xz" });
    try argv.appendSlice(std.testing.allocator, names);

    // `tar cJf` shells out to `xz`. Skip the test when the platform lacks
    // either `tar` or `xz` so CI on Windows / minimal Linux images keeps
    // passing without false negatives.
    var child = std.process.spawn(tio, .{
        .argv = argv.items,
        .cwd = .{ .dir = tmp.dir },
    }) catch return error.SkipZigTest;
    const term = child.wait(tio) catch return error.SkipZigTest;
    if (term != .exited or term.exited != 0) return error.SkipZigTest;

    for (names) |name| {
        tmp.dir.deleteFile(tio, name) catch {};
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.deleteDir(tio, parent) catch {};
        }
    }

    return try tmp.dir.openFile(tio, "archive.tar.xz", .{});
}

test "extractTarGz extracts files with correct contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarGz(&tmp, &.{ "myapp/README.md", "myapp/myapp" }, &.{ "readme\n", "#!/bin/sh\necho hello\n" });
    defer file.close(std.testing.io);

    try extractTarGz(std.testing.io, tmp.dir, &file, 0);

    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "myapp/README.md", .{})).kind == .file);
    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "myapp/myapp", .{})).kind == .file);

    const content = try tmp.dir.readFileAlloc(std.testing.io, "myapp/README.md", std.testing.allocator, Io.Limit.limited(256));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("readme\n", content);
}

test "extractTarGz handles single file archive" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarGz(&tmp, &.{"tool"}, &.{"binary"});
    defer file.close(std.testing.io);

    try extractTarGz(std.testing.io, tmp.dir, &file, 0);

    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "tool", .{})).kind == .file);
}

test "extractTarGz strips leading components" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarGz(&tmp, &.{ "myapp/bin/tool", "myapp/README.md" }, &.{ "exec", "readme" });
    defer file.close(std.testing.io);

    try extractTarGz(std.testing.io, tmp.dir, &file, 1);

    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "bin/tool", .{})).kind == .file);
    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "README.md", .{})).kind == .file);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "myapp", .{}));
}

test "extractTarXz extracts files with correct contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarXz(&tmp, &.{ "myapp/README.md", "myapp/myapp" }, &.{ "readme\n", "#!/bin/sh\necho hello\n" });
    defer file.close(std.testing.io);

    try extractTarXz(std.testing.allocator, std.testing.io, tmp.dir, &file, 0);

    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "myapp/README.md", .{})).kind == .file);
    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "myapp/myapp", .{})).kind == .file);

    const content = try tmp.dir.readFileAlloc(std.testing.io, "myapp/README.md", std.testing.allocator, Io.Limit.limited(256));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("readme\n", content);
}

test "extractAuto dispatches on filename and strips components" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarGz(&tmp, &.{ "wrap/inner/tool", "wrap/inner/data.txt" }, &.{ "exec", "data" });
    file.close(std.testing.io);

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const archive_len = try tmp.dir.realPathFile(std.testing.io, "archive.tar.gz", &path_buf);
    const archive_abs = path_buf[0..archive_len];

    try extractAuto(std.testing.allocator, std.testing.io, tmp.dir, archive_abs, 1);

    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "inner/tool", .{})).kind == .file);
    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "inner/data.txt", .{})).kind == .file);
}

fn createTestDeb(tmp: *std.testing.TmpDir) !File {
    const tio = std.testing.io;

    try tmp.dir.createDirPath(tio, "usr/bin");
    try tmp.dir.createDirPath(tio, "usr/lib/azureauth");

    var tool = try tmp.dir.createFile(tio, "usr/bin/azureauth", .{ .permissions = .executable_file });
    try tool.writeStreamingAll(tio, "#!/bin/sh\n");
    tool.close(tio);

    var control = try tmp.dir.createFile(tio, "control", .{});
    try control.writeStreamingAll(tio, "Package: azureauth\nVersion: 1.0\nArchitecture: arm64\n\n");
    control.close(tio);

    var debian_binary = try tmp.dir.createFile(tio, "debian-binary", .{});
    try debian_binary.writeStreamingAll(tio, "2.0\n");
    debian_binary.close(tio);

    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(std.testing.allocator);

    // Each helper invocation requires `tar`, `zstd`, and `ar`. Skip the
    // test if any of them are missing or fail; CI environments without
    // dpkg tooling (e.g. Windows, minimal Linux images) shouldn't fail.
    try argv.appendSlice(std.testing.allocator, &.{ "tar", "--zstd", "-cf", "control.tar.zst", "control" });
    var child = std.process.spawn(tio, .{ .argv = argv.items, .cwd = .{ .dir = tmp.dir } }) catch return error.SkipZigTest;
    var term = child.wait(tio) catch return error.SkipZigTest;
    if (term != .exited or term.exited != 0) return error.SkipZigTest;
    tmp.dir.deleteFile(tio, "control") catch {};

    argv.items.len = 0;
    try argv.appendSlice(std.testing.allocator, &.{ "tar", "--zstd", "-cf", "data.tar.zst", "usr" });
    child = std.process.spawn(tio, .{ .argv = argv.items, .cwd = .{ .dir = tmp.dir } }) catch return error.SkipZigTest;
    term = child.wait(tio) catch return error.SkipZigTest;
    if (term != .exited or term.exited != 0) return error.SkipZigTest;

    argv.items.len = 0;
    try argv.appendSlice(std.testing.allocator, &.{ "ar", "rcs", "archive.deb", "debian-binary", "control.tar.zst", "data.tar.zst" });
    child = std.process.spawn(tio, .{ .argv = argv.items, .cwd = .{ .dir = tmp.dir } }) catch return error.SkipZigTest;
    term = child.wait(tio) catch return error.SkipZigTest;
    if (term != .exited or term.exited != 0) return error.SkipZigTest;

    return try tmp.dir.openFile(tio, "archive.deb", .{});
}

test "extractAuto handles .deb archives" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestDeb(&tmp);
    defer file.close(std.testing.io);

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const archive_len = try tmp.dir.realPathFile(std.testing.io, "archive.deb", &path_buf);
    const archive_abs = path_buf[0..archive_len];

    try tmp.dir.createDirPath(std.testing.io, "extract");
    var extract_dir = try tmp.dir.openDir(std.testing.io, "extract", .{ .iterate = true });
    defer extract_dir.close(std.testing.io);

    try extractAuto(std.testing.allocator, std.testing.io, extract_dir, archive_abs, 0);

    try std.testing.expect((try extract_dir.statFile(std.testing.io, "usr/bin/azureauth", .{})).kind == .file);
    try std.testing.expect((try extract_dir.statFile(std.testing.io, "usr/lib/azureauth", .{})).kind == .directory);
}

test "extractAuto rejects unknown formats" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile(std.testing.io, "blob.bin", .{});
    f.close(std.testing.io);

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const abs_len = try tmp.dir.realPathFile(std.testing.io, "blob.bin", &path_buf);
    const abs = path_buf[0..abs_len];
    try std.testing.expectError(error.UnknownArchiveFormat, extractAuto(std.testing.allocator, std.testing.io, tmp.dir, abs, 0));
}
