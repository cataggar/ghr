const std = @import("std");
const koino = @import("koino");
const config = @import("config");

const options: koino.Options = .{
    .extensions = .{ .table = true, .strikethrough = true, .autolink = true, .tagfilter = true },
    .render = .{ .header_anchors = true },
};
const Document = struct {
    source: []const u8,
    route: []const u8,
    title: []const u8,
    ast: *koino.nodes.AstNode,
    anchors: std.StringHashMap(void),
};

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 3) return error.ExpectedDocDirectoryAndOutput;
    const dir = try std.Io.Dir.cwd().openDir(init.io, args[1], .{ .iterate = true });
    defer dir.close(init.io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var paths: std.ArrayList([]const u8) = .empty;
    while (try walker.next(init.io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".md")) continue;
        const path = try allocator.dupe(u8, entry.path);
        for (path) |*byte| if (byte.* == '\\') {
            byte.* = '/';
        };
        try paths.append(allocator, path);
    }
    if (paths.items.len == 0) return error.NoMarkdownDocuments;
    std.mem.sort([]const u8, paths.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    var documents: std.ArrayList(Document) = .empty;
    defer for (documents.items) |document| document.ast.deinit();
    for (paths.items) |path| {
        const markdown = try dir.readFileAlloc(init.io, path, allocator, .limited(4 * 1024 * 1024));
        const document = parseDocument(allocator, path, markdown) catch |err| {
            std.log.err("{s}: cannot parse document: {s}", .{ path, @errorName(err) });
            return err;
        };
        try documents.append(allocator, document);
    }
    var output: std.Io.Writer.Allocating = .init(allocator);
    const writer = &output.writer;
    try writer.writeAll("// Generated from doc/; do not edit.\nconst mer = @import(\"mer\");\n\n");
    for (documents.items, 0..) |*document, index| {
        try rewriteLinks(allocator, document, documents.items);
        var html: std.Io.Writer.Allocating = .init(allocator);
        try html.writer.writeAll("<article class=\"prose docs\"><nav class=\"docs-nav\" aria-label=\"Documentation\">");
        for (documents.items) |item| {
            const href = try publicUrl(allocator, item.route);
            try html.writer.print("<a href=\"{s}\">{s}</a> ", .{ try escapeHtml(allocator, href), try escapeHtml(allocator, item.title) });
        }
        try html.writer.writeAll("</nav>\n");
        try koino.html.print(&html.writer, allocator, options, document.ast);
        try html.writer.print("<p class=\"doc-source\"><a href=\"{s}/blob/main/doc/{s}\">View Markdown source</a></p></article>\n", .{ config.repository_url, try encodePath(allocator, document.source) });
        try writer.print("fn render_{d}(_: mer.Request) mer.Response {{ return mer.html(\"{f}\"); }}\n", .{ index, std.zig.fmtString(html.written()) });
    }
    try writer.writeAll("\npub const routes = [_]mer.Route{\n");
    for (documents.items, 0..) |document, index| {
        try writer.print("    .{{ .path = \"{f}\", .render = render_{d}, .meta = .{{ .title = \"{f}\" }}, .prerender = true }},\n", .{ std.zig.fmtString(document.route), index, std.zig.fmtString(try escapeHtml(allocator, document.title)) });
    }
    try writer.writeAll("};\n");
    const file = try std.Io.Dir.cwd().createFile(init.io, args[2], .{});
    defer file.close(init.io);
    try file.writePositionalAll(init.io, output.written(), 0);
}

fn parseDocument(allocator: std.mem.Allocator, source: []const u8, markdown: []const u8) !Document {
    const ast = try koino.parse(allocator, markdown, options);
    errdefer ast.deinit();
    var anchors = std.StringHashMap(void).init(allocator);
    var buffer: std.Io.Writer.Allocating = .init(allocator);
    defer buffer.deinit();
    var formatter = koino.html.makeHtmlFormatter(&buffer.writer, allocator, options);
    defer formatter.deinit();
    var title: ?[]const u8 = null;
    var nodes = ast.descendantsIterator();
    while (nodes.next()) |node| {
        switch (node.data.value) {
            .Heading => |heading| {
                const anchor = try allocator.dupe(u8, try formatter.getNodeAnchor(node));
                try anchors.put(anchor, {});
                if (heading.level == 1 and title == null) {
                    var text: std.Io.Writer.Allocating = .init(allocator);
                    var children = node.descendantsIterator();
                    while (children.next()) |child| {
                        switch (child.data.value) {
                            .Text, .Code => |literal| try text.writer.writeAll(literal),
                            .SoftBreak, .LineBreak => try text.writer.writeByte(' '),
                            else => {},
                        }
                    }
                    title = try allocator.dupe(u8, text.written());
                    text.deinit();
                }
            },
            else => {},
        }
    }
    return .{
        .source = source,
        .route = try routeFor(allocator, source),
        .title = title orelse return error.DocumentMissingH1,
        .ast = ast,
        .anchors = anchors,
    };
}

fn rewriteLinks(allocator: std.mem.Allocator, document: *Document, documents: []const Document) !void {
    var nodes = document.ast.descendantsIterator();
    while (nodes.next()) |node| {
        const link = switch (node.data.value) {
            .Link => |*link| link,
            .Image => |*image| image,
            else => continue,
        };
        const image = node.data.value == .Image;
        const rewritten = rewriteUrl(allocator, document, documents, link.url, image) catch |err| {
            std.log.err("{s}: cannot publish link '{s}': {s}", .{ document.source, link.url, @errorName(err) });
            return err;
        };
        allocator.free(link.url);
        link.url = rewritten;
    }
}

fn rewriteUrl(allocator: std.mem.Allocator, current: *const Document, documents: []const Document, url: []const u8, image: bool) ![]u8 {
    if (url.len == 0 or std.mem.startsWith(u8, url, "//")) return allocator.dupe(u8, url);
    const path_end = std.mem.findAny(u8, url, "?#") orelse url.len;
    if (std.mem.findScalar(u8, url[0..path_end], ':') != null) return allocator.dupe(u8, url);
    const fragment_index = std.mem.findScalar(u8, url, '#');
    const path = try decodePath(allocator, url[0..path_end]);
    const query_end = fragment_index orelse url.len;
    const query = url[path_end..query_end];
    const fragment = if (fragment_index) |index| url[index + 1 ..] else "";
    const resolved = if (path.len == 0)
        try std.fmt.allocPrint(allocator, "/doc/{s}", .{current.source})
    else
        try std.fs.path.resolvePosix(allocator, &.{ "/doc", std.fs.path.dirname(current.source) orelse "", path });
    if (!image and std.mem.startsWith(u8, resolved, "/doc/") and std.mem.endsWith(u8, resolved, ".md")) {
        for (documents) |target| {
            if (!std.mem.eql(u8, target.source, resolved["/doc/".len..])) continue;
            if (fragment.len != 0 and !target.anchors.contains(try decodePath(allocator, fragment))) return error.UnknownHeadingFragment;
            const suffix = if (fragment_index) |index| url[index..] else "";
            if (path.len == 0 and query.len == 0) return allocator.dupe(u8, suffix);
            return std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ try publicUrl(allocator, target.route), query, suffix });
        }
        return error.MissingMarkdownTarget;
    }
    const prefix = if (image) config.raw_repository_url else config.repository_url ++ "/blob/main";
    return std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ prefix, try encodePath(allocator, resolved), url[path_end..] });
}

fn routeFor(allocator: std.mem.Allocator, source: []const u8) ![]u8 {
    if (std.mem.eql(u8, source, "README.md")) return allocator.dupe(u8, "/docs");
    return std.fmt.allocPrint(allocator, "/docs/{s}", .{source[0 .. source.len - ".md".len]});
}

fn publicUrl(allocator: std.mem.Allocator, route: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{s}.html", .{ config.base_path, try encodePath(allocator, route) });
}

fn encodePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    for (path) |byte| {
        if (std.ascii.isAlphanumeric(byte) or std.mem.findScalar(u8, "-._~/", byte) != null) {
            try output.writer.writeByte(byte);
        } else {
            try output.writer.print("%{X:0>2}", .{byte});
        }
    }
    return allocator.dupe(u8, output.written());
}

fn decodePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (path[i] == '%') {
            if (i + 2 >= path.len) return error.InvalidUrlEncoding;
            const high = try std.fmt.charToDigit(path[i + 1], 16);
            const low = try std.fmt.charToDigit(path[i + 2], 16);
            const byte = high * 16 + low;
            if (byte == 0 or byte == '\\') return error.InvalidUrlPath;
            try output.writer.writeByte(byte);
            i += 2;
        } else {
            if (path[i] == '\\') return error.InvalidUrlPath;
            try output.writer.writeByte(path[i]);
        }
    }
    return allocator.dupe(u8, output.written());
}

fn escapeHtml(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    for (text) |byte| {
        try output.writer.writeAll(switch (byte) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            else => &.{byte},
        });
    }
    return allocator.dupe(u8, output.written());
}

test "native Markdown keeps GFM, Unicode and duplicate heading anchors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const document = try parseDocument(allocator, "guide.md", "# Guide\n## YÉS\n## YÉS\n\n| A | B |\n| - | - |\n| x | y |\n\n```zig\nconst x = 1;\n```\n\n<script>bad()</script>\n");
    defer document.ast.deinit();
    try std.testing.expect(document.anchors.contains("yés"));
    try std.testing.expect(document.anchors.contains("yés-1"));
    var html: std.Io.Writer.Allocating = .init(allocator);
    defer html.deinit();
    try koino.html.print(&html.writer, allocator, options, document.ast);
    try std.testing.expect(std.mem.find(u8, html.written(), "<table>") != null);
    try std.testing.expect(std.mem.find(u8, html.written(), "class=\"language-zig\"") != null);
    try std.testing.expect(std.mem.find(u8, html.written(), "<script>") == null);
}

test "AST link rewriting resolves pages, fragments, queries and repository files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const index = try parseDocument(allocator, "README.md", "# Documentation\n");
    defer index.ast.deinit();
    const guide = try parseDocument(allocator, "nested/guide.md", "# Guide\n## YÉS\n");
    defer guide.ast.deinit();
    const documents = [_]Document{ index, guide };
    try std.testing.expectEqualStrings("/ghr/docs/nested/guide.html?x=1#y%C3%A9s", try rewriteUrl(allocator, &index, &documents, "nested/guide.md?x=1#y%C3%A9s", false));
    try std.testing.expectEqualStrings("/ghr/docs.html", try rewriteUrl(allocator, &guide, &documents, "../README.md", false));
    try std.testing.expectEqualStrings("#yés", try rewriteUrl(allocator, &guide, &documents, "#yés", false));
    try std.testing.expectEqualStrings(config.repository_url ++ "/blob/main/README.md", try rewriteUrl(allocator, &index, &documents, "../README.md", false));
    try std.testing.expectEqualStrings(config.raw_repository_url ++ "/doc/nested/image%20one.png", try rewriteUrl(allocator, &guide, &documents, "image%20one.png", true));
    try std.testing.expectEqualStrings("https://example.test/file.md#x", try rewriteUrl(allocator, &guide, &documents, "https://example.test/file.md#x", false));
    try std.testing.expectError(error.UnknownHeadingFragment, rewriteUrl(allocator, &index, &documents, "nested/guide.md#missing", false));
    try std.testing.expectError(error.MissingMarkdownTarget, rewriteUrl(allocator, &index, &documents, "missing.md", false));
}
