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
const NavigationPage = struct { source: []const u8, label: []const u8 };
const NavigationGroup = struct { label: []const u8, pages: []const NavigationPage };
const navigation = [_]NavigationGroup{
    .{ .label = "Getting started", .pages = &.{
        .{ .source = "getting-started.md", .label = "Quick start" },
        .{ .source = "README.md", .label = "Overview" },
        .{ .source = "install.md", .label = "Installation" },
    } },
    .{ .label = "Guides", .pages = &.{
        .{ .source = "download.md", .label = "Download assets" },
        .{ .source = "github-actions.md", .label = "GitHub Actions" },
        .{ .source = "wsl-linking.md", .label = "WSL linking" },
        .{ .source = "troubleshooting.md", .label = "Troubleshooting" },
    } },
    .{ .label = "Reference", .pages = &.{
        .{ .source = "directories.md", .label = "Directories" },
        .{ .source = "verification.md", .label = "Verification" },
    } },
    .{ .label = "Development", .pages = &.{
        .{ .source = "install-identifiers.md", .label = "Install identifiers" },
        .{ .source = "reproducible-builds.md", .label = "Reproducible builds" },
    } },
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
    var home_navigation: std.Io.Writer.Allocating = .init(allocator);
    try renderNavigation(allocator, &home_navigation.writer, "", documents.items);
    try writer.print("pub const home_navigation = \"{f}\";\n\n", .{std.zig.fmtString(home_navigation.written())});
    for (documents.items, 0..) |*document, index| {
        try rewriteLinks(allocator, document, documents.items);
        var html: std.Io.Writer.Allocating = .init(allocator);
        try html.writer.writeAll("<div class=\"docs-shell\">\n");
        try renderNavigation(allocator, &html.writer, document.source, documents.items);
        try html.writer.writeAll("<main id=\"main-content\" tabindex=\"-1\" class=\"prose docs\">\n");
        try koino.html.print(&html.writer, allocator, options, document.ast);
        try html.writer.print("<p class=\"doc-source\"><a href=\"{s}/blob/main/doc/{s}\">View Markdown source</a></p></main>\n</div>\n", .{ config.repository_url, try encodePath(allocator, document.source) });
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

fn renderNavigation(allocator: std.mem.Allocator, writer: *std.Io.Writer, current: []const u8, documents: []const Document) !void {
    try writer.writeAll("<aside class=\"docs-sidebar\"><details class=\"docs-menu\" open><summary>Documentation menu</summary>\n<nav class=\"docs-index\" aria-label=\"Documentation\"><p class=\"docs-index-title\">Documentation</p><ul>\n");
    for (navigation) |group| {
        var present = false;
        for (group.pages) |page| {
            if (findDocument(documents, page.source) == null) continue;
            present = true;
        }
        if (!present) continue;
        try writer.print("<li><details class=\"docs-group\" open><summary>{s}</summary><ul>\n", .{try escapeHtml(allocator, group.label)});
        for (group.pages) |page| {
            const document = findDocument(documents, page.source) orelse continue;
            try renderNavigationLink(allocator, writer, current, document, page.label);
        }
        try writer.writeAll("</ul></details></li>\n");
    }
    var additional = false;
    for (documents) |document| {
        if (isClassified(document.source)) continue;
        additional = true;
    }
    if (additional) {
        try writer.writeAll("<li><details class=\"docs-group\" open><summary>More documentation</summary><ul>\n");
        for (documents) |document| {
            if (isClassified(document.source)) continue;
            try renderNavigationLink(allocator, writer, current, document, document.title);
        }
        try writer.writeAll("</ul></details></li>\n");
    }
    try writer.writeAll("</ul></nav></details></aside>\n");
}

fn findDocument(documents: []const Document, source: []const u8) ?Document {
    for (documents) |document| {
        if (std.mem.eql(u8, document.source, source)) return document;
    }
    return null;
}

fn isClassified(source: []const u8) bool {
    for (navigation) |group| {
        for (group.pages) |page| {
            if (std.mem.eql(u8, source, page.source)) return true;
        }
    }
    return false;
}

fn renderNavigationLink(allocator: std.mem.Allocator, writer: *std.Io.Writer, current: []const u8, document: Document, label: []const u8) !void {
    try writer.print("<li><a href=\"{s}\"{s}>{s}</a></li>\n", .{
        try escapeHtml(allocator, try publicUrl(allocator, document.route)),
        if (std.mem.eql(u8, current, document.source)) " aria-current=\"page\"" else "",
        try escapeHtml(allocator, label),
    });
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

test "documentation navigation expands all groups and keeps reading order and current page" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const index = try parseDocument(allocator, "README.md", "# Documentation\n");
    defer index.ast.deinit();
    const install = try parseDocument(allocator, "install.md", "# Install\n");
    defer install.ast.deinit();
    const start = try parseDocument(allocator, "getting-started.md", "# Getting started\n");
    defer start.ast.deinit();
    const verify = try parseDocument(allocator, "verification.md", "# Verification\n");
    defer verify.ast.deinit();
    var html: std.Io.Writer.Allocating = .init(allocator);
    try renderNavigation(allocator, &html.writer, verify.source, &.{ index, install, start, verify });
    const output = html.written();
    try std.testing.expect(std.mem.find(u8, output, "class=\"docs-group\" open><summary>Getting started") != null);
    try std.testing.expect(std.mem.find(u8, output, "class=\"docs-group\" open><summary>Reference") != null);
    try std.testing.expect(std.mem.find(u8, output, "/ghr/docs/verification.html\" aria-current=\"page\"") != null);
    try std.testing.expect(std.mem.find(u8, output, ">Quick start<").? < std.mem.find(u8, output, ">Overview<").?);
    try std.testing.expect(std.mem.find(u8, output, ">Overview<").? < std.mem.find(u8, output, ">Installation<").?);
    try std.testing.expect(std.mem.find(u8, output, "<summary>Guides") == null);
    try std.testing.expect(std.mem.find(u8, output, "/ghr/docs/directories.html") == null);
    html.clearRetainingCapacity();
    try renderNavigation(allocator, &html.writer, "", &.{ index, install, start, verify });
    try std.testing.expect(std.mem.find(u8, html.written(), "class=\"docs-group\"><summary>") == null);
    try std.testing.expect(std.mem.find(u8, html.written(), "aria-current=\"page\"") == null);
}

test "unclassified nested documents remain navigable with escaped titles and encoded URLs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const page = try parseDocument(allocator, "nested/new guide.md", "# Tips & \\<tools\\>\n");
    defer page.ast.deinit();
    var html: std.Io.Writer.Allocating = .init(allocator);
    try renderNavigation(allocator, &html.writer, page.source, &.{page});
    try std.testing.expect(std.mem.find(u8, html.written(), "class=\"docs-group\" open><summary>More documentation") != null);
    try std.testing.expect(std.mem.find(u8, html.written(), "href=\"/ghr/docs/nested/new%20guide.html\" aria-current=\"page\"") != null);
    try std.testing.expect(std.mem.find(u8, html.written(), ">Tips &amp; &lt;tools&gt;</a>") != null);
    html.clearRetainingCapacity();
    try renderNavigation(allocator, &html.writer, "", &.{page});
    try std.testing.expect(std.mem.find(u8, html.written(), "class=\"docs-group\" open><summary>More documentation") != null);
}
