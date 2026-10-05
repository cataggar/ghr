const mer = @import("mer");
const h = mer.h;
const layout = @import("app/layout");

pub const prerender = true;

pub const meta: mer.Meta = .{
    .title = "ghr — a toolkit for GitHub releases",
    .description = "Install tools from GitHub releases with one cross-platform command. A single static binary that picks the right asset for your OS and architecture, and verifies it with minisign, sigstore, or checksums.",
};

const page_node = page();

pub fn render(req: mer.Request) mer.Response {
    return mer.render(req.allocator, page_node);
}

fn page() h.Node {
    return h.div(.{}, .{
        h.section(.{}, .{
            h.img(.{ .src = layout.logo_url, .alt = "ghr logo", .class = "hero-art" }),
            h.h1(.{}, "Install tools from GitHub releases with one command."),
            h.p(.{}, "ghr is a single static binary that picks the right release asset for your OS and architecture, then verifies it with minisign, sigstore, or a plain checksum — on Mac, Linux, and Windows, and in GitHub Actions."),
            h.div(.{ .class = "page-actions" }, .{
                h.a(.{ .href = layout.docs_url, .class = "btn btn-primary" }, "Get started"),
                h.a(.{ .href = layout.docs_url, .class = "btn btn-secondary" }, "Docs"),
                h.a(.{ .href = "https://github.com/cataggar/ghr", .class = "btn btn-secondary" }, "View on GitHub"),
            }),
        }),

        h.section(.{}, .{
            h.h2(.{}, "What it does"),
            h.ul(.{}, .{
                feature("Cross-platform installs", "ghr picks the right archive for your OS and CPU architecture automatically — one command works on macOS, Linux, and Windows."),
                feature("Verified, not just downloaded", "Every install can check GitHub's own SHA-256, a minisign signature, and a sigstore bundle before anything is extracted."),
                feature("Built for GitHub Actions", "actions/install and actions/download install several tools in one cached step, sharing an HTTP client and auth token."),
                feature("Install ghr with ghr", "ghr can install itself from its own releases — the same verification path every other tool gets."),
                feature("No key files on disk", "ghr minisign sign reads its signing key from the environment, so a release job is a single step."),
                feature("Fork and self-host", "Mirroring or re-publishing a project's releases is a normal GitHub fork — no separate registry to run."),
            }),
        }),
    });
}

fn feature(title: []const u8, desc: []const u8) h.Node {
    return h.li(.{}, .{
        h.strong(.{}, title),
        h.text(": "),
        h.text(desc),
    });
}
