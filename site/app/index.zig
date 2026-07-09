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
        h.section(.{ .class = "hero" }, .{
            h.span(.{ .class = layout.Badge.classes ++ " badge-outline", .style = "background:rgba(255,255,255,0.14);color:#ffe5e4;border-color:rgba(255,255,255,0.2);margin-bottom:14px;" }, "TOOLKIT FOR GITHUB RELEASES"),
            h.h1(.{}, "Install tools from GitHub releases with one command."),
            h.p(.{}, "ghr is a single static binary that picks the right release asset for your OS and architecture, then verifies it with minisign, sigstore, or a plain checksum — on Mac, Linux, and Windows, and in GitHub Actions."),
            h.div(.{ .class = "hero-actions" }, .{
                h.a(.{ .href = "https://github.com/cataggar/ghr", .class = "btn btn-primary" }, "View on GitHub"),
                h.a(.{ .href = "https://github.com/cataggar/ghr#install", .class = "btn btn-secondary" }, "Install ghr"),
                h.a(.{ .href = "/blog", .class = "btn btn-secondary" }, "Read the blog"),
            }),
        }),

        h.section(.{}, .{
            h.div(.{ .class = "section-title" }, "Quick install"),
            h.pre(.{}, .{h.code(.{}, "curl -fsSL https://raw.githubusercontent.com/cataggar/ghr/main/install.sh | sh")}),
            h.pre(.{}, .{h.code(.{}, "iwr -useb https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1 | iex")}),
            h.pre(.{}, .{h.code(.{}, "brew install cataggar/ghr/ghr   # or: winget install ghr")}),
            h.pre(.{}, .{h.code(.{}, "pipx install ghr-bin             # or: uv tool install ghr-bin")}),
        }),

        h.section(.{}, .{
            h.div(.{ .class = "section-title" }, "What it does"),
            h.div(.{ .class = "grid " ++ layout.FeatureGrid.classes }, .{
                feature("Cross-platform installs", "ghr picks the right archive for your OS and CPU architecture automatically — one command works on macOS, Linux, and Windows."),
                feature("Verified, not just downloaded", "Every install can check GitHub's own SHA-256, a minisign signature, and a sigstore bundle before anything is extracted."),
                feature("Built for GitHub Actions", "actions/install and actions/download install several tools in one cached step, sharing an HTTP client and auth token."),
                feature("Install ghr with ghr", "ghr can install itself from its own releases — the same verification path every other tool gets."),
                feature("No key files on disk", "ghr minisign sign reads its secret key and password from the environment, so a release job is a single step."),
                feature("Fork and self-host", "Mirroring or re-publishing a project's releases is a normal GitHub fork — no separate registry to run."),
            }),
        }),

        h.section(.{}, .{
            h.div(.{ .class = "section-title" }, "From the blog"),
            h.div(.{ .class = "post-list" }, .{
                postCard("blog/ghr-toolkit", "ghr: a toolkit for GitHub releases", "Why ghr exists, how installs are verified with GitHub's checksum, minisign, and sigstore, and what it looks like to install ghr with ghr itself."),
                postCard("blog/installable-wasm-apps", "Installable WebAssembly apps", "Teaching ghr to install WASI 0.3 WebAssembly components straight from a GitHub release — a 3 KB app that runs unmodified on Windows, Linux, and macOS."),
                postCard("blog/wasi-petstore", "Installable WASI 0.3 Pet Store example", "A two-component WebAssembly example — a web component and a storage component talking over a component-model interface — installed with a single ghr command."),
            }),
        }),
    });
}

fn feature(title: []const u8, desc: []const u8) h.Node {
    return h.div(.{ .class = "card" }, .{
        h.h3(.{}, title),
        h.p(.{}, desc),
    });
}

fn postCard(href: []const u8, title: []const u8, desc: []const u8) h.Node {
    return h.article(.{ .class = "post-card" }, .{
        h.h3(.{}, title),
        h.p(.{}, desc),
        h.a(.{ .href = "/" ++ href, .class = "read-more" }, "Read more \u{2192}"),
    });
}
