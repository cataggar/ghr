const mer = @import("mer");
const h = mer.h;
const layout = @import("app/layout");

pub const prerender = true;

pub const meta: mer.Meta = .{
    .title = "Blog",
    .description = "Notes on building ghr — a toolkit for GitHub releases — and installable WebAssembly apps.",
};

const page_node = page();

pub fn render(req: mer.Request) mer.Response {
    return mer.render(req.allocator, page_node);
}

fn page() h.Node {
    return h.div(.{}, .{
        h.h1(.{ .style = "margin-bottom:32px;" }, "Blog"),
        h.section(.{}, .{
            h.div(.{ .class = "post-list " ++ layout.FeatureGrid.classes }, .{
                post("ghr-toolkit", "ghr: a toolkit for GitHub releases", "Why ghr exists, how installs are verified with GitHub's checksum, minisign, and sigstore, and what it looks like to install ghr with ghr itself.", "https://cataggar.medium.com/ghr-a-toolkit-for-github-releases-60bc489cf3aa"),
                post("installable-wasm-apps", "Installable WebAssembly apps", "Teaching ghr to install WASI 0.3 WebAssembly components straight from a GitHub release — a 3 KB app that runs unmodified on Windows, Linux, and macOS.", "https://cataggar.medium.com/installable-webassembly-apps-a9c44038a7d9"),
                post("wasi-petstore", "Installable WASI 0.3 Pet Store example", "A two-component WebAssembly example — a web component and a storage component talking over a component-model interface — installed with a single ghr command.", "https://cataggar.medium.com/installable-wasi-0-3-pet-store-example-beb0e04101a6"),
            }),
        }),
    });
}

fn post(slug: []const u8, title: []const u8, desc: []const u8, medium_url: []const u8) h.Node {
    return h.article(.{ .class = "post-card" }, .{
        h.h3(.{}, title),
        h.p(.{}, desc),
        h.div(.{ .style = "display:flex;gap:16px;margin-top:10px;" }, .{
            h.a(.{ .href = "/blog/" ++ slug, .class = "read-more" }, "Read on ghr.dev \u{2192}"),
            h.a(.{ .href = medium_url, .class = "read-more", .target = "_blank", .rel = "noopener" }, "Original on Medium \u{2197}"),
        }),
    });
}
