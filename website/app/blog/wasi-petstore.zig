const mer = @import("mer");
const h = mer.h;
const layout = @import("app/layout");

pub const prerender = true;

pub const meta: mer.Meta = .{
    .title = "Installable WASI 0.3 Pet Store example",
    .description = "A two-component WebAssembly example, installed with a single ghr command.",
};

const page_node = page();

pub fn render(req: mer.Request) mer.Response {
    return mer.render(req.allocator, page_node);
}

fn page() h.Node {
    return h.article(.{ .class = "prose" }, .{
        h.a(.{ .href = layout.base_path ++ "/blog", .class = "back-link" }, "\u{2190} Back to blog"),
        h.h1(.{}, "Installable WASI 0.3 Pet Store example"),
        h.p(.{ .style = "color:var(--muted);" }, .{
            h.text("Originally published on "),
            h.a(.{ .href = "https://cataggar.medium.com/installable-wasi-0-3-pet-store-example-beb0e04101a6", .target = "_blank", .rel = "noopener" }, "Medium"),
            h.text("."),
        }),

        h.p(.{}, .{
            h.text("New ghr logo by "),
            h.a(.{ .href = "https://www.instagram.com/my_artistic_sidetrip/", .target = "_blank", .rel = "noopener" }, "Talia Blasquez"),
            h.text("."),
        }),

        h.p(.{}, "I published a petstore-serve.wasm and a petstore-test.wasm — WASI 0.3 examples that install with a single ghr command:"),
        h.pre(.{}, .{h.code(.{}, "ghr install cataggar/wabt/petstore-serve@petstore-0.1.0\nghr install cataggar/wabt/petstore-test@petstore-0.1.0")}),

        h.p(.{}, "petstore-serve starts a web service, and petstore-test makes a series of HTTP calls to exercise its endpoints. Internally, the web service is composed of two WebAssembly components: a web component and a storage component. The storage component implements a store interface that the web component consumes — for this example, an in-memory storage implementation was used."),

        h.p(.{}, "I implemented the service in Zig, but the implementation details deserve their own post. There are several ways to build on this example — you could write a different implementation of the store interface, in Zig or in any other language with WebAssembly component-model support, and swap it in without touching the web component at all."),

        h.blockquote(.{}, "Current release: github.com/cataggar/wabt/releases/tag/petstore-0.1.0"),
        h.blockquote(.{}, "Example source: github.com/cataggar/wabt/tree/example/petstore"),
    });
}
