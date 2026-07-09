const mer = @import("mer");
const h = mer.h;

pub const prerender = true;

pub const meta: mer.Meta = .{
    .title = "Installable WebAssembly apps",
    .description = "Teaching ghr to install WASI 0.3 WebAssembly components straight from a GitHub release.",
};

const page_node = page();

pub fn render(req: mer.Request) mer.Response {
    return mer.render(req.allocator, page_node);
}

fn page() h.Node {
    return h.article(.{ .class = "prose" }, .{
        h.a(.{ .href = "/blog", .class = "back-link" }, "\u{2190} Back to blog"),
        h.h1(.{}, "Installable WebAssembly apps"),
        h.p(.{ .style = "color:var(--muted);" }, .{
            h.text("Originally published on "),
            h.a(.{ .href = "https://cataggar.medium.com/installable-webassembly-apps-a9c44038a7d9", .target = "_blank", .rel = "noopener" }, "Medium"),
            h.text("."),
        }),

        h.p(.{}, "I updated ghr to be able to install WebAssembly apps. I created a GitHub release for the \"hello\" app — a WebAssembly binary built using a WASI 0.3 CLI, so it requires Wasmtime 46 or newer. It works cross-platform: I tested it on Windows, Linux, and Mac."),

        h.p(.{}, "The release page has only three assets. The app itself is about 3 KB. A .wasm.ghr sidecar file names the WebAssembly runtime and its runtime args, and a .minisig sidecar lets anyone verify that I published it."),

        h.pre(.{}, .{h.code(.{}, "ghr install cataggar/wabt/hello@hello-2.0.0")}),

        h.p(.{}, "That's the whole install experience: one command resolves the release, downloads a 3 KB component instead of a platform-specific binary for every OS/arch combination, verifies it, and wires up a runnable command backed by Wasmtime."),

        h.h2(.{}, "Why this matters"),
        h.p(.{}, "A single WebAssembly component can replace a matrix of native binaries — no more publishing separate linux-x64, linux-arm64, macos-arm64, macos-x64, windows-x64, and windows-arm64 archives for a CLI tool that doesn't need direct OS access. The .wasm.ghr sidecar tells ghr which WASI runtime to invoke and with what arguments, so `ghr install` can make a 3 KB component feel like any other installed command."),

        h.blockquote(.{}, "See it in action: github.com/cataggar/wabt/releases/tag/hello-2.0.0"),
    });
}
