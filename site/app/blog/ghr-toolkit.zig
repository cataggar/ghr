const mer = @import("mer");
const h = mer.h;

pub const prerender = true;

pub const meta: mer.Meta = .{
    .title = "ghr: a toolkit for GitHub releases",
    .description = "Why ghr exists, how installs are verified with GitHub's checksum, minisign, and sigstore, and what it looks like to install ghr with ghr itself.",
};

const page_node = page();

pub fn render(req: mer.Request) mer.Response {
    return mer.render(req.allocator, page_node);
}

fn page() h.Node {
    return h.article(.{ .class = "prose" }, .{
        h.a(.{ .href = "/blog", .class = "back-link" }, "\u{2190} Back to blog"),
        h.h1(.{}, "ghr: a toolkit for GitHub releases"),
        h.p(.{ .style = "color:var(--muted);" }, .{
            h.text("Originally published on "),
            h.a(.{ .href = "https://cataggar.medium.com/ghr-a-toolkit-for-github-releases-60bc489cf3aa", .target = "_blank", .rel = "noopener" }, "Medium"),
            h.text("."),
        }),

        h.p(.{}, "Installing binaries from the internet can be dangerous. Piping curl straight into a shell isn't something I enjoy doing — but it's convenient, so if you trust the repo, here's one way ghr can be installed on Mac or Linux:"),
        h.pre(.{}, .{h.code(.{}, "curl -fsSL https://raw.githubusercontent.com/cataggar/ghr/main/install.sh | sh")}),
        h.p(.{}, "or on Windows:"),
        h.pre(.{}, .{h.code(.{}, "iwr -useb https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1 | iex")}),

        h.p(.{}, "I trust package managers more, so if you have Homebrew installed on Mac or Linux:"),
        h.pre(.{}, .{h.code(.{}, "brew install cataggar/ghr/ghr")}),
        h.p(.{}, "or using winget on Windows:"),
        h.pre(.{}, .{h.code(.{}, "winget install ghr")}),

        h.p(.{}, "Every language ecosystem now has a way to install tools. Python tools provide a nice way to install native tools across platforms:"),
        h.pre(.{}, .{h.code(.{}, "pipx install ghr-bin\nuv tool install ghr-bin")}),
        h.p(.{}, "Both pipx and uv install binaries into ~/.local/bin. ghr does the same, but the binaries come from GitHub Releases."),

        h.h2(.{}, "Installing anything from a release"),
        h.p(.{}, "Once ghr is installed, it can install self-contained executables directly from their releases:"),
        h.pre(.{}, .{h.code(.{}, "ghr install astral-sh/uv\nghr install bytecodealliance/wasmtime\nghr install casey/just\nghr install nushell/nushell\nghr install burntsushi/ripgrep")}),

        h.h2(.{}, "Installing ghr with ghr"),
        h.p(.{}, "It's possible to install ghr with ghr itself — and it's the best example of what verifications are possible:"),
        h.pre(.{}, .{h.code(.{},
            \\$ ghr install cataggar/ghr@v0.5.2 RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0
            \\resolving cataggar/ghr@v0.5.2 ...
            \\found release v0.5.2
            \\downloading ghr-0.5.2-linux-musl-arm64.tar.gz ...
            \\downloaded 0.7 MB
            \\verified github sha256 b5fd69633ce4... (release asset digest)
            \\verified minisign: key 9bb2e9a96876fe37 (timestamp:2026-06-11T20:45:29Z file:ghr-0.5.2-linux-musl-arm64.tar.gz commit:c58accaaa736724f0fe83023587b11aff02f7eb8 tag:v0.5.2)
            \\verified sigstore: sha256 b5fd69633ce4... (rekor t=2026-06-11T20:44:54Z, log 1793360650) identity:
            \\https://github.com/cataggar/ghr/.github/workflows/release.yml@refs/tags/v0.5.2 issuer: https://token.actions.githubusercontent.com inclusion: tree size 1671456430 + checkpoint
            \\extracting ...
            \\linking executables: linked ghr
            \\installed cataggar/ghr@v0.5.2
        )}),
        h.p(.{}, "GitHub's own SHA-256 is verified, the minisign signature is verified, and the sigstore bundle is verified. The minisign public key is the string that comes right after the version above — required by default whenever a release has .minisig sidecars."),

        h.h2(.{}, "Verifying the author, not just the bytes"),
        h.p(.{}, "One great thing about minisign is that it lets you verify the author. I mirror some Zig releases that I use — you can check the signature on Zig's own download page to confirm a mirrored build is genuinely theirs:"),
        h.pre(.{}, .{h.code(.{}, "ghr install cataggar/zig@v0.16.0 RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U")}),

        h.p(.{}, "I think forking and hosting your own releases is going to become more common for open source software in the age of AI. ghr is a tool that makes that easier — and yes, you can fork it too."),

        h.blockquote(.{}, "See the full command reference and verification details in the README: github.com/cataggar/ghr"),
    });
}
