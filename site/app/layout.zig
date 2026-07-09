// app/layout.zig — shared page chrome for the ghr site.
//
// Palette and typography mirror merlionjs.com (https://merlionjs.com/), the
// framework's own site, which this project is built with. Layout mirrors
// its warm paper background + brand red accent + DM Serif Display/DM Sans
// pairing. Structural spacing (`FeatureGrid`) and the small version pill
// (`Badge`) are generated with `mer.mercss` — merjs's built-in, Tailwind v4
// inspired, comptime utility CSS engine — the same CSS system that powers
// the mercss features on merlionjs.com.

const std = @import("std");
const mer = @import("mer");
const mercss = mer.mercss;

pub const logo_url = "https://github.com/cataggar/ghr/releases/download/v0.6.2/ghr-logo.jpg";

/// Small rounded pill, e.g. the "MIT licensed" / version badges.
pub const Badge = mercss.Component(.{
    .display = "inline-flex",
    .align_items = "center",
    .padding = "4px 10px",
    .border_radius = "999px",
    .font_size = "12px",
    .font_weight = "700",
    .letter_spacing = "0.04em",
});

/// Mobile-first responsive gap for the feature/blog card grids.
pub const FeatureGrid = mercss.ResponsiveComponent(.{
    .base = .{ .gap = "16px" },
    .md = .{ .gap = "24px" },
});

/// Framework primitive — automatically wraps all HTML page responses.
pub fn wrap(allocator: std.mem.Allocator, path: []const u8, body: []const u8, meta: mer.Meta) []const u8 {
    const title = if (meta.title.len > 0) meta.title else "ghr";
    const desc = if (meta.description.len > 0) meta.description else "A toolkit for GitHub releases.";

    var buf: std.Io.Writer.Allocating = .init(allocator);
    const w = &buf.writer;

    w.writeAll(
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\  <meta charset="UTF-8">
        \\  <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\  <link rel="preconnect" href="https://fonts.googleapis.com">
        \\  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        \\  <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
        \\  <link rel="icon" href="/favicon.ico" sizes="any">
        \\  <link rel="icon" href="/favicon-32x32.png" type="image/png" sizes="32x32">
        \\
    ) catch return body;

    w.print("  <title>{s} \u{2014} ghr</title>\n", .{title}) catch return body;
    w.print("  <meta name=\"description\" content=\"{s}\">\n", .{desc}) catch return body;
    w.print("  <meta property=\"og:title\" content=\"{s}\">\n", .{title}) catch return body;
    w.print("  <meta property=\"og:description\" content=\"{s}\">\n", .{desc}) catch return body;
    w.writeAll("  <meta property=\"og:type\" content=\"website\">\n") catch return body;

    w.writeAll(
        \\  <style>
        \\    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        \\    :root {
        \\      --bg:#f0ebe3; --bg2:#e8e2d9; --bg3:#ddd5cc;
        \\      --text:#252530; --muted:#8a7f78; --border:#d5cdc4;
        \\      --red:#e8251f; --red-dark:#aa1915; --paper:#fffdfa;
        \\    }
        \\    body { background:var(--bg); color:var(--text); font-family:'DM Sans',system-ui,-apple-system,sans-serif; min-height:100vh; line-height:1.65; }
        \\    a { color:inherit; text-decoration:none; }
        \\    code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
        \\    code { font-size:0.9em; background:var(--bg2); border-radius:4px; padding:2px 6px; }
        \\    pre { background:#201014; color:#ffe8e7; border-radius:10px; padding:18px 20px; overflow-x:auto; font-size:13px; line-height:1.6; }
        \\    pre code { background:none; padding:0; color:inherit; }
        \\    h1, h2, h3 { font-family:'DM Serif Display',Georgia,serif; letter-spacing:-0.02em; }
        \\    .layout { max-width:880px; margin:0 auto; padding:48px 32px 96px; }
        \\    .layout-wide { max-width:1080px; }
        \\    .layout-header { display:flex; flex-direction:column; align-items:center; text-align:center; margin-bottom:48px; gap:18px; }
        \\    .site-logo-link { display:block; width:100%; }
        \\    .site-logo { display:block; width:100%; height:auto; border-radius:16px; box-shadow:0 16px 40px rgba(37,37,48,0.18); }
        \\    .nav { display:flex; gap:20px; flex-wrap:wrap; justify-content:center; }
        \\    .nav a { font-size:13px; color:var(--muted); transition:color 0.15s; }
        \\    .nav a:hover { color:var(--text); }
        \\    .hero { background:linear-gradient(145deg,#2f1214 0%,#7a1715 45%,#e8251f 100%); color:#fff8f7; border-radius:14px; padding:40px; margin-bottom:40px; box-shadow:0 20px 50px rgba(111,19,18,0.18); }
        \\    .hero h1 { font-size:clamp(32px,5vw,48px); line-height:1.05; margin-bottom:14px; }
        \\    .hero p { max-width:60ch; color:#ffe8e7; font-size:17px; margin-bottom:22px; }
        \\    .hero-actions { display:flex; gap:12px; flex-wrap:wrap; }
        \\    .btn { display:inline-flex; align-items:center; font-size:14px; font-weight:700; padding:11px 20px; border-radius:8px; transition:transform 0.15s ease, opacity 0.15s ease; }
        \\    .btn:hover { transform:translateY(-1px); }
        \\    .btn-primary { background:#fff; color:var(--red-dark); }
        \\    .btn-secondary { background:rgba(255,255,255,0.14); color:#fff; border:1px solid rgba(255,255,255,0.2); }
        \\    .btn-ghost { background:transparent; color:var(--text); border:1px solid var(--border); }
        \\    .btn-ghost:hover { border-color:var(--text); }
        \\    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); }
        \\    .card { background:var(--paper); border:1px solid var(--border); border-radius:12px; padding:22px; }
        \\    .card h3 { font-size:16px; margin-bottom:8px; }
        \\    .card p { font-size:14px; color:var(--muted); }
        \\    .section-title { font-size:14px; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; color:var(--muted); margin-bottom:16px; }
        \\    section + section { margin-top:48px; }
        \\    .post-list { display:flex; flex-direction:column; gap:16px; }
        \\    .post-card { background:var(--paper); border:1px solid var(--border); border-radius:12px; padding:22px 24px; }
        \\    .post-card h3 { font-size:18px; margin-bottom:6px; }
        \\    .post-card p { color:var(--muted); font-size:14px; }
        \\    .post-card .read-more { display:inline-block; margin-top:10px; font-size:13px; font-weight:700; color:var(--red); }
        \\    .prose h2 { font-size:24px; margin:32px 0 14px; }
        \\    .prose h3 { font-size:19px; margin:24px 0 10px; }
        \\    .prose p { margin-bottom:16px; }
        \\    .prose ul, .prose ol { margin:0 0 16px 24px; }
        \\    .prose li { margin-bottom:6px; }
        \\    .prose blockquote { border-left:3px solid var(--red); padding-left:16px; color:var(--muted); margin:0 0 16px; }
        \\    .back-link { display:inline-block; margin-bottom:24px; font-size:13px; color:var(--muted); }
        \\    .back-link:hover { color:var(--text); }
        \\    .attribution { margin-top:12px; font-size:12px; color:var(--muted); }
        \\    .layout-footer { margin-top:64px; padding-top:24px; border-top:1px solid var(--border); font-size:12px; color:var(--muted); text-align:center; }
        \\    .layout-footer a { text-decoration:underline; text-underline-offset:2px; }
        \\
    ) catch return body;

    // mercss-generated utility CSS (comptime, atomic — see mercss.zig).
    w.writeAll(Badge.css) catch return body;
    w.writeAll(FeatureGrid.css) catch return body;

    w.writeAll(
        \\    .badge-red { background:var(--red); color:#fff; }
        \\    .badge-outline { border:1px solid var(--border); color:var(--muted); }
        \\  </style>
        \\
    ) catch return body;

    if (meta.extra_head) |extra| {
        w.writeAll(extra) catch {};
        w.writeAll("\n") catch {};
    }

    w.writeAll("</head>\n<body>\n<div class=\"layout\">\n  <header class=\"layout-header\">\n") catch return body;
    w.print(
        \\    <nav class="nav">
        \\      <a href="/blog">Blog</a>
        \\      <a href="https://github.com/cataggar/ghr">GitHub</a>
        \\      <a href="https://github.com/cataggar/ghr#install">Install</a>
        \\    </nav>
        \\    <a href="/" class="site-logo-link"><img src="{s}" alt="ghr logo" class="site-logo"></a>
        \\
    , .{logo_url}) catch return body;
    w.writeAll("  </header>\n") catch return body;

    _ = path;
    w.writeAll(body) catch return body;

    w.writeAll(
        \\
        \\  <footer class="layout-footer">
        \\    Built with <a href="https://merlionjs.com/">merjs</a> &middot; Zig 0.16 &middot;
        \\    <a href="https://github.com/cataggar/ghr">github.com/cataggar/ghr</a><br>
        \\    <span class="attribution">Logo by
        \\      <a href="https://www.instagram.com/my_artistic_sidetrip/">Talia Blasquez</a>,
        \\      licensed <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>.
        \\    </span>
        \\  </footer>
        \\</div>
        \\</body>
        \\</html>
    ) catch return body;

    return buf.written();
}
