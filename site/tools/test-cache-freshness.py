#!/usr/bin/env python3
"""Exercise production builds without clearing Zig's configuration cache."""

from pathlib import Path
import shutil
import subprocess


SITE = Path(__file__).resolve().parents[1]
PROJECT = SITE / ".tmp-cache-freshness"
PAGE = """const mer = @import("mer");
pub const prerender = true;
pub const meta: mer.Meta = .{ .title = "Cache fixture" };
pub fn render(_: mer.Request) mer.Response {
    return mer.html("cache-route-marker");
}
"""
LAYOUT = """const std = @import("std");
const mer = @import("mer");
pub fn wrap(alloc: std.mem.Allocator, path: []const u8, body: []const u8, meta: mer.Meta) []const u8 {
    _ = path;
    _ = meta;
    return std.fmt.allocPrint(alloc, "cache-layout-marker:{s}", .{body}) catch body;
}
"""


def build():
    result = subprocess.run(
        ["zig", "build", "prod"], cwd=PROJECT, capture_output=True, text=True
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return (PROJECT / "src/generated/routes.zig").read_text()


def write(path, contents):
    file = PROJECT / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(contents)


def check_page(path):
    assert "cache-route-marker" in (PROJECT / "dist" / path).read_text()


def main():
    # Never overwrite an existing directory, including leftovers from another run.
    PROJECT.mkdir()
    try:
        for file in ("build.zig", "build.zig.zon"):
            shutil.copy2(SITE / file, PROJECT / file)
        for directory in ("src", "tools", "public"):
            shutil.copytree(SITE / directory, PROJECT / directory)
        (PROJECT / "src/generated/routes.zig").unlink(missing_ok=True)
        write("app/index.zig", PAGE)
        build()
        build()  # Warm the cache after output/cache directories have been created.
        check_page("index.html")

        write("app/nested/deep/page.zig", PAGE)
        assert '@import("app/nested/deep/page")' in build()
        check_page("nested/deep/page.html")

        (PROJECT / "app/nested/deep/page.zig").rename(
            PROJECT / "app/nested/deep/renamed.zig"
        )
        routes = build()
        assert '@import("app/nested/deep/renamed")' in routes
        assert '@import("app/nested/deep/page")' not in routes
        check_page("nested/deep/renamed.html")

        (PROJECT / "app/nested").rename(PROJECT / "app/moved")
        routes = build()
        assert '@import("app/moved/deep/renamed")' in routes
        assert "app/nested/" not in routes
        check_page("moved/deep/renamed.html")

        (PROJECT / "app/moved/deep/renamed.zig").unlink()
        assert "app/moved/deep/renamed" not in build()
        shutil.rmtree(PROJECT / "app/moved")
        assert "app/moved/" not in build()

        write("app/layout.zig", LAYOUT)
        assert 'pub const layout = app_layout.wrap;' in build()
        assert "cache-layout-marker" in (PROJECT / "dist/index.html").read_text()
        (PROJECT / "app/layout.zig").unlink()
        assert "app_layout" not in build()
        assert "cache-layout-marker" not in (PROJECT / "dist/index.html").read_text()

        # api/ starts absent; its presence is a configuration input too.
        write("api/v1/ping.zig", PAGE)
        assert '@import("api/v1/ping")' in build()
        check_page("api/v1/ping.html")
        shutil.rmtree(PROJECT / "api")
        assert "api/v1/ping" not in build()

        # Exercise missing app/ as well as recreating it with a different route.
        shutil.rmtree(PROJECT / "app")
        assert 'const app_' not in build()
        write("app/recreated.zig", PAGE)
        assert '@import("app/recreated")' in build()
        check_page("recreated.html")
        print("Configuration cache freshness: add/rename/delete, nested directories, "
              "optional layout and app/api presence passed")
    finally:
        shutil.rmtree(PROJECT)


if __name__ == "__main__":
    main()
