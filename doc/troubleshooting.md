# Name resolution on Linux

On Linux ghr resolves host names through the Zig standard library, which reads `/etc/resolv.conf` with a 512-byte line buffer and a 255-byte `search` list. WSL regenerates `/etc/resolv.conf` on every boot from the Windows host's DNS settings, and on a corporate network the generated `search` line lists every advertised suffix — often more than a kilobyte. That overruns both limits, and older versions of ghr failed before opening a socket:

```
resolving cataggar/ghr ...
error: failed to fetch release: error.ResolvConfParseFailed
```

ghr now carries its own resolv.conf parser and DNS client for exactly this case. The standard resolver stays in charge — IP literals, `/etc/hosts` and `localhost` continue to resolve the way they always did, and `/etc/hosts` still wins over DNS. ghr only takes over the DNS query itself, and only once the standard resolver has reported that it cannot read the file. Lines may be any length; a `search` list too long to keep in full is truncated at a domain boundary rather than mid-suffix. This is a workaround for [ziglang/zig#35371](https://codeberg.org/ziglang/zig/issues/35371) and will be dropped once ghr builds against a Zig release that carries the fix.

Nothing needs configuring. If you would rather shorten the list at the source, disable WSL's generated file by adding this to `/etc/wsl.conf` and writing your own `/etc/resolv.conf`:

```ini
[network]
generateResolvConf = false
```
