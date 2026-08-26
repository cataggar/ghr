//! Host name resolution fallback for machines whose `/etc/resolv.conf` the
//! Zig standard library refuses to parse.
//!
//! Zig 0.16's `std.Io.net.HostName.ResolvConf.init` reads the file through a
//! 512-byte line buffer and copies the entire `search`/`domain` list into a
//! 255-byte buffer. WSL regenerates `/etc/resolv.conf` on every boot with a
//! `search` line naming every DNS suffix the host network advertises; on a
//! corporate network that line routinely runs past a kilobyte. The line
//! exceeds the reader buffer, `ResolvConf.init` fails, and every lookup
//! returns `error.ResolvConfParseFailed` before a socket is ever opened:
//!
//!     resolving cataggar/ghr ...
//!     error: failed to fetch release: error.ResolvConfParseFailed
//!
//! `wrap` returns an `Io` that keeps the standard resolver in charge and only
//! steps in once it has given up, re-running the DNS half of the lookup
//! against a resolv.conf parser that tolerates lines of any length.
//!
//! The fallback is Linux-only because Linux is the only target where the
//! standard library resolves names through `/etc/resolv.conf`; Windows uses
//! `DnsQueryEx` and the BSDs go through libc.

const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;
const net = Io.net;
const HostName = net.HostName;
const IpAddress = net.IpAddress;

/// Whether the standard resolver on this target reads `/etc/resolv.conf`.
pub const enabled = builtin.os.tag == .linux;

/// resolv.conf(5) caps the nameserver list at three entries.
const max_nameservers = 3;

/// How much of the `search` list to keep. Long enough for the suffix lists
/// WSL inherits from a corporate DNS server, which is the case that defeats
/// the standard library's 255-byte buffer in the first place.
const max_search = 4096;

/// `/etc/resolv.conf` is a small text file; anything past this is ignored.
const max_resolv_conf_bytes = 16 * 1024;

/// Largest DNS query this module writes: header, name, type and class.
const max_query_len = 12 + 1 + 253 + 1 + 4;

/// A DNS reply over UDP is capped at 512 bytes; this module advertises no
/// EDNS0 buffer, so a server must truncate rather than exceed it.
const max_reply_len = 512;

/// One query per record type, sent to every nameserver.
const max_messages = 2 * max_nameservers;

/// Capacity of the private queue the fallback lends to the standard resolver.
/// The resolver runs concurrently with the drain below, so this only decides
/// how far ahead of the drain it may get, not whether it can finish.
const private_queue_len = 64;

/// Results held back while the standard resolver is still running. Its
/// `/etc/hosts` step queues a canonical name before deciding it found no
/// usable address, then lets the lookup fall through to `/etc/resolv.conf`;
/// that name has to be dropped if the fallback takes over, or the caller
/// would end up with two of them.
const stash_len = 2;

const dns_port = 53;

/// Copied from the wrapped `Io` so the fallback can call through to the
/// standard resolver and hand out an `Io` of its own. Written once by `wrap`
/// before any lookup can run.
var fallback_vtable: Io.VTable = undefined;
var std_net_lookup: @FieldType(Io.VTable, "netLookup") = undefined;

/// Returns an `Io` that resolves host names even when `/etc/resolv.conf`
/// defeats the standard library's parser. Call once, before any networking.
pub fn wrap(io: Io) Io {
    if (!enabled) return io;
    fallback_vtable = io.vtable.*;
    std_net_lookup = io.vtable.netLookup;
    fallback_vtable.netLookup = netLookup;
    return .{ .userdata = io.userdata, .vtable = &fallback_vtable };
}

/// Runs the standard resolver against a private queue so that its
/// `defer resolved.close(io)` cannot shut the caller's queue before the
/// fallback gets a turn. `lookupDnsSearch` gives up while parsing
/// `/etc/resolv.conf`, before it queues any address, so retrying the lookup
/// from scratch cannot duplicate one.
fn netLookup(
    userdata: ?*anyopaque,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) HostName.LookupError!void {
    const io: Io = .{ .userdata = userdata, .vtable = &fallback_vtable };

    var private_buffer: [private_queue_len]HostName.LookupResult = undefined;
    var private: Io.Queue(HostName.LookupResult) = .init(&private_buffer);

    // The resolver has to run alongside the drain rather than ahead of it: it
    // fills whatever queue it is given from an `/etc/hosts` of unbounded size,
    // so lending it a bounded one and draining afterwards would wedge both
    // sides. Where there is no second unit of concurrency to be had, give it
    // the caller's queue and accept stock behaviour -- including the very
    // error this module exists to avoid -- in preference to a hang.
    var future = io.concurrent(callStdNetLookup, .{ userdata, host_name, &private, options }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return std_net_lookup(userdata, host_name, resolved, options),
    };
    // Registered below the branch above, which leaves the close to the
    // standard resolver.
    defer resolved.close(io);

    var stash: [stash_len]HostName.LookupResult = undefined;
    var stashed: usize = 0;
    var drain_failure: ?Io.Cancelable = null;

    // Keep taking results even after a failed hand-off, so the resolver always
    // reaches its own `close` and `await` below cannot block forever.
    while (private.getOneUncancelable(io)) |result| {
        if (drain_failure != null) continue;
        switch (result) {
            .canonical_name => {
                // A second canonical name proves the resolver is already past
                // `/etc/resolv.conf`, so the one before it can be released.
                if (stashed == stash.len) {
                    put(io, resolved, stash[0]) catch |e| {
                        drain_failure = e;
                        continue;
                    };
                    std.mem.copyForwards(HostName.LookupResult, stash[0 .. stash.len - 1], stash[1..]);
                    stashed -= 1;
                }
                stash[stashed] = result;
                stashed += 1;
            },
            // Addresses only reach the queue on paths that go on to succeed,
            // so handing them over right away cannot race the fallback.
            .address => put(io, resolved, result) catch |e| {
                drain_failure = e;
            },
        }
    } else |err| switch (err) {
        error.Closed => {},
    }

    const lookup_result = future.await(io);
    if (drain_failure) |e| return e;
    lookup_result catch |err| switch (err) {
        error.ResolvConfParseFailed => return lookupDns(io, host_name, resolved, options),
        else => |e| return e,
    };
    for (stash[0..stashed]) |result| try put(io, resolved, result);
}

/// `io.concurrent` needs a function, not the function pointer saved by `wrap`.
fn callStdNetLookup(
    userdata: ?*anyopaque,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) HostName.LookupError!void {
    return std_net_lookup(userdata, host_name, resolved, options);
}

fn put(io: Io, queue: *Io.Queue(HostName.LookupResult), result: HostName.LookupResult) Io.Cancelable!void {
    queue.putOne(io, result) catch |err| switch (err) {
        // `HostName.lookup` asserts the caller leaves `resolved` open.
        error.Closed => unreachable,
        error.Canceled => |e| return e,
    };
}

// --- resolv.conf ---

const ResolvConf = struct {
    nameservers_buffer: [max_nameservers]IpAddress = undefined,
    nameservers_len: usize = 0,
    search_buffer: [max_search]u8 = undefined,
    search_len: usize = 0,
    ndots: u32 = 1,
    timeout_seconds: u32 = 5,
    attempts: u32 = 2,

    fn nameservers(rc: *const ResolvConf) []const IpAddress {
        return rc.nameservers_buffer[0..rc.nameservers_len];
    }

    fn search(rc: *const ResolvConf) []const u8 {
        return rc.search_buffer[0..rc.search_len];
    }

    /// Parses resolv.conf(5) syntax. Unlike the standard library's parser this
    /// imposes no limit on line length, keeps as much of an over-long `search`
    /// list as fits without splitting a domain, and skips entries it cannot
    /// make sense of instead of failing the whole lookup.
    fn parse(io: Io, bytes: []const u8) Io.Cancelable!ResolvConf {
        var rc: ResolvConf = .{};
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |raw_line| {
            var tokens = std.mem.tokenizeAny(u8, stripComment(raw_line), " \t\r");
            const directive = tokens.next() orelse continue;
            if (std.mem.eql(u8, directive, "nameserver")) {
                if (rc.nameservers_len == max_nameservers) continue;
                const text = tokens.next() orelse continue;
                // `resolve` rather than `parse` so a link-local nameserver
                // keeps the interface its scope names, as in `fe80::1%eth0`.
                rc.nameservers_buffer[rc.nameservers_len] = IpAddress.resolve(io, text, dns_port) catch |err| switch (err) {
                    error.Canceled => |e| return e,
                    else => continue,
                };
                rc.nameservers_len += 1;
            } else if (std.mem.eql(u8, directive, "search") or std.mem.eql(u8, directive, "domain")) {
                rc.search_len = copySearchList(&rc.search_buffer, tokens.rest());
            } else if (std.mem.eql(u8, directive, "options")) {
                while (tokens.next()) |option| {
                    var parts = std.mem.splitScalar(u8, option, ':');
                    const name = parts.first();
                    const value_text = parts.next() orelse continue;
                    const value = std.fmt.parseInt(u8, value_text, 10) catch |err| switch (err) {
                        error.Overflow => 255,
                        error.InvalidCharacter => continue,
                    };
                    if (std.mem.eql(u8, name, "ndots")) {
                        rc.ndots = @min(value, 15);
                    } else if (std.mem.eql(u8, name, "attempts")) {
                        // Clamped away from zero: `attempts` divides the timeout.
                        rc.attempts = std.math.clamp(value, 1, 10);
                    } else if (std.mem.eql(u8, name, "timeout")) {
                        rc.timeout_seconds = std.math.clamp(value, 1, 60);
                    }
                }
            }
        }
        return rc;
    }
};

/// resolv.conf(5) treats both `#` and `;` as starting a comment.
fn stripComment(line: []const u8) []const u8 {
    return line[0 .. std.mem.indexOfAny(u8, line, "#;") orelse line.len];
}

/// Copies whole search domains into `dest` until the next one would not fit,
/// so a truncated list never ends in a half-written suffix.
fn copySearchList(dest: *[max_search]u8, list: []const u8) usize {
    var len: usize = 0;
    var domains = std.mem.tokenizeAny(u8, list, " \t\r");
    while (domains.next()) |domain| {
        if (domain.len > HostName.max_len) continue;
        const separator: usize = @intFromBool(len != 0);
        if (len + separator + domain.len > dest.len) break;
        if (separator != 0) {
            dest[len] = ' ';
            len += 1;
        }
        @memcpy(dest[len..][0..domain.len], domain);
        len += domain.len;
    }
    return len;
}

fn readResolvConf(io: Io, buffer: *[max_resolv_conf_bytes]u8) HostName.LookupError!ResolvConf {
    const contents = Io.Dir.cwd().readFile(io, "/etc/resolv.conf", buffer) catch |err| switch (err) {
        error.Canceled => |e| return e,
        else => return error.DetectingNetworkConfigurationFailed,
    };
    // A file larger than the buffer is cut off mid-line; drop the partial tail
    // rather than parsing half a directive.
    const complete = if (contents.len == buffer.len)
        contents[0 .. std.mem.lastIndexOfScalar(u8, contents, '\n') orelse 0]
    else
        contents;
    var rc: ResolvConf = try .parse(io, complete);
    if (rc.nameservers_len == 0) {
        rc.nameservers_buffer[0] = .{ .ip4 = .loopback(dns_port) };
        rc.nameservers_len = 1;
    }
    return rc;
}

// --- lookup ---

/// Applies the `search` list the way resolv.conf(5) describes, then queries.
fn lookupDns(
    io: Io,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) HostName.LookupError!void {
    var file_buffer: [max_resolv_conf_bytes]u8 = undefined;
    const rc = try readResolvConf(io, &file_buffer);

    // A name carrying at least `ndots` dots, or a trailing dot, is already
    // global scope and must not be suffixed.
    const dots = std.mem.countScalar(u8, host_name.bytes, '.');
    const trailing_dot = std.mem.endsWith(u8, host_name.bytes, ".");

    var name = host_name.bytes;
    if (trailing_dot) name.len -= 1;
    if (std.mem.endsWith(u8, name, ".")) return error.UnknownHostName;
    if (name.len == 0) return error.UnknownHostName;

    var local_buffer: [HostName.max_len]u8 = undefined;
    const name_buffer = options.canonical_name_buffer orelse &local_buffer;

    if (dots < rc.ndots and !trailing_dot) {
        var suffixes = std.mem.tokenizeScalar(u8, rc.search(), ' ');
        while (suffixes.next()) |suffix| {
            const candidate_len = name.len + 1 + suffix.len;
            if (candidate_len > name_buffer.len) continue;
            @memcpy(name_buffer[0..name.len], name);
            name_buffer[name.len] = '.';
            @memcpy(name_buffer[name.len + 1 ..][0..suffix.len], suffix);
            if (query(io, &rc, name_buffer[0..candidate_len], resolved, options)) {
                return;
            } else |err| switch (err) {
                error.UnknownHostName, error.NoAddressReturned => continue,
                else => |e| return e,
            }
        }
    }

    @memcpy(name_buffer[0..name.len], name);
    return query(io, &rc, name_buffer[0..name.len], resolved, options);
}

/// Sends A and AAAA queries to every configured nameserver, retrying until the
/// resolv.conf timeout expires, and queues whatever addresses come back.
fn query(
    io: Io,
    rc: *const ResolvConf,
    name: []const u8,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) HostName.LookupError!void {
    // `A` is skipped for an IPv6-only caller and `AAAA` for an IPv4-only one.
    const wanted: [2]struct { family: IpAddress.Family, record: HostName.DnsRecord } = .{
        .{ .family = .ip6, .record = .A },
        .{ .family = .ip4, .record = .AAAA },
    };
    var query_storage: [2][max_query_len]u8 = undefined;
    var queries_storage: [2][]const u8 = undefined;
    var queries_len: usize = 0;
    for (wanted) |w| {
        if (options.family == w.family) continue;
        var id: [2]u8 = undefined;
        io.random(&id);
        // Sharing a transaction id with the other question would make both
        // replies match the first of them, stranding the second one.
        for (queries_storage[0..queries_len]) |other| {
            if (id[0] == other[0] and id[1] == other[1]) id[1] +%= 1;
        }
        const len = writeQuery(&query_storage[queries_len], name, w.record, id) orelse
            return error.UnknownHostName;
        queries_storage[queries_len] = query_storage[queries_len][0..len];
        queries_len += 1;
    }
    const queries = queries_storage[0..queries_len];
    if (queries.len == 0) return error.NoAddressReturned;

    // An IPv6 socket reaches IPv4 nameservers through their mapped addresses,
    // so a single socket covers a mixed nameserver list.
    var mapped_storage: [max_nameservers]IpAddress = undefined;
    const servers = rc.nameservers();
    const mapped = mapped_storage[0..servers.len];
    var use_ip6 = false;
    for (servers, mapped) |server, *m| {
        m.* = .{ .ip6 = .fromAny(server) };
        use_ip6 = use_ip6 or server == .ip6;
    }

    var socket = socket: {
        if (use_ip6) ip6: {
            const unspecified: IpAddress = .{ .ip6 = .unspecified(0) };
            break :socket unspecified.bind(io, .{ .ip6_only = true, .mode = .dgram }) catch |err| switch (err) {
                error.AddressFamilyUnsupported => break :ip6,
                else => |e| return e,
            };
        }
        use_ip6 = false;
        const unspecified: IpAddress = .{ .ip4 = .unspecified(0) };
        break :socket try unspecified.bind(io, .{ .mode = .dgram });
    };
    defer socket.close(io);
    const targets = if (use_ip6) mapped else servers;

    var receive_storage: [max_messages * max_reply_len]u8 = undefined;
    var reply_storage: [2][max_reply_len]u8 = undefined;
    var answers_storage: [2][]const u8 = .{ &.{}, &.{} };
    const answers = answers_storage[0..queries.len];
    var answers_remaining = answers.len;

    // The boot clock keeps suspended time counting against a wait for a reply.
    const clock: Io.Clock = .boot;
    var now = clock.now(io);
    const deadline = now.addDuration(.fromSeconds(rc.timeout_seconds));
    const attempt_duration: Io.Duration = .{
        .nanoseconds = (std.time.ns_per_s / rc.attempts) * @as(i96, rc.timeout_seconds),
    };

    send: while (now.nanoseconds < deadline.nanoseconds) : (now = clock.now(io)) {
        {
            var outgoing: [max_messages]net.OutgoingMessage = undefined;
            var outgoing_len: usize = 0;
            for (queries, answers) |q, answer| {
                if (answer.len != 0) continue;
                for (targets) |*target| {
                    outgoing[outgoing_len] = .{
                        .address = target,
                        .data_ptr = q.ptr,
                        .data_len = q.len,
                    };
                    outgoing_len += 1;
                }
            }
            socket.sendMany(io, outgoing[0..outgoing_len], .{}) catch {};
        }

        const attempt_deadline = now.addDuration(attempt_duration);
        const timeout: Io.Timeout = .{ .deadline = .{
            .raw = attempt_deadline,
            .clock = clock,
        } };

        while (true) {
            // `receiveManyTimeout` takes whatever is already waiting before it
            // consults the clock, so a nameserver that never stops answering,
            // or a socket that keeps failing without delay, would otherwise
            // keep this loop running long past its deadline.
            if (clock.now(io).nanoseconds >= attempt_deadline.nanoseconds) continue :send;

            var incoming: [max_messages]net.IncomingMessage = @splat(.init);
            const receive_err, const received = socket.receiveManyTimeout(
                io,
                &incoming,
                &receive_storage,
                .{},
                timeout,
            );
            for (incoming[0..received]) |*message| {
                const reply = message.data;
                if (reply.len < 4 or reply.len > max_reply_len) continue;

                // Ignore anything from an address we did not query.
                const server = for (targets) |*target| {
                    if (message.from.eql(target)) break target;
                } else continue;

                // Match the reply to its question by transaction id.
                const index = for (queries, 0..) |q, i| {
                    if (reply[0] == q[0] and reply[1] == q[1]) break i;
                } else continue;
                if (answers[index].len != 0) continue;

                switch (reply[3] & 15) {
                    // Take positive (0) and authoritative negative (3) replies.
                    // Copy out of the shared receive buffer, which the next
                    // receive overwrites.
                    0, 3 => {
                        const slot = reply_storage[index][0..reply.len];
                        @memcpy(slot, reply);
                        answers[index] = slot;
                        answers_remaining -= 1;
                        if (answers_remaining == 0) break :send;
                    },
                    // Retry a server failure (2) immediately.
                    2 => {
                        const q = queries[index];
                        var retry: net.OutgoingMessage = .{
                            .address = server,
                            .data_ptr = q.ptr,
                            .data_len = q.len,
                        };
                        socket.sendMany(io, (&retry)[0..1], .{}) catch {};
                    },
                    // Ignore anything else, such as a refusal.
                    else => continue,
                }
            }
            if (receive_err) |err| switch (err) {
                error.Canceled => |e| return e,
                error.Timeout => continue :send,
                else => continue,
            };
        }
    } else return error.NameServerFailure;

    var addresses: usize = 0;
    var canonical_name: ?HostName = null;
    for (answers) |answer| {
        if (answer.len == 0) continue;
        var records = HostName.DnsResponse.init(answer) catch continue;
        while (records.next() catch continue) |record| switch (record.rr) {
            .A => {
                const data = record.packet[record.data_off..][0..record.data_len];
                if (data.len != 4) return error.InvalidDnsARecord;
                try put(io, resolved, .{ .address = .{ .ip4 = .{
                    .bytes = data[0..4].*,
                    .port = options.port,
                } } });
                addresses += 1;
            },
            .AAAA => {
                const data = record.packet[record.data_off..][0..record.data_len];
                if (data.len != 16) return error.InvalidDnsAAAARecord;
                try put(io, resolved, .{ .address = .{ .ip6 = .{
                    .bytes = data[0..16].*,
                    .port = options.port,
                } } });
                addresses += 1;
            },
            .CNAME => {
                if (options.canonical_name_buffer) |buffer| {
                    _, canonical_name = HostName.expand(record.packet, record.data_off, buffer) catch
                        return error.InvalidDnsCnameRecord;
                }
            },
            _ => continue,
        };
    }

    // Report the name only once an address is in hand, so that falling through
    // to the next search suffix cannot queue a second canonical name.
    if (addresses == 0) return error.NoAddressReturned;
    if (options.canonical_name_buffer != null) {
        try put(io, resolved, .{ .canonical_name = canonical_name orelse .{ .bytes = name } });
    }
}

/// Writes a recursive query for `name` into `buffer`, returning its length, or
/// `null` when `name` cannot be expressed as a DNS question.
fn writeQuery(
    buffer: *[max_query_len]u8,
    name: []const u8,
    record: HostName.DnsRecord,
    id: [2]u8,
) ?usize {
    var stripped = name;
    if (std.mem.endsWith(u8, stripped, ".")) stripped.len -= 1;
    if (stripped.len == 0 or stripped.len > 253) return null;

    buffer[0..2].* = id;
    buffer[2] = 0x01; // recursion desired
    buffer[3] = 0x00;
    std.mem.writeInt(u16, buffer[4..6], 1, .big); // one question
    @memset(buffer[6..12], 0); // no answer, authority or additional records

    var len: usize = 12;
    var labels = std.mem.splitScalar(u8, stripped, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return null;
        buffer[len] = @intCast(label.len);
        len += 1;
        @memcpy(buffer[len..][0..label.len], label);
        len += label.len;
    }
    buffer[len] = 0; // root label
    len += 1;
    std.mem.writeInt(u16, buffer[len..][0..2], @intFromEnum(record), .big);
    len += 2;
    std.mem.writeInt(u16, buffer[len..][0..2], 1, .big); // class IN
    len += 2;
    return len;
}

// --- tests ---

const testing = std.testing;

/// Modelled on the file WSL 2 generates on a machine joined to a corporate
/// network, with the real suffixes replaced by placeholders of the same shape.
/// A `search` line this long is what defeats the standard library.
const wsl_resolv_conf =
    \\# This file was automatically generated by WSL. To stop automatic generation of this file, add the following entry to /etc/wsl.conf:
    \\# [network]
    \\# generateResolvConf = false
    \\nameserver 10.255.255.254
    \\search corp.example.com eu.corp.example.com us.corp.example.com apac.corp.example.com dev.corp.example.com test.corp.example.com stage.corp.example.com prod.corp.example.com build.corp.example.com deploy.corp.example.com remote.corp.example.com vpn.corp.example.com wifi.corp.example.com lab.corp.example.com research.corp.example.com sales.corp.example.com support.corp.example.com partners.example.net internal.example.net services.example.net registry.example.net storage.example.net database.example.net cache.example.net queue.example.net metrics.example.net logging.example.net identity.example.net gateway.example.net in-addr.arpa ip6.arpa example.org
    \\
;

test "parse: WSL search line longer than the standard library's line buffer" {
    // The regression this module exists for: the standard library reads
    // resolv.conf through a 512-byte line buffer and copies the search list
    // into a 255-byte buffer, so this file fails both limits.
    const search_line = wsl_resolv_conf[std.mem.indexOf(u8, wsl_resolv_conf, "search ").?..];
    try testing.expect(std.mem.indexOfScalar(u8, search_line, '\n').? > 512);

    const rc = try ResolvConf.parse(testing.io, wsl_resolv_conf);
    try testing.expectEqual(@as(usize, 1), rc.nameservers_len);
    try testing.expect(rc.nameservers()[0].eql(&try IpAddress.parse("10.255.255.254", 53)));
    try testing.expect(rc.search_len > HostName.max_len);

    var suffixes = std.mem.tokenizeScalar(u8, rc.search(), ' ');
    try testing.expectEqualStrings("corp.example.com", suffixes.next().?);

    // Every retained suffix must be whole, never a truncated tail.
    var last: []const u8 = "";
    while (suffixes.next()) |suffix| last = suffix;
    try testing.expectEqualStrings("example.org", last);
}

test "parse: defaults when the file says nothing" {
    const rc = try ResolvConf.parse(testing.io, "");
    try testing.expectEqual(@as(usize, 0), rc.nameservers_len);
    try testing.expectEqual(@as(usize, 0), rc.search_len);
    try testing.expectEqual(@as(u32, 1), rc.ndots);
    try testing.expectEqual(@as(u32, 5), rc.timeout_seconds);
    try testing.expectEqual(@as(u32, 2), rc.attempts);
}

test "parse: nameservers, options and comments" {
    const rc = try ResolvConf.parse(testing.io,
        \\# a comment
        \\nameserver 1.1.1.1 # trailing comment
        \\nameserver 2606:4700:4700::1111
        \\; semicolon comment
        \\nameserver 8.8.8.8
        \\nameserver 9.9.9.9
        \\options ndots:3 timeout:9 attempts:4 edns0
        \\domain example.com
        \\
    );
    // resolv.conf(5) keeps at most three nameservers.
    try testing.expectEqual(@as(usize, 3), rc.nameservers_len);
    try testing.expect(rc.nameservers()[0].eql(&try IpAddress.parse("1.1.1.1", 53)));
    try testing.expect(rc.nameservers()[1].eql(&try IpAddress.parse("2606:4700:4700::1111", 53)));
    try testing.expect(rc.nameservers()[2].eql(&try IpAddress.parse("8.8.8.8", 53)));
    try testing.expectEqual(@as(u32, 3), rc.ndots);
    try testing.expectEqual(@as(u32, 9), rc.timeout_seconds);
    try testing.expectEqual(@as(u32, 4), rc.attempts);
    try testing.expectEqualStrings("example.com", rc.search());
}

test "parse: skips malformed entries instead of failing the lookup" {
    const rc = try ResolvConf.parse(testing.io,
        \\nameserver not-an-address
        \\nameserver
        \\sortlist 130.155.160.0/255.255.240.0
        \\options ndots attempts:zero
        \\nameserver 1.0.0.1
        \\
    );
    try testing.expectEqual(@as(usize, 1), rc.nameservers_len);
    try testing.expect(rc.nameservers()[0].eql(&try IpAddress.parse("1.0.0.1", 53)));
    try testing.expectEqual(@as(u32, 1), rc.ndots);
    try testing.expectEqual(@as(u32, 2), rc.attempts);
}

test "parse: clamps values that would divide by zero or overflow" {
    const rc = try ResolvConf.parse(testing.io,
        \\options ndots:99 timeout:0 attempts:0
        \\
    );
    try testing.expectEqual(@as(u32, 15), rc.ndots);
    try testing.expectEqual(@as(u32, 1), rc.timeout_seconds);
    try testing.expectEqual(@as(u32, 1), rc.attempts);
}

test "parse: a last line without a trailing newline still counts" {
    // The standard library reports `error.EndOfStream` for this file.
    const rc = try ResolvConf.parse(testing.io, "nameserver 1.1.1.1");
    try testing.expectEqual(@as(usize, 1), rc.nameservers_len);
}

test "parse: keeps a nameserver whose address carries a scope" {
    // Resolving "%lo" needs a real interface table, and the module only runs
    // on Linux anyway.
    if (!enabled) return error.SkipZigTest;

    // `IpAddress.parse` rejects the "%lo" suffix, so only `resolve` keeps this
    // nameserver; dropping it would leave the fallback talking to 127.0.0.1.
    const rc = try ResolvConf.parse(testing.io, "nameserver fe80::1%lo\n");
    try testing.expectEqual(@as(usize, 1), rc.nameservers_len);
    try testing.expect(rc.nameservers()[0] == .ip6);
}

test "copySearchList: drops the first domain that does not fit whole" {
    var buffer: [max_search]u8 = undefined;

    const domain = "a" ** 63 ++ ".example.com";
    var list: std.ArrayListUnmanaged(u8) = .empty;
    defer list.deinit(testing.allocator);
    for (0..100) |_| {
        try list.appendSlice(testing.allocator, domain);
        try list.append(testing.allocator, ' ');
    }

    const len = copySearchList(&buffer, list.items);
    try testing.expect(len <= buffer.len);

    var domains = std.mem.tokenizeScalar(u8, buffer[0..len], ' ');
    var count: usize = 0;
    while (domains.next()) |d| : (count += 1) try testing.expectEqualStrings(domain, d);
    try testing.expectEqual(buffer.len / (domain.len + 1), count);
}

test "copySearchList: skips a domain longer than a host name may be" {
    var buffer: [max_search]u8 = undefined;
    const len = copySearchList(&buffer, "a" ** (HostName.max_len + 1) ++ " ok.example.com");
    try testing.expectEqualStrings("ok.example.com", buffer[0..len]);
}

test "stripComment" {
    try testing.expectEqualStrings("nameserver 1.1.1.1 ", stripComment("nameserver 1.1.1.1 # comment"));
    try testing.expectEqualStrings("nameserver 1.1.1.1 ", stripComment("nameserver 1.1.1.1 ; comment"));
    try testing.expectEqualStrings("", stripComment("# whole line"));
    try testing.expectEqualStrings("no comment", stripComment("no comment"));
}

test "writeQuery: encodes a question the standard library can read back" {
    var buffer: [max_query_len]u8 = undefined;
    const len = writeQuery(&buffer, "api.github.com", .A, .{ 0xab, 0xcd }).?;

    try testing.expectEqualSlices(u8, &.{
        0xab, 0xcd, // id
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no records
        3,    'a',  'p',  'i',
        6,    'g',  'i',  't',  'h',  'u',  'b',
        3,    'c',  'o',  'm',
        0, // root label
        0x00, 0x01, // type A
        0x00, 0x01, // class IN
    }, buffer[0..len]);

    // Turn the question into the reply a nameserver would send, and walk it
    // with the same parser `query` uses, so the encoding stays compatible.
    var reply: [max_query_len + 16]u8 = undefined;
    @memcpy(reply[0..len], buffer[0..len]);
    reply[2] = 0x81; // response, recursion desired
    reply[3] = 0x80; // recursion available, no error
    std.mem.writeInt(u16, reply[6..8], 1, .big); // one answer
    const answer = [_]u8{
        0xc0, 0x0c, // name: pointer to the question
        0x00, 0x01, // type A
        0x00, 0x01, // class IN
        0x00, 0x00, 0x00, 0x3c, // ttl
        0x00, 0x04, // four bytes of data
        140,  82,   112,  4,
    };
    @memcpy(reply[len..][0..answer.len], &answer);

    var response = try HostName.DnsResponse.init(reply[0 .. len + answer.len]);
    const record = (try response.next()).?;
    try testing.expectEqual(HostName.DnsRecord.A, record.rr);
    try testing.expectEqualSlices(
        u8,
        &.{ 140, 82, 112, 4 },
        record.packet[record.data_off..][0..record.data_len],
    );
    try testing.expectEqual(@as(?HostName.DnsResponse.Answer, null), try response.next());
}

test "writeQuery: strips a trailing dot and rejects unusable names" {
    var buffer: [max_query_len]u8 = undefined;

    const with_dot = writeQuery(&buffer, "example.com.", .AAAA, .{ 0, 1 }).?;
    var without_dot_buffer: [max_query_len]u8 = undefined;
    const without_dot = writeQuery(&without_dot_buffer, "example.com", .AAAA, .{ 0, 1 }).?;
    try testing.expectEqualSlices(u8, without_dot_buffer[0..without_dot], buffer[0..with_dot]);

    try testing.expectEqual(@as(?usize, null), writeQuery(&buffer, "", .A, .{ 0, 0 }));
    try testing.expectEqual(@as(?usize, null), writeQuery(&buffer, ".", .A, .{ 0, 0 }));
    try testing.expectEqual(@as(?usize, null), writeQuery(&buffer, "a..b", .A, .{ 0, 0 }));
    try testing.expectEqual(@as(?usize, null), writeQuery(&buffer, "a" ** 64 ++ ".com", .A, .{ 0, 0 }));
    try testing.expectEqual(@as(?usize, null), writeQuery(&buffer, "a." ** 127 ++ "ab", .A, .{ 0, 0 }));
}

test "writeQuery: fills the buffer exactly at the longest legal name" {
    var buffer: [max_query_len]u8 = undefined;
    const name = ("a" ** 63 ++ ".") ** 3 ++ "a" ** 61;
    try testing.expectEqual(@as(usize, 253), name.len);
    try testing.expectEqual(@as(?usize, max_query_len), writeQuery(&buffer, name, .A, .{ 0, 0 }));
}
