const std = @import("std");

pub fn decompressAlloc(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output: usize,
) ![]u8 {
    var input_index: usize = 0;
    const output_len = try readLength(compressed, &input_index);
    if (output_len > max_output) return error.OutputTooLarge;

    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    var output_index: usize = 0;
    while (input_index < compressed.len) {
        if (output_index == output.len) return error.TrailingData;

        const tag = compressed[input_index];
        input_index += 1;

        switch (tag & 0x03) {
            0 => {
                const literal_len = try readLiteralLength(tag, compressed, &input_index);
                if (literal_len > output.len - output_index) return error.OutputLengthMismatch;
                if (literal_len > compressed.len - input_index) return error.TruncatedInput;

                @memcpy(
                    output[output_index..][0..literal_len],
                    compressed[input_index..][0..literal_len],
                );
                input_index += literal_len;
                output_index += literal_len;
            },
            1 => {
                if (input_index >= compressed.len) return error.TruncatedInput;
                const copy_len: usize = 4 + ((tag >> 2) & 0x07);
                const offset: usize =
                    (@as(usize, tag & 0xe0) << 3) |
                    compressed[input_index];
                input_index += 1;
                try copyFromOutput(output, &output_index, offset, copy_len);
            },
            2 => {
                if (compressed.len - input_index < 2) return error.TruncatedInput;
                const copy_len: usize = 1 + (tag >> 2);
                const offset = std.mem.readInt(u16, compressed[input_index..][0..2], .little);
                input_index += 2;
                try copyFromOutput(output, &output_index, offset, copy_len);
            },
            3 => {
                if (compressed.len - input_index < 4) return error.TruncatedInput;
                const copy_len: usize = 1 + (tag >> 2);
                const offset = std.mem.readInt(u32, compressed[input_index..][0..4], .little);
                input_index += 4;
                try copyFromOutput(output, &output_index, offset, copy_len);
            },
            else => unreachable,
        }
    }

    if (output_index != output.len) return error.OutputLengthMismatch;
    return output;
}

fn readLength(compressed: []const u8, input_index: *usize) !usize {
    var value: u32 = 0;
    var shift: u5 = 0;

    for (0..5) |i| {
        if (input_index.* >= compressed.len) return error.TruncatedInput;
        const byte = compressed[input_index.*];
        input_index.* += 1;

        if (i == 4 and byte > 0x0f) return error.LengthOverflow;
        value |= @as(u32, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) return value;
        shift += 7;
    }

    return error.LengthOverflow;
}

fn readLiteralLength(tag: u8, compressed: []const u8, input_index: *usize) !usize {
    const encoded_len = tag >> 2;
    if (encoded_len < 60) return @as(usize, encoded_len) + 1;

    const length_bytes: usize = encoded_len - 59;
    if (compressed.len - input_index.* < length_bytes) return error.TruncatedInput;

    var length_minus_one: u32 = 0;
    for (0..length_bytes) |i| {
        length_minus_one |= @as(u32, compressed[input_index.* + i]) <<
            @intCast(i * 8);
    }
    input_index.* += length_bytes;

    return std.math.add(usize, @as(usize, length_minus_one), 1) catch
        return error.LengthOverflow;
}

fn copyFromOutput(
    output: []u8,
    output_index: *usize,
    offset_value: anytype,
    copy_len: usize,
) !void {
    const offset = std.math.cast(usize, offset_value) orelse
        return error.InvalidOffset;
    if (offset == 0 or offset > output_index.*) return error.InvalidOffset;
    if (copy_len > output.len - output_index.*) return error.OutputLengthMismatch;

    for (0..copy_len) |_| {
        output[output_index.*] = output[output_index.* - offset];
        output_index.* += 1;
    }
}

test "decompresses literals and all copy tag widths" {
    const allocator = std.testing.allocator;

    const literal = try decompressAlloc(allocator, "\x05\x10hello", 5);
    defer allocator.free(literal);
    try std.testing.expectEqualStrings("hello", literal);

    const copy_one = try decompressAlloc(
        allocator,
        "\x0c\x08abc\x15\x03",
        12,
    );
    defer allocator.free(copy_one);
    try std.testing.expectEqualStrings("abcabcabcabc", copy_one);

    const copy_two = try decompressAlloc(
        allocator,
        "\x41\x00a\xfe\x01\x00",
        65,
    );
    defer allocator.free(copy_two);
    try std.testing.expectEqualSlices(u8, "a" ** 65, copy_two);

    const copy_four = try decompressAlloc(
        allocator,
        "\x05\x00a\x0f\x01\x00\x00\x00",
        5,
    );
    defer allocator.free(copy_four);
    try std.testing.expectEqualStrings("aaaaa", copy_four);
}

test "decompresses long literals" {
    const allocator = std.testing.allocator;
    const compressed = "\x3d\xf0\x3c" ++ ("x" ** 61);
    const output = try decompressAlloc(allocator, compressed, 61);
    defer allocator.free(output);
    try std.testing.expectEqualSlices(u8, "x" ** 61, output);
}

test "rejects malformed and oversized inputs" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(
        error.TruncatedInput,
        decompressAlloc(allocator, "\x80", 1024),
    );
    try std.testing.expectError(
        error.LengthOverflow,
        decompressAlloc(allocator, "\xff\xff\xff\xff\x10", std.math.maxInt(usize)),
    );
    try std.testing.expectError(
        error.OutputTooLarge,
        decompressAlloc(allocator, "\x05\x10hello", 4),
    );
    try std.testing.expectError(
        error.TruncatedInput,
        decompressAlloc(allocator, "\x05\x10hell", 5),
    );
    try std.testing.expectError(
        error.InvalidOffset,
        decompressAlloc(allocator, "\x05\x00a\x0f\x00\x00\x00\x00", 5),
    );
    try std.testing.expectError(
        error.InvalidOffset,
        decompressAlloc(allocator, "\x05\x00a\x0f\x02\x00\x00\x00", 5),
    );
    try std.testing.expectError(
        error.OutputLengthMismatch,
        decompressAlloc(allocator, "\x06\x10hello", 6),
    );
    try std.testing.expectError(
        error.TrailingData,
        decompressAlloc(allocator, "\x01\x00a\x00", 1),
    );
}
