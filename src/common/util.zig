const std = @import("std");
const stdout = @import("./stdout.zig");

pub fn indexOfString(haystack: [][]const u8, needle: []const u8) ?usize {
    for (haystack, 0..) |item, i| {
        if (std.mem.eql(u8, item, needle)) {
            return i;
        }
    }
    return null;
}

pub fn readCstring(allocator: std.mem.Allocator, reader: anytype, offset: usize) ![]const u8 {
    const current_pos = try reader.context.getPos();

    try reader.context.seekTo(0); // Reset poistion temporarily.
    var file_buf = try reader.context.readToEndAlloc(allocator, try reader.context.getEndPos());
    try reader.context.seekTo(current_pos); // Restore the current position.

    var length: usize = 0;
    while (file_buf[offset + length] != 0) {
        length += 1;
    }
    return file_buf[offset .. offset + length];
}

pub fn usizeToBytes(allocator: std.mem.Allocator, value: usize) ![]u8 {
    const value_hex = try std.fmt.allocPrint(allocator, "{x:0>16}", .{value});

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    var i: usize = 0;
    while (i < value_hex.len) {
        // If the byte is 1 digit, add '0'
        if (i % 2 == 0 and i + 1 >= value_hex.len) {
            try result.append('0');
        }
        try result.append(value_hex[i]);

        // Add space for each byte
        if (i % 2 == 1 and i != (value_hex.len - 1)) {
            try result.append(' ');
        }
        i += 1;
    }

    return result.toOwnedSlice();
}

pub fn timestapmToDateStr(allocator: std.mem.Allocator, timestamp: u64) ![]const u8 {
    const epoch = std.time.epoch.EpochSeconds{ .secs = timestamp };
    const epoch_day = epoch.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();

    const year = year_day.year;
    const month = month_day.month.numeric();
    const day = month_day.day_index + 1;
    const hours = day_seconds.getHoursIntoDay();
    const minutes = day_seconds.getMinutesIntoHour();
    const seconds = day_seconds.getSecondsIntoMinute();

    return std.fmt.allocPrint(
        allocator,
        "{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}",
        .{ year, month, day, hours, minutes, seconds },
    );
}
