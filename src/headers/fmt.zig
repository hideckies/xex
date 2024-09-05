const std = @import("std");
const chameleon = @import("chameleon");

pub fn fmtMultiHeaders(
    allocator: std.mem.Allocator,
    comptime T: type,
    headers: []T,
    empty_message: []const u8,
    is_index: bool,
) ![]const u8 {
    var cham = chameleon.initRuntime(.{ .allocator = allocator });
    defer cham.deinit();

    // Format Section Headers
    var str_hdrs = std.ArrayList([]const u8).init(allocator);
    defer str_hdrs.deinit();
    for (headers, 0..) |hdr, i| {
        const str_hdr = if (is_index) try std.fmt.allocPrint(
            allocator,
            "[{s}] {s}\n",
            .{
                try cham.green().fmt("{d}", .{i}),
                hdr,
            },
        ) else try std.fmt.allocPrint(
            allocator,
            "{s}\n",
            .{hdr},
        );
        try str_hdrs.append(str_hdr);
    }
    if (headers.len == 0) {
        try str_hdrs.append(try cham.red().fmt("{s}\n", .{empty_message}));
    }

    return try std.mem.join(
        allocator,
        "",
        try allocator.dupe([]const u8, str_hdrs.items),
    );
}
