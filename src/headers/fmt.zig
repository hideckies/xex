const std = @import("std");
const chameleon = @import("chameleon");

pub const MultiEntriesString = struct {
    allocator: std.mem.Allocator,
    str: std.ArrayList([]const u8),
    str_joined: []const u8,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        comptime T: type,
        entries: []T,
        comptime empty_message: []const u8,
        comptime is_index: bool,
        comptime indent: usize,
    ) !Self {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        var str_hdrs = std.ArrayList([]const u8).init(allocator);
        if (entries.len > 0) {
            for (entries, 0..) |hdr, i| {
                const str_hdr = if (is_index) try std.fmt.allocPrint(
                    allocator,
                    "{s}[{s}] {s}\n",
                    .{
                        " " ** indent,
                        try cham.green().fmt("{d}", .{i}),
                        hdr,
                    },
                ) else try std.fmt.allocPrint(
                    allocator,
                    "{s}{s}\n",
                    .{ " " ** indent, hdr },
                );
                defer allocator.free(str_hdr);
                try str_hdrs.append(try allocator.dupe(u8, str_hdr));
            }
        } else {
            try str_hdrs.append(try allocator.dupe(u8, try cham.red().fmt("{s}\n", .{empty_message})));
        }

        return Self{
            .allocator = allocator,
            .str = str_hdrs,
            .str_joined = try std.mem.join(allocator, "", str_hdrs.items),
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.str.items) |s| {
            self.allocator.free(s);
        }
        self.str.deinit();
        self.allocator.free(self.str_joined);
    }
};
