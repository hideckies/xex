const std = @import("std");
const stdout = @import("../common.zig").stdout;

pub const History = struct {
    entries: std.ArrayList([]const u8),
    max_len: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_len: usize) Self {
        return Self{
            .entries = std.ArrayList([]const u8).init(allocator),
            .max_len = max_len,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |item| {
            self.allocator.free(item);
        }
        self.entries.deinit();
    }

    pub fn addEntry(self: *Self, entry: []const u8) !void {
        const dest = try self.allocator.alloc(u8, entry.len);
        @memcpy(dest, entry);
        try self.entries.append(dest);
        // if (self.entries.items.len > self.max_len) {
        //     // Rotate history if max_len is reached
        //     const items = self.entries.items;
        //     @memcpy(items[0 .. self.max_len - 1], items[1..self.max_len]);
        // }
    }

    pub fn getEntry(self: *Self, idx: usize) ?[]const u8 {
        if (self.entries.items.len == 0) return null;
        // std.debug.print("max_idx: {d}\n", .{current_max_idx});
        // std.debug.print("idx: {d}\n", .{idx});
        return self.entries.items[idx];
    }
};
