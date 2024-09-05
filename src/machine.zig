const builtin = @import("builtin");
const std = @import("std");
const stdout = @import("./common.zig").stdout;

pub const Machine = struct {
    allocator: std.mem.Allocator,
    cpu_count: usize,
    memory_total: ?usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .allocator = allocator,
            .cpu_count = try std.Thread.getCpuCount(),
            .memory_total = try std.process.totalSystemMemory(),
        };
    }
};
