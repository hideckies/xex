const std = @import("std");
const stdout = @import("./common.zig").stdout;

pub const MemoryMap = @import("./process/memmap.zig").MemoryMap;
pub const ptrace = @import("./process/ptrace.zig");

pub const Process = struct {
    allocator: std.mem.Allocator,
    pid: i32,
    memmap: MemoryMap,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        file_path: []const u8,
        file_args: [*:null]const ?[*:0]const u8,
    ) !Self {
        const pid = try ptrace.startTracing(file_path, file_args);
        const memmap = try MemoryMap.init(allocator, pid, file_path);

        return Self{
            .allocator = allocator,
            .pid = pid,
            .memmap = memmap,
        };
    }

    pub fn deinit(self: *Self) void {
        self.memmap.deinit();
    }
};
