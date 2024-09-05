const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../common.zig").stdout;
const Breakpoint = @import("../breakpoint.zig").Breakpoint;

pub fn makeMarker(
    allocator: std.mem.Allocator,
    insn_addr: usize,
    breakpoints: std.ArrayList(Breakpoint),
) ![]const u8 {
    var cham = chameleon.initRuntime(.{ .allocator = allocator });
    defer cham.deinit();

    for (breakpoints.items) |bp| {
        if (bp.addr == insn_addr and bp.is_set) {
            return cham.red().fmt("•", .{});
        }
    }
    return " ";
}
