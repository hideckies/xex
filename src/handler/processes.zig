const std = @import("std");
const colored = @import("../common.zig").color.colored;
const chameleon = @import("chameleon");
const stdout = @import("../common.zig").stdout;
const symbol = @import("../common.zig").symbol;
const Debugger = @import("../dbg.zig").Debugger;

// Display the current PID of running target program.
pub fn processes(dbg: *Debugger) !void {
    var arena = std.heap.ArenaAllocator.init(dbg.allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
    defer cham.deinit();

    return stdout.print(
        "{s} ({s})\n  └ {s} ({s})\n",
        .{
            try cham.yellow().fmt("xex", .{}),
            try cham.cyanBright().fmt("{d}", .{std.c.getpid()}),
            try cham.yellow().fmt("{s}", .{dbg.option.file.path}),
            try cham.cyanBright().fmt("{d}", .{dbg.process.pid}),
        },
    );
}
