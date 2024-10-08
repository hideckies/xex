const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../common.zig").stdout;
const Breakpoint = @import("../breakpoint.zig").Breakpoint;
const Command = @import("../readline.zig").Command;
const Debugger = @import("../dbg.zig").Debugger;

const _helper = @import("./_helper.zig");

pub fn breakpoint(dbg: *Debugger, cmd: Command) !void {
    if (cmd.command_args.items.len == 0) {
        return stdout.printError("Not enough argument.\n", .{});
    } else if (cmd.command_args.items.len > 1) {
        return stdout.printError("Too many arguments.\n", .{});
    }

    const target = cmd.command_args.items[0];
    const target_idx: usize = std.fmt.parseInt(usize, target, 10) catch {
        return stdout.printError(
            "Invalid argument. Specify the index of breakpoints.\n",
            .{},
        );
    };

    // Find the target breakpoint by index.
    for (dbg.breakpoints.items, 0..) |bp, i| {
        if (i + 1 == target_idx) {
            // Display the information.
            return stdout.print("{s}\n", .{bp});
        }
    }
    return stdout.printError("Breakpoint not found at {d}\n", .{target_idx});
}

pub fn breakpointAdd(dbg: *Debugger, cmd: Command) !void {
    var arena = std.heap.ArenaAllocator.init(dbg.allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
    defer cham.deinit();

    if (cmd.command_args.items.len == 0) {
        return stdout.printError("Not enough argument.\n", .{});
    } else if (cmd.command_args.items.len > 1) {
        return stdout.printError("Too many arguments.\n", .{});
    }

    var addr: usize = undefined;
    const arg = cmd.command_args.items[0];
    addr = _helper.getAddrFromArg(dbg, arg) catch |err| {
        return stdout.printError("error: {}\n", .{err});
    };

    // Check if the address alread exists in breakpoints.
    for (dbg.breakpoints.items) |b| {
        if (b.addr == addr) {
            return stdout.printError(
                "The address {s} has already been set to breakpoint.\n",
                .{try cham.yellow().fmt("0x{x}", .{addr})},
            );
        }
    }

    // Add breakpoint.
    const bp = Breakpoint.init(dbg.process.pid, addr) catch |err| {
        return stdout.printError("error: {}\n", .{err});
    };
    try dbg.breakpoints.append(bp);

    return stdout.printInfo(
        "Breakpoint added at {s}\n",
        .{try cham.yellow().fmt("0x{x}", .{addr})},
    );
}

pub fn breakpointDelete(dbg: *Debugger, cmd: Command) !void {
    if (cmd.command_args.items.len == 0) {
        return stdout.printError("Not enough argument.\n", .{});
    } else if (cmd.command_args.items.len > 1) {
        return stdout.printError("Too many arguments.\n", .{});
    }

    const target = cmd.command_args.items[0];
    const target_idx: usize = std.fmt.parseInt(usize, target, 10) catch {
        return stdout.printError(
            "Invalid argument. Specify the index of breakpoints.\n",
            .{},
        );
    };

    // Find the target breakpoint by index.
    for (dbg.breakpoints.items, 0..) |*item, i| {
        var bp = item.*;
        if (i + 1 == target_idx) {
            // Unset & delete this breakpoint.
            try bp.unset();
            _ = dbg.breakpoints.orderedRemove(i);
            return stdout.printInfo(
                "The breakpoint removed at index {d}.\n",
                .{target_idx},
            );
        }
    }
    return stdout.printError("Breakpoint not found at {d}\n", .{target_idx});
}

// Display all breakpoints.
pub fn breakpoints(dbg: *Debugger) !void {
    var arena = std.heap.ArenaAllocator.init(dbg.allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
    defer cham.deinit();

    if (dbg.breakpoints.items.len == 0) {
        return stdout.printError("Breakpoints are not set.\n", .{});
    }

    // var str_bps = std.ArrayList([]const u8).init(dbg.allocator);
    for (dbg.breakpoints.items, 0..) |bp, i| {
        const str_bp = try std.fmt.allocPrint(arena_allocator, "{s}\t{s}", .{
            try cham.greenBright().fmt("{d}", .{i + 1}),
            try cham.yellow().fmt("0x{x}", .{bp.addr}),
        });
        // try str_bps.append(str_bp);
        try stdout.print("{s}\n", .{str_bp});
    }
}
