const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../common.zig").stdout;
const Command = @import("../readline.zig").Command;
const Debugger = @import("../dbg.zig").Debugger;
const Process = @import("../process.zig").Process;
const ptrace = @import("../process.zig").ptrace;
const func = @import("../func.zig");

pub fn restart(dbg: *Debugger, cmd: *Command) !void {
    var cham = chameleon.initRuntime(.{ .allocator = dbg.allocator });
    defer cham.deinit();

    try stdout.print_info(dbg.allocator, "Restarting the program...\n", .{});

    _ = std.os.linux.kill(dbg.process.pid, std.os.linux.SIG.KILL);

    const new_process = try Process.init(
        dbg.allocator,
        dbg.option.file.path,
        dbg.option.file.args.?,
    );
    dbg.process = new_process;
    // Refetch functions.
    dbg.funcs = try func.getFunctions(
        dbg.allocator,
        new_process,
        dbg.headers,
        dbg.option.file.path,
        dbg.option.file.buffer,
        dbg.breakpoints,
    );

    cmd.pid = new_process.pid;

    // Reset breakpoints
    dbg.breakpoints.clearRetainingCapacity();

    try stdout.print_info(
        dbg.allocator,
        "The process started with PID {s}.\n",
        .{try cham.cyanBright().fmt("{d}", .{new_process.pid})},
    );
}

pub fn conti(dbg: *Debugger, cmd: *Command) !void {
    const pc = try ptrace.readRegister(dbg.process.pid, "pc");
    for (dbg.breakpoints.items) |*bp| {
        if (bp.addr == pc) {
            if (bp.is_set) {
                if (try bp.reset()) {
                    try restart(dbg, cmd);
                }
            }
            break;
        }
    }

    const status = try ptrace.continueExec(dbg.process.pid);
    switch (status) {
        .SignalTrap => return,
        .ProcessExited => try restart(dbg, cmd),
        else => return error.WaitError,
    }
}

pub fn stepi(dbg: *Debugger, cmd: *Command) !void {
    const allocator = std.heap.page_allocator;

    // Step n times.
    var n: usize = 1;
    if (cmd.command_args.items.len == 1) {
        n = std.fmt.parseInt(usize, cmd.command_args.items[0], 10) catch |err| {
            return stdout.print_error(allocator, "Invalid argument: {}\n", .{err});
        };
    } else if (cmd.command_args.items.len > 1) {
        return stdout.print_error(allocator, "Too many arguments.\n", .{});
    }

    const pc = try ptrace.readRegister(dbg.process.pid, "pc");

    while (n > 0) : (n -= 1) {
        var bp_reached: bool = false;
        for (dbg.breakpoints.items) |*bp| {
            if (bp.addr == pc) {
                bp_reached = true;
                if (try bp.reset()) {
                    try restart(dbg, cmd);
                }
                break;
            }
        }

        if (!bp_reached) {
            const status = try ptrace.singleStep(dbg.process.pid);
            switch (status) {
                .SignalTrap => return,
                .ProcessExited => try restart(dbg, cmd),
                else => return error.WaitError,
            }
        }
    }
}

pub fn steps(dbg: *Debugger, cmd: *Command) !void {
    const allocator = std.heap.page_allocator;

    // Step n times.
    var n: usize = 1;
    if (cmd.command_args.items.len == 1) {
        n = std.fmt.parseInt(usize, cmd.command_args.items[0], 10) catch |err| {
            return stdout.print_error(allocator, "Invalid argument: {}\n", .{err});
        };
    } else if (cmd.command_args.items.len > 1) {
        return stdout.print_error(allocator, "Too many arguments.\n", .{});
    }

    var dwarf = dbg.debug_info.elf.?.dwarf;

    while (n > 0) : (n -= 1) {
        var pc_offset = try dbg.process.memmap.base_addr_info.getOffset(
            try ptrace.readRegister(dbg.process.pid, "pc"),
        );
        const compile_unit = dwarf.findCompileUnit(pc_offset) catch |err| {
            return stdout.print_error(allocator, "Failed to step source: {}\n", .{err});
        };
        const line_info = dwarf.getLineNumberInfo(allocator, compile_unit, pc_offset) catch |err| {
            return stdout.print_error(allocator, "Failed to step source: {}\n", .{err});
        };

        while (true) {
            try stepi(dbg, cmd);

            pc_offset = try dbg.process.memmap.base_addr_info.getOffset(
                try ptrace.readRegister(dbg.process.pid, "pc"),
            );
            const new_line_info = dwarf.getLineNumberInfo(allocator, compile_unit, pc_offset) catch |err| {
                return stdout.print_error(allocator, "Failed to step source: {}\n", .{err});
            };

            if ((new_line_info.line == line_info.line) and
                (new_line_info.column == line_info.column) and
                (std.mem.eql(u8, new_line_info.file_name, line_info.file_name)))
            {
                break;
            }
        }
    }
}
