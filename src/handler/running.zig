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
        new_process, // new_process.memmap.base_addr_info.exe_base_addr,
        dbg.headers,
        dbg.breakpoints,
        dbg.option.file.path,
        dbg.option.file.buffer,
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
    const status = try ptrace.continueExec(dbg.process.pid);
    switch (status) {
        .SignalTrap => return,
        .ProcessExited => try restart(dbg, cmd),
        else => return error.WaitError,
    }
}

pub fn step(dbg: *Debugger, cmd: *Command) !void {
    const status = try ptrace.singleStep(dbg.process.pid);
    switch (status) {
        .SignalTrap => return,
        .ProcessExited => try restart(dbg, cmd),
        else => return error.WaitError,
    }
}
