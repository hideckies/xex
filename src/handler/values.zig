const builtin = @import("builtin");
const std = @import("std");
const stdout = @import("../common.zig").stdout;
const readline = @import("../readline.zig");
const Command = readline.Command;
const CommandType = readline.CommandType;
const Debugger = @import("../dbg.zig").Debugger;
const ptrace = @import("../process.zig").ptrace;
const X86Registers = @import("../reg/x86.zig").X86Registers;
const X8664Registers = @import("../reg/x86_64.zig").X8664Registers;

// Display register values.
pub fn registers(dbg: *Debugger) !void {
    switch (builtin.cpu.arch) {
        .x86 => {
            var regs: X86Registers = undefined;
            try ptrace.readRegisters(dbg.pid, @intFromPtr(&regs));
            try regs.display(dbg.allocator);
        },
        .x86_64 => {
            var regs: X8664Registers = undefined;
            try ptrace.readRegisters(dbg.process.pid, @intFromPtr(&regs));
            try regs.display(dbg.allocator);
        },
        else => try stdout.print("Unsupported architecture.\n", .{}),
    }
}

// Helper function for print()
fn print_switch(command_type: CommandType, target: []const u8, value: usize) !void {
    switch (command_type) {
        CommandType.printb => try stdout.print("{s} = 0b{b}\n", .{ target, value }),
        CommandType.printo => try stdout.print("{s} = 0o{o}\n", .{ target, value }),
        CommandType.printd => try stdout.print("{s} = {d}\n", .{ target, value }),
        CommandType.printx => try stdout.print("{s} = 0x{x}\n", .{ target, value }),
        // CommandType.prints => {
        //     try stdout.print("\n{s} = {s}\n\n", .{ target, value });
        // },
        else => try stdout.print("Unknown print format you specified.\n", .{}),
    }
}

// Display value of address/register in specified format.
pub fn print(dbg: *Debugger, cmd: Command) !void {
    if (cmd.command_args.items.len == 0) {
        return stdout.print("Not enough argument.\n", .{});
    }

    const target = cmd.command_args.items[0];
    if (std.mem.startsWith(u8, target, "0x")) {
        // Read value of the address.
        const addr = std.fmt.parseInt(usize, target[2..], 16) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
        var value: usize = undefined;
        ptrace.readData(dbg.process.pid, addr, &value) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };

        try print_switch(cmd.command_type, target, value);
    } else {
        // Read value of register.
        const value = ptrace.readRegister(dbg.allocator, dbg.process.pid, target) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
        print_switch(cmd.command_type, target, value) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
    }
}

// Display value of address/register in string.
pub fn prints(dbg: *Debugger, cmd: Command) !void {
    if (cmd.command_args.items.len == 0) {
        return stdout.print("Not enough argument.\n", .{});
    }

    const target = cmd.command_args.items[0];
    var addr: usize = undefined;
    if (std.mem.startsWith(u8, target, "0x")) {
        // Read value of the address.
        addr = std.fmt.parseInt(usize, target[2..], 16) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
    } else {
        // Read string value of the register.
        addr = ptrace.readRegister(dbg.allocator, dbg.process.pid, target) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
    }

    // Read strings until null-terminated character.
    const str_value = ptrace.readDataAsString(dbg.process.pid, addr) catch |err| {
        return stdout.printError("error: {}\n", .{err});
    };
    try stdout.print("0x{x} = {s}\n", .{ addr, str_value });
}

pub fn set(dbg: *Debugger, cmd: Command) !void {
    if (cmd.command_args.items.len < 2) {
        return stdout.print("Not enough argument.\n", .{});
    }

    const target = cmd.command_args.items[0];
    const value = cmd.command_args.items[1];

    // Convert string to usize
    var value_num: usize = 0;
    if (std.mem.startsWith(u8, value, "0x")) {
        value_num = std.fmt.parseInt(usize, value[2..], 16) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
    } else {
        value_num = std.fmt.parseInt(usize, value, 10) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
    }

    // Detect address
    if (std.mem.eql(u8, target[0..1], "0x")) {
        // Set value to address.
        const addr = try std.fmt.parseInt(usize, target[2..], 16);
        ptrace.writeData(dbg.process.pid, addr, value_num) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
    } else {
        // Set value to register.
        ptrace.writeRegister(dbg.allocator, dbg.process.pid, target, value_num) catch |err| {
            return stdout.printError("error: {}\n", .{err});
        };
    }
}
