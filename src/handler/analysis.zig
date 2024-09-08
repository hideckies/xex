const std = @import("std");
const stdout = @import("../common.zig").stdout;
const util = @import("../common.zig").util;
const Command = @import("../readline.zig").Command;
const Debugger = @import("../dbg.zig").Debugger;
const disas = @import("../disas.zig");
const ptrace = @import("../process.zig").ptrace;
const _helper = @import("./_helper.zig");

pub fn info(dbg: *Debugger) !void {
    try dbg.headers.printInfo();
}

pub fn hash(dbg: *Debugger) !void {
    try stdout.print("{}", .{dbg.option.file.hash});
}

pub fn headers(dbg: *Debugger) !void {
    try dbg.headers.printHeaders();
}

pub fn file_header(dbg: *Debugger) !void {
    try dbg.headers.printFileHeader();
}

pub fn program_headers(dbg: *Debugger) !void {
    try dbg.headers.printProgramHeaders();
}

pub fn sections(dbg: *Debugger) !void {
    try dbg.headers.printSectionHeaders();
}

pub fn symbols(dbg: *Debugger) !void {
    try dbg.headers.printSymbols();
}

pub fn dynsymbols(dbg: *Debugger) !void {
    try dbg.headers.printDynSymbols();
}

// Display all functions.
pub fn functions(dbg: *Debugger) !void {
    if (dbg.funcs.len == 0) {
        try stdout.print("Functions not found.\n", .{});
    }
    for (dbg.funcs) |func| {
        try stdout.print("{}\n", .{func});
    }
}

// Disassemble.
pub fn disassemble(dbg: *Debugger, cmd: Command) !void {
    // Determine target address
    var addr: usize = 0;
    var lines: usize = 10; // Number of lines to display.
    if (cmd.command_args.items.len == 0) {
        // Set PC to target address.
        addr = ptrace.readRegister(dbg.process.pid, "pc") catch |err| {
            return stdout.print_error(dbg.allocator, "error: {}\n", .{err});
        };
    } else {
        const arg = cmd.command_args.items[0];
        addr = _helper.getAddrFromArg(dbg, arg) catch |err| {
            return stdout.print_error(dbg.allocator, "error: {}\n", .{err});
        };

        // Get the argument for number of lines to display.
        if (cmd.command_args.items.len == 2) {
            lines = std.fmt.parseInt(usize, cmd.command_args.items[1], 10) catch |err| {
                return stdout.print_error(dbg.allocator, "error: {}\n", .{err});
            };
        }
    }

    // Disassemble and get instructions.
    const insts = disas.disassemble(
        dbg.allocator,
        dbg.process.pid,
        dbg.breakpoints,
        addr,
        lines,
    ) catch |err| {
        return stdout.print_error(dbg.allocator, "error: {}\n", .{err});
    };
    disas.displayInstructions(
        dbg.allocator,
        insts,
        dbg.process.pid,
        // dbg.funcs,
        dbg.breakpoints,
        lines,
        false,
    ) catch |err| {
        return stdout.print_error(dbg.allocator, "error: {}\n", .{err});
    };
}

// Display decompiled source code.
pub fn decompile(dbg: *Debugger, cmd: Command) !void {
    if (cmd.command_args.items.len == 0) {
        return stdout.print("Not enough argument.\n", .{});
    }

    const target = cmd.command_args.items[0];

    if (dbg.debug_info.elf == null) {
        return stdout.print("[x] No debug info.\n", .{});
    }
    var dwarf_info = dbg.debug_info.elf.?.dwarf;

    try stdout.print("dwarf_info: {}\n", .{dwarf_info});

    // Get target address
    if (!std.mem.startsWith(u8, target, "0x")) {
        return stdout.print("[x] The target value is not address.\n", .{});
    }
    const target_addr = try std.fmt.parseInt(u64, target[2..], 16);

    // Get line info.
    const compile_unit = try dwarf_info.findCompileUnit(target_addr);
    const bp_line_info = try dwarf_info.getLineNumberInfo(dbg.allocator, compile_unit, target_addr);
    // defer bp_line_info.deinit();

    var file = try std.fs.cwd().openFile(bp_line_info.file_name, .{});
    const reader = file.reader();
    defer file.close();

    var line_buf: [1024]u8 = undefined;
    var line_num: u32 = 1;
    while (line_num < bp_line_info.line - 1) : (line_num += 1) {
        const line = try reader.readUntilDelimiter(line_buf[0..], '\n');
        _ = line;
    }

    while (line_num < bp_line_info.line + 2) {
        const line = try reader.readUntilDelimiterOrEof(line_buf[0..], '\n');
        try stdout.print("{} {s}\n", .{ line_num, line.? });
    }
}
