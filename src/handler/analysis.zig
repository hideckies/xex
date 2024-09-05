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

pub fn hexdump(dbg: *Debugger, cmd: Command) !void {
    var addr: []const u8 = undefined;
    if (cmd.command_args.items.len == 0) {
        // The start address is not specified, the program counter is used.
        const pc = try ptrace.readRegister(dbg.process.pid, "pc");
        addr = try std.fmt.allocPrint(dbg.allocator, "0x{x}", .{pc});
    } else if (cmd.command_args.items.len > 1) {
        return stdout.print("Too many arguments.\n", .{});
    } else {
        addr = cmd.command_args.items[0];
    }

    // Convert addr string to int
    if (!std.mem.startsWith(u8, addr, "0x")) {
        return stdout.print("Invalid start address: {s}\n", .{addr});
    }
    const addr_int = try std.fmt.parseInt(usize, addr[2..], 16);

    // const start_addr: *const u8 = @ptrFromInt(addr_int);
    const max_dump_length: usize = 128;
    // const bytes_per_line: usize = 16;
    // const buffer = @as([*]const u8, @ptrCast(start_addr))[0..max_dump_length];

    // var ascii_buffer: [bytes_per_line]u8 = undefined;

    //     try stdout.print("\n", .{});
    //     for (buffer, 0..) |byte, i| {
    //         // Dump HEX
    //         try stdout.print("{x:0>2} ", .{byte});

    //         // Get ASCII
    //         if (byte >= 0x20 and byte <= 0x7E) {
    //             ascii_buffer[i % bytes_per_line] = byte;
    //         } else {
    //             ascii_buffer[i % bytes_per_line] = '.'; // Non-printable characters are replaced with '.'
    //         }

    //         // Dump ASCII
    //         if ((i + 1) % bytes_per_line == 0) {
    //             try stdout.print(" | {s}\n", .{ascii_buffer});
    //         }
    //     }

    //     // Process the final line
    //     const remaining = max_dump_length % bytes_per_line;
    //     if (remaining != 0) {
    //         for (remaining..16) |_| {
    //             try stdout.print("   ", .{});
    //         }
    //         try stdout.print(" | {s}\n", .{ascii_buffer[0..remaining]});
    //     }
    //     try stdout.print("\n", .{});

    // try ptrace.readAddress(dbg.pid, addr_int, &data);
    // const start_addr: *const u8 = @ptrFromInt(data);
    // const bytes = @as([*]const u8, @ptrCast(start_addr))[0..max_dump_length];
    // for (bytes, 0..) |byte, i| {
    //     _ = i;
    //     try stdout.print("{x:0>2} ", .{byte});
    // }

    var offset: usize = 0;
    while (offset < max_dump_length) {
        var data: usize = undefined;
        try ptrace.readData(dbg.process.pid, addr_int + offset, &data);

        const bytes = try util.usizeToBytes(dbg.allocator, data);
        try stdout.print("{s} ", .{bytes});

        // Dump hex
        // const data_hex = try std.fmt.allocPrint(dbg.allocator, "{x:0>16}", .{data});
        for (bytes, 0..) |byte, i| {
            _ = byte;
            _ = i;
            // try stdout.print("{s}")
            // try stdout.print("{x:0>2} ", .{byte});
            //     if ((i + 1) % bytes_per_line == 0) {
            //         try stdout.print("\n", .{});
            //     }
            //     try stdout.print("{s} ", .{data_hex[i .. i + 1]});
        }
        try stdout.print("\n", .{});
        offset += @sizeOf(usize);
    }
}
