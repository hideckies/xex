// Framework: Capstone (https://github.com/capstone-engine/capstone)

const std = @import("std");
const color = @import("./common.zig").color;
const stdout = @import("./common.zig").stdout;
const symbol = @import("./common.zig").symbol;
const TRAP_INST_MASK = @import("./common.zig").types.TRAP_INST_MASK;
const util = @import("./common.zig").util;
const Breakpoint = @import("./breakpoint.zig").Breakpoint;
const getOriginalInstByAddr = @import("./breakpoint.zig").getOriginalInstByAddr;
// const Function = @import("./func.zig").Function;
const ptrace = @import("./process.zig").ptrace;

pub const Instruction = @import("./disass/inst.zig").Instruction;
pub const getInstructions = @import("./disass/inst.zig").getInstructions;

pub fn disassemble(
    allocator: std.mem.Allocator,
    pid: i32,
    breakpoints: std.ArrayList(Breakpoint),
    target_addr: usize,
    lines: usize,
) ![]Instruction {
    const size: usize = @sizeOf(usize) * lines; // 128;

    var buffer: []u8 = allocator.alloc(u8, size) catch |err| {
        return err;
    };
    var current_addr = target_addr;
    var idx: usize = 0;
    while (idx < size) : (idx += @sizeOf(usize)) {
        var data: usize = 0;
        try ptrace.readText(pid, current_addr, &data);
        if (data == -1) {
            return stdout.print_error("Failed to read memory at address 0x{x}\n", .{current_addr});
        }

        // If the breakpoint is set at the address, replace `int3` with the original instruction.
        const orig_data = try getOriginalInstByAddr(current_addr, breakpoints);
        if (orig_data) |od| {
            data = od;
        }

        // Convert usize to []u8 (adjust little-endian)
        var data_bytes: [@sizeOf(usize)]u8 = undefined;
        var k: usize = 0;
        while (k < @sizeOf(usize)) : (k += 1) {
            data_bytes[k] = @intCast(data >> (8 * @as(u6, @intCast(k))) & 0xff);
        }
        // Add the data_bytes to buffer
        var m: usize = 0;
        while (m < @sizeOf(usize)) : (m += 1) {
            buffer[idx + m] = data_bytes[m];
        }

        current_addr += @sizeOf(usize);
    }
    const buffer_c = &buffer[0];

    const insts = getInstructions(
        allocator,
        buffer_c,
        buffer.len,
        target_addr, // start_addr,
        breakpoints,
    ) catch |err| {
        return err;
    };
    return insts;
}

pub fn displayInstructions(
    allocator: std.mem.Allocator,
    instructions: []Instruction,
    pid: i32,
    // funcs: []Function,
    breakpoints: std.ArrayList(Breakpoint),
    lines: usize, // number of lines to display.
    is_hexdump: bool,
) !void {
    const pc = try ptrace.readRegister(pid, "pc");

    for (instructions, 0..) |inst, i| {
        if (i + 1 > lines) break;

        // Display the function name if it is the start of the function.
        // for (funcs) |func| {
        //     if (func.addr == inst.addr) {
        //         try stdout.print("{s}:\n", .{func.name});
        //     }
        // }

        inst.display(allocator, pc, breakpoints, is_hexdump) catch {
            try stdout.print("<unknown>\n", .{});
        };
    }
}
