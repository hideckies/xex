// Framework: Capstone (https://github.com/capstone-engine/capstone)

const std = @import("std");
const color = @import("./common.zig").color;
const stdout = @import("./common.zig").stdout;
const symbol = @import("./common.zig").symbol;
const TRAP_INST_MASK = @import("./common.zig").types.TRAP_INST_MASK;
const util = @import("./common.zig").util;
const Breakpoint = @import("./breakpoint.zig").Breakpoint;
const getOriginalInstByAddr = @import("./breakpoint.zig").getOriginalInstByAddr;
const Function = @import("./func.zig").Function;
const ptrace = @import("./process.zig").ptrace;

pub const Instruction = @import("./disass/inst.zig").Instruction;
pub const getInstructions = @import("./disass/inst.zig").getInstructions;

pub const Disas = struct {
    allocator: std.mem.Allocator,
    pid: i32,
    breakpoints: std.ArrayList(Breakpoint),
    addr: usize,
    lines: usize,
    funcs: ?[]Function,
    insts: []Instruction,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        pid: i32,
        breakpoints: std.ArrayList(Breakpoint),
        target_addr: usize,
        lines: usize,
        funcs: ?[]Function,
    ) !Self {
        const size: usize = @sizeOf(usize) * lines; // 128;

        var start_addr: usize = target_addr;
        var end_addr: usize = 0;

        // If the target address is in range of a function, set the addresses.
        if (funcs) |fs| {
            for (fs) |f| {
                if (f.start_addr <= target_addr and target_addr <= f.end_addr) {
                    start_addr = f.start_addr;
                    end_addr = f.end_addr;
                    break;
                }
            }
        }

        var buffer: []u8 = try allocator.alloc(u8, size);
        defer allocator.free(buffer);

        var current_addr = start_addr;
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

        const insts = try getInstructions(
            allocator,
            buffer_c,
            buffer.len,
            start_addr,
            if (end_addr > 0) end_addr else null,
            breakpoints,
        );

        return Self{
            .allocator = allocator,
            .pid = pid,
            .breakpoints = breakpoints,
            .addr = target_addr,
            .lines = lines,
            .funcs = funcs,
            .insts = insts,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.insts) |*inst| {
            inst.deinit();
        }
        self.allocator.free(self.insts);
    }

    pub fn displayInstructions(self: Self) !void {
        const pc = try ptrace.readRegister(self.pid, "pc");

        for (self.insts, 0..) |inst, i| {
            if (i + 1 > self.lines) break;

            inst.display(self.allocator, pc, self.breakpoints, self.funcs) catch {
                try stdout.print("<unknown>\n", .{});
            };
        }
    }

    pub fn findFuncStartAddr(self: Self) !usize {
        for (self.insts) |inst| {
            if (std.mem.containsAtLeast(u8, inst.mnemonic, 1, "endbr")) {
                return inst.addr;
            }
        }
        return error.FuncStartAddrNotFound;
    }

    pub fn findFuncEndAddr(self: Self) !usize {
        var prev_addr: usize = 0;
        for (self.insts) |inst| {
            if (prev_addr > 0) {
                if (std.mem.containsAtLeast(u8, inst.mnemonic, 1, "endbr")) {
                    return prev_addr;
                }
            }
            if (std.mem.eql(u8, inst.mnemonic, "ret")) {
                return inst.addr;
            }
            prev_addr = inst.addr;
        }
        return error.FuncEndAddrNotFound;
    }
};
