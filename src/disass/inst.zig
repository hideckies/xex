const std = @import("std");
const chameleon = @import("chameleon");
const Colors = chameleon.HexColors;
const color = @import("../common.zig").color;
const emoji = @import("../common.zig").emoji;
const stdout = @import("../common.zig").stdout;
const symbol = @import("../common.zig").symbol;
const Breakpoint = @import("../breakpoint.zig").Breakpoint;
const Function = @import("../func.zig").Function;
const getOriginalInstByAddr = @import("../breakpoint.zig").getOriginalInstByAddr;
const ptrace = @import("../process.zig").ptrace;

const displayMarkersGuide = @import("./marker.zig").displayMarkersGuide;
const makeMarker = @import("./marker.zig").makeMarker;
const parseErrorCode = @import("./error.zig").parseErrorCode;

const c = @cImport({
    @cInclude("capstone/capstone.h");
});

pub const Instruction = struct {
    allocator: std.mem.Allocator,
    addr: usize,
    size: usize,
    bytes: []const u8,
    mnemonic: []const u8,
    op_str: []const u8,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        addr: usize,
        size: usize,
        bytes: []const u8,
        mnemonic: []const u8,
        op_str: []const u8,
    ) Self {
        return Self{
            .allocator = allocator,
            .addr = addr,
            .size = size,
            .bytes = bytes,
            .mnemonic = mnemonic,
            .op_str = op_str,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.mnemonic);
        self.allocator.free(self.op_str);
    }

    pub fn display(
        self: Self,
        pc: usize,
        breakpoints: std.ArrayList(Breakpoint),
        funcs: ?[]Function,
    ) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        // Display the function name if it is the start of the function.
        if (funcs) |funcs_| {
            for (funcs_) |func| {
                if (func.start_addr == self.addr) {
                    try stdout.print("\n{s}:\n", .{func.name});
                }
            }
        }

        // Prepare strings.
        const str_addr = if (self.addr == pc) try cham.black().bgGreenBright().fmt("0x{x:0>16}", .{self.addr}) else try cham.greenBright().fmt("0x{x:0>16}", .{self.addr});
        const str_mnemonic = try cham.yellow().fmt("{s}", .{self.mnemonic});
        const str_op = try cham.cyanBright().fmt("{s}", .{self.op_str});

        try stdout.print("{s}{s}\t{s}\t{s}\n", .{
            try makeMarker(arena_allocator, self.addr, breakpoints),
            str_addr,
            str_mnemonic,
            str_op,
        });

        // Add newline if the address is the end_addr.
        if (funcs) |funcs_| {
            for (funcs_) |func| {
                if (func.end_addr == self.addr) {
                    try stdout.print("\n", .{});
                }
            }
        }
    }
};

fn getSingleInstruction(
    allocator: std.mem.Allocator,
    code: [*c]const u8,
    code_size: usize,
    start_addr: usize,
) !Instruction {
    var handle: c.csh = 0;
    defer _ = c.cs_close(&handle);
    const err = c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &handle);
    if (err != c.CS_ERR_OK) {
        return error.CapstoneInitError;
    }

    var insn: [*c]c.cs_insn = undefined;

    const count = c.cs_disasm(
        handle,
        code,
        code_size,
        start_addr,
        0,
        @ptrCast(&insn),
    );
    if (count > 0) {
        const addr = insn[0].address;
        const size = insn[0].size;

        const bytes = insn[0].bytes;

        // Truncate characters after null-terminator
        const mnemonic = insn[0].mnemonic;
        var mnemonic_size: usize = 0;
        while (mnemonic[mnemonic_size] != 0) : (mnemonic_size += 1) {}

        const op_str = insn[0].op_str;
        var op_str_size: usize = 0;
        while (op_str[op_str_size] != 0) : (op_str_size += 1) {}

        c.cs_free(insn, count);
        return Instruction.init(
            allocator,
            addr,
            size,
            try allocator.dupe(u8, bytes[0..]),
            try allocator.dupe(u8, mnemonic[0..mnemonic_size]),
            try allocator.dupe(u8, op_str[0..op_str_size]),
        );
    } else {
        const err_code = c.cs_errno(handle);
        if (parseErrorCode(err_code)) |e| {
            return e;
        }
    }
    return error.Unknown;
}

pub fn getInstructions(
    allocator: std.mem.Allocator,
    code: [*c]const u8,
    code_size: usize,
    start_addr: usize,
    end_addr: ?usize,
    breakpoints: std.ArrayList(Breakpoint),
) ![]Instruction {
    var insts = std.ArrayList(Instruction).init(allocator);
    defer insts.deinit();

    var handle: c.csh = 0;
    defer _ = c.cs_close(&handle);
    const err = c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &handle);
    if (err != c.CS_ERR_OK) {
        return error.CapstoneInitError;
    }

    var insn: [*c]c.cs_insn = undefined;

    const count = c.cs_disasm(
        handle,
        code,
        code_size,
        start_addr,
        0,
        @ptrCast(&insn),
    );
    if (count > 0) {
        for (0..count) |i| {
            const addr = insn[i].address;
            const size = insn[i].size;

            // Truncate characters after null-terminator
            const bytes = insn[i].bytes;
            // var bytes_size: usize = 0;
            // while (bytes[bytes_size] != 0 and bytes_size < 16) : (bytes_size += 1) {}

            const mnemonic = insn[i].mnemonic;
            var mnemonic_size: usize = 0;
            while (mnemonic[mnemonic_size] != 0) : (mnemonic_size += 1) {}

            const op_str = insn[i].op_str;
            var op_str_size: usize = 0;
            while (op_str[op_str_size] != 0) : (op_str_size += 1) {}

            var new_inst = Instruction.init(
                allocator,
                addr,
                size,
                try allocator.dupe(u8, bytes[0..]),
                try allocator.dupe(u8, mnemonic[0..mnemonic_size]),
                try allocator.dupe(u8, op_str[0..op_str_size]),
            );

            // -------------------------------------------------------------------------------
            // If the breakpoint is set at the address, replace `int3` with the original instruction.
            const orig_data = try getOriginalInstByAddr(addr, breakpoints);
            if (orig_data) |data| {
                const orig_code_size = @sizeOf(usize);
                var buffer: []u8 = allocator.alloc(u8, orig_code_size) catch |e| {
                    return e;
                };
                defer allocator.free(buffer);
                // Convert usize to []u8 (adjust little-endian)
                var data_bytes: [@sizeOf(usize)]u8 = undefined;
                var k: usize = 0;
                while (k < @sizeOf(usize)) : (k += 1) {
                    data_bytes[k] = @intCast(data >> (8 * @as(u6, @intCast(k))) & 0xff);
                }
                // Add the data_bytes to buffer
                var m: usize = 0;
                while (m < @sizeOf(usize)) : (m += 1) {
                    buffer[m] = data_bytes[m];
                }
                const buffer_c = &buffer[0];

                const orig_inst = try getSingleInstruction(
                    allocator,
                    buffer_c,
                    orig_code_size,
                    addr,
                );
                try insts.append(orig_inst);

                // Don't forget free the new_inst.
                new_inst.deinit();
            } else {
                try insts.append(new_inst);
            }
            // -------------------------------------------------------------------------------

            if (end_addr != null and addr >= end_addr.?) break;
        }
        c.cs_free(insn, count);
        return insts.toOwnedSlice();
    } else {
        const err_code = c.cs_errno(handle);
        if (parseErrorCode(err_code)) |e| {
            switch (e) {
                error.OK => return insts.toOwnedSlice(),
                else => return e,
            }
        }
    }
    return error.Unknown;
}
