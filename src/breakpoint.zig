const builtin = @import("builtin");
const std = @import("std");
const stdout = @import("./common.zig").stdout;
const types = @import("./common.zig").types;
const ptrace = @import("./process.zig").ptrace;
const trap_inst_t = types.trap_inst_t;
const TRAP_INST = types.TRAP_INST;
const TRAP_INST_MASK = types.TRAP_INST_MASK;

pub const Breakpoint = struct {
    pid: std.posix.pid_t,
    addr: usize,
    orig_inst: usize,
    is_set: bool,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const str =
            \\Address                 : 0x{x}
            \\Original instruction    : 0x{x}
            \\Set                     : {s}
        ;
        return writer.print(str, .{ self.addr, self.orig_inst, if (self.is_set) "Yes" else "No" });
    }

    pub fn init(pid: std.posix.pid_t, addr: usize) !Self {
        var self = Self{
            .pid = pid,
            .addr = addr,
            .orig_inst = undefined,
            .is_set = false,
        };
        try self.set();
        return self;
    }

    // Reference: https://github.com/tensorush/dobby/blob/main/src/Breakpoint.zig#L32
    pub fn set(self: *Self) !void {
        var inst: usize = 0;
        try ptrace.readText(self.pid, self.addr, &inst);
        const orig_inst: u8 = @intCast(inst & 0xff);
        const modified_inst = (inst & TRAP_INST_MASK) | 0xcc;
        try ptrace.writeText(self.pid, self.addr, modified_inst);
        self.orig_inst = orig_inst;
        self.is_set = true;
    }

    pub fn unset(self: *Self) !void {
        var inst: usize = 0;
        try ptrace.readText(self.pid, self.addr, &inst);
        const restored_inst = (inst & TRAP_INST_MASK) | self.orig_inst;
        try ptrace.writeText(self.pid, self.addr, restored_inst);
        self.orig_inst = restored_inst;
        self.is_set = false;
    }

    // If the process exited, return true.
    pub fn reset(self: *Self) !bool {
        try self.unset();
        const status = try ptrace.singleStep(self.pid);
        switch (status) {
            .SignalTrap => return false,
            .ProcessExited => return true,
            else => return error.WaitError,
        }
        try self.set();
    }
};

// Get original instruction of the breakpoint at specified address.
pub fn getOriginalInstByAddr(addr: usize, breakpoints: std.ArrayList(Breakpoint)) !?usize {
    // If the breakpoint is set at the current_addr, replace `int3` with the original instruction.
    for (breakpoints.items) |bp| {
        if (bp.addr == addr and bp.is_set) {
            var inst: usize = 0;
            try ptrace.readText(bp.pid, bp.addr, &inst);
            return (inst & TRAP_INST_MASK) | bp.orig_inst;
        }
    }
    return null;
}
