// Reference: https://github.com/tensorush/dobby/blob/main/src/ptrace.zig

const builtin = @import("builtin");
const linux = std.os.linux;
const PTRACE = linux.PTRACE;
const posix = std.posix;
const stdout = @import("../common.zig").stdout;
const X86Registers = @import("../reg.zig").X86Registers;
const X8664Registers = @import("../reg.zig").X8664Registers;

const c = @cImport({
    @cInclude("sys/user.h");
    @cInclude("sys/personality.h");
});

const std = @import("std");

pub const WaitStatus = enum {
    ProcessExited,
    ProcessStopeed,
    SignalTrap,
    SignalUnexpected,
    Unknown,
};

pub fn wait(pid: posix.pid_t) !WaitStatus {
    const status = posix.waitpid(pid, 0).status;
    if (linux.W.IFSTOPPED(status)) {
        const signal = linux.W.STOPSIG(status);
        if (signal == posix.SIG.TRAP) {
            return .SignalTrap;
        } else {
            return .SignalUnexpected;
        }
    } else if (linux.W.IFEXITED(status)) {
        try stdout.print("Process exited with status 0x{x}\n", .{status});
        return .ProcessExited;
    } else {
        return .Unknown;
    }
}

pub fn killOnExit(pid: posix.pid_t) !void {
    try posix.ptrace(PTRACE.SETOPTIONS, pid, 0, 0x0010_0000);
}

// Probably it is the same as PEEKDATA.
pub fn readText(pid: posix.pid_t, addr: usize, inst: *usize) !void {
    try posix.ptrace(PTRACE.PEEKTEXT, pid, addr, @intFromPtr(inst));
}

pub fn writeText(pid: posix.pid_t, addr: usize, inst: usize) !void {
    try posix.ptrace(PTRACE.POKETEXT, pid, addr, inst);
}

// Probably it is the same as PEEKTEXT.
pub fn readData(pid: posix.pid_t, addr: usize, data: *usize) !void {
    try posix.ptrace(PTRACE.PEEKDATA, pid, addr, @intFromPtr(data));
}

pub fn readDataAsString(pid: posix.pid_t, addr: usize) ![]u8 {
    var buf: [1024]u8 = undefined;
    var buf_len: usize = 0;
    for (buf[0..], 0..) |*byte, i| {
        var word_value: u8 = 0;
        try posix.ptrace(PTRACE.PEEKDATA, pid, addr + i, @intFromPtr(&word_value));
        byte.* = word_value;
        if (word_value == 0) {
            break;
        }
        buf_len += 1;
    }
    return buf[0..buf_len];
}

pub fn writeData(pid: posix.pid_t, addr: usize, data: usize) !void {
    try posix.ptrace(PTRACE.POKEDATA, pid, addr, data);
}

pub fn readRegisters(pid: posix.pid_t, regs_int: usize) !void {
    try posix.ptrace(PTRACE.GETREGS, pid, 0, regs_int);
}

pub fn readRegister(allocator: std.mem.Allocator, pid: posix.pid_t, reg_name: []const u8) !usize {
    switch (builtin.cpu.arch) {
        .x86 => {
            var regs: X86Registers = undefined;
            try posix.ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
            return regs.get(allocator, reg_name);
        },
        .x86_64 => {
            var regs: X8664Registers = undefined;
            try posix.ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
            return regs.get(allocator, reg_name);
        },
        else => return error.UnsupportedArchitecture,
    }
}

pub fn writeRegister(allocator: std.mem.Allocator, pid: posix.pid_t, reg_name: []const u8, value: usize) !void {
    switch (builtin.cpu.arch) {
        .x86 => {
            var regs: X86Registers = undefined;
            try posix.ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
            try regs.set(allocator, reg_name, value);
            try posix.ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
        },
        .x86_64 => {
            var regs: X8664Registers = undefined;
            try posix.ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
            try regs.set(allocator, reg_name, value);
            try posix.ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
        },
        else => return error.UnsupportedArchitecture,
    }
}

// Step back (PC - 1).
pub fn resetPC(allocator: std.mem.Allocator, pid: posix.pid_t) !usize {
    const pc = try readRegister(allocator, pid, "pc") - 1;
    try writeRegister(allocator, pid, "pc", pc);
    return pc;
}

pub fn continueExec(allocator: std.mem.Allocator, pid: posix.pid_t) !WaitStatus {
    try posix.ptrace(PTRACE.CONT, pid, 0, 0);
    const status = wait(pid);
    _ = try resetPC(allocator, pid);
    return status;
}

pub fn singleStep(pid: posix.pid_t) !WaitStatus {
    try posix.ptrace(PTRACE.SINGLESTEP, pid, 0, 0);
    return wait(pid);
}

pub fn startTracing(file_path: []const u8, file_args: [*:null]const ?[*:0]const u8) !posix.pid_t {
    const pid = try posix.fork();
    if (pid == 0) {
        // _ = c.personality(c.ADDR_NO_RANDOMIZE);
        try posix.ptrace(PTRACE.TRACEME, pid, 0, 0);
        const posix_file_path = try posix.toPosixPath(file_path);

        posix.execveZ(
            &posix_file_path,
            file_args,
            @ptrCast(std.os.environ.ptr),
        ) catch @panic("Failed to execute the program.");
    }

    const status = try wait(pid);
    switch (status) {
        .SignalTrap => {},
        else => return error.NotSignalTrap,
    }
    try killOnExit(pid);
    return pid;
}
