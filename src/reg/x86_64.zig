const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../common.zig").stdout;

// Reference: https://en.wikipedia.org/wiki/FLAGS_register
const EFLAGS_CF: u64 = @intCast(1 << 0); // Carry Flag
const EFLAGS_PF: u64 = @intCast(1 << 2); // Parity Flag
const EFLAGS_AF: u64 = @intCast(1 << 4); // Auxiliary Carry Flag
const EFLAGS_ZF: u64 = @intCast(1 << 6); // Zero Flag
const EFLAGS_SF: u64 = @intCast(1 << 7); // Sign Flag
const EFLAGS_TF: u64 = @intCast(1 << 8); // Trap Flag
const EFLAGS_IF: u64 = @intCast(1 << 9); // Interrupt Enable Flag
const EFLAGS_DF: u64 = @intCast(1 << 10); // Direction Flag
const EFLAGS_OF: u64 = @intCast(1 << 11); // Overflow Flag
const EFLAGS_IOPL: u64 = @intCast(0b11 << 12); // I/O Privilege Level
const EFLAGS_NT: u64 = @intCast(1 << 14); // Nested Task Flag
const EFLAGS_RF: u64 = @intCast(1 << 15); // Resume Flag
const EFLAGS_VM: u64 = @intCast(1 << 16); // Virtual 8086 Mode
const EFLAGS_AC: u64 = @intCast(1 << 18); // Alignment Check
const EFLAGS_VIF: u64 = @intCast(1 << 19); // Virtual Interrupt Flag
const EFLAGS_VIP: u64 = @intCast(1 << 20); // Virtual Interrupt Pending
const EFLAGS_ID: u64 = @intCast(1 << 21); // ID Flag

fn getFlag(eflags: u64, target_flag: u64) u8 {
    if ((eflags & target_flag) == 0) {
        return 0;
    } else {
        return 1;
    }
}

fn setFlag(eflags: *u64, target_flag: u64, value: u8) void {
    if (value != 0) {
        // Set flag
        eflags.* |= target_flag;
    } else {
        // Clear flag
        eflags.* &= ~target_flag;
    }
}

// This needs to be compatible with `ptrace`.
// WARNING: *Don't add other fields.
// Reference: 'user_regs_struct' in '/usr/include/x86_64-linux-gnu/sys/user.h'
// pub const X8664Registers = c.user_regs_struct;
pub const X8664Registers = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const allocator = std.heap.page_allocator;
        var cham = chameleon.initRuntime(.{ .allocator = allocator });
        defer cham.deinit();

        const str_generals = try std.fmt.allocPrint(allocator,
            \\{s} {s} {s} {s} {s} {s}
            \\{s} {s} {s} {s} {s} {s}
            \\{s} {s} {s} {s} {s} {s}
            \\{s} {s} {s} {s} {s} {s}
            \\{s} {s} {s} {s}
        , .{
            try cham.yellow().fmt("RAX", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rax}),
            try cham.yellow().fmt("RBX", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rbx}),
            try cham.yellow().fmt("RCX", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rcx}),
            try cham.yellow().fmt("RDX", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rdx}),
            try cham.yellow().fmt("R11", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.r11}),
            try cham.yellow().fmt("R12", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.r12}),
            try cham.yellow().fmt("R13", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.r13}),
            try cham.yellow().fmt("R14", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.r14}),
            try cham.yellow().fmt("R15", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.r15}),
            try cham.yellow().fmt("RSI", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rsi}),
            try cham.yellow().fmt("RDI", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rdi}),
            try cham.yellow().fmt("RBP", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rbp}),
            try cham.yellow().fmt("RSP", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rsp}),
            try cham.yellow().fmt("RIP", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.rip}),
        });

        const str_segs = try std.fmt.allocPrint(allocator,
            \\{s} {s} {s} {s} {s} {s}
            \\{s} {s} {s} {s} {s} {s}
        , .{
            try cham.yellow().fmt("CS", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.cs}),
            try cham.yellow().fmt("DS", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.ds}),
            try cham.yellow().fmt("ES", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.es}),
            try cham.yellow().fmt("FS", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.fs}),
            try cham.yellow().fmt("GS", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.gs}),
            try cham.yellow().fmt("SS", .{}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.ss}),
        });

        const str_eflags_keys = try cham.yellow().fmt("CF PF AF ZF SF TF IF DF OF IOPL NT RF VM AC VIF VIP ID", .{});
        const str_eflags_values = try cham.greenBright().fmt(
            " {d}  {d}  {d}  {d}  {d}  {d}  {d}  {d}  {d}    {d}  {d}  {d}  {d}  {d}   {d}   {d}  {d}",
            .{
                getFlag(self.eflags, EFLAGS_CF),
                getFlag(self.eflags, EFLAGS_PF),
                getFlag(self.eflags, EFLAGS_AF),
                getFlag(self.eflags, EFLAGS_ZF),
                getFlag(self.eflags, EFLAGS_SF),
                getFlag(self.eflags, EFLAGS_TF),
                getFlag(self.eflags, EFLAGS_IF),
                getFlag(self.eflags, EFLAGS_DF),
                getFlag(self.eflags, EFLAGS_OF),
                getFlag(self.eflags, EFLAGS_IOPL),
                getFlag(self.eflags, EFLAGS_NT),
                getFlag(self.eflags, EFLAGS_RF),
                getFlag(self.eflags, EFLAGS_VM),
                getFlag(self.eflags, EFLAGS_AC),
                getFlag(self.eflags, EFLAGS_VIF),
                getFlag(self.eflags, EFLAGS_VIP),
                getFlag(self.eflags, EFLAGS_ID),
            },
        );

        return writer.print(
            \\{s}
            \\
            \\{s}
            \\
            \\{s}
            \\{s}
        , .{
            str_generals,
            str_segs,
            str_eflags_keys,
            str_eflags_values,
        });
    }

    pub fn get(self: Self, reg: []const u8) !usize {
        const allocator = std.heap.page_allocator;
        const buf = try allocator.alloc(u8, reg.len);
        defer allocator.free(buf);
        const reg_lower = std.ascii.lowerString(buf, reg);

        if (std.mem.eql(u8, reg_lower, "rax")) {
            return self.rax;
        } else if (std.mem.eql(u8, reg_lower, "rbx")) {
            return self.rbx;
        } else if (std.mem.eql(u8, reg_lower, "rcx")) {
            return self.rcx;
        } else if (std.mem.eql(u8, reg_lower, "rdx")) {
            return self.rdx;
        } else if (std.mem.eql(u8, reg_lower, "r11")) {
            return self.r11;
        } else if (std.mem.eql(u8, reg_lower, "r12")) {
            return self.r12;
        } else if (std.mem.eql(u8, reg_lower, "r13")) {
            return self.r13;
        } else if (std.mem.eql(u8, reg_lower, "r14")) {
            return self.r14;
        } else if (std.mem.eql(u8, reg_lower, "r15")) {
            return self.r15;
        } else if (std.mem.eql(u8, reg_lower, "rsi")) {
            return self.rsi;
        } else if (std.mem.eql(u8, reg_lower, "rdi")) {
            return self.rdi;
        } else if (std.mem.eql(u8, reg_lower, "rbp")) {
            return self.rbp;
        } else if (std.mem.eql(u8, reg_lower, "rsp")) {
            return self.rsp;
        } else if (std.mem.eql(u8, reg_lower, "rip") or std.mem.eql(u8, reg_lower, "pc")) {
            return self.rip;
        } else if (std.mem.eql(u8, reg_lower, "cs")) {
            return self.cs;
        } else if (std.mem.eql(u8, reg_lower, "ds")) {
            return self.ds;
        } else if (std.mem.eql(u8, reg_lower, "es")) {
            return self.es;
        } else if (std.mem.eql(u8, reg_lower, "fs")) {
            return self.fs;
        } else if (std.mem.eql(u8, reg_lower, "gs")) {
            return self.gs;
        } else if (std.mem.eql(u8, reg_lower, "ss")) {
            return self.ss;
        } else if (std.mem.eql(u8, reg_lower, "cf")) {
            return getFlag(self.eflags, EFLAGS_CF);
        } else if (std.mem.eql(u8, reg_lower, "pf")) {
            return getFlag(self.eflags, EFLAGS_PF);
        } else if (std.mem.eql(u8, reg_lower, "af")) {
            return getFlag(self.eflags, EFLAGS_AF);
        } else if (std.mem.eql(u8, reg_lower, "zf")) {
            return getFlag(self.eflags, EFLAGS_ZF);
        } else if (std.mem.eql(u8, reg_lower, "sf")) {
            return getFlag(self.eflags, EFLAGS_SF);
        } else if (std.mem.eql(u8, reg_lower, "tf")) {
            return getFlag(self.eflags, EFLAGS_TF);
        } else if (std.mem.eql(u8, reg_lower, "if")) {
            return getFlag(self.eflags, EFLAGS_IF);
        } else if (std.mem.eql(u8, reg_lower, "df")) {
            return getFlag(self.eflags, EFLAGS_DF);
        } else if (std.mem.eql(u8, reg_lower, "of")) {
            return getFlag(self.eflags, EFLAGS_OF);
        } else if (std.mem.eql(u8, reg_lower, "iopl")) {
            return getFlag(self.eflags, EFLAGS_IOPL);
        } else if (std.mem.eql(u8, reg_lower, "nt")) {
            return getFlag(self.eflags, EFLAGS_NT);
        } else if (std.mem.eql(u8, reg_lower, "rf")) {
            return getFlag(self.eflags, EFLAGS_RF);
        } else if (std.mem.eql(u8, reg_lower, "vm")) {
            return getFlag(self.eflags, EFLAGS_VM);
        } else if (std.mem.eql(u8, reg_lower, "ac")) {
            return getFlag(self.eflags, EFLAGS_AC);
        } else if (std.mem.eql(u8, reg_lower, "vif")) {
            return getFlag(self.eflags, EFLAGS_VIF);
        } else if (std.mem.eql(u8, reg_lower, "vip")) {
            return getFlag(self.eflags, EFLAGS_VIP);
        } else if (std.mem.eql(u8, reg_lower, "id")) {
            return getFlag(self.eflags, EFLAGS_ID);
        } else {
            return error.InvalidRegisterName;
        }
    }

    pub fn set(self: *Self, reg: []const u8, value: usize) !void {
        const allocator = std.heap.page_allocator;
        const buf = try allocator.alloc(u8, reg.len);
        defer allocator.free(buf);
        const reg_lower = std.ascii.lowerString(buf, reg);

        if (std.mem.eql(u8, reg_lower, "rax")) {
            self.rax = value;
        } else if (std.mem.eql(u8, reg_lower, "rbx")) {
            self.rbx = value;
        } else if (std.mem.eql(u8, reg_lower, "rcx")) {
            self.rcx = value;
        } else if (std.mem.eql(u8, reg_lower, "rdx")) {
            self.rdx = value;
        } else if (std.mem.eql(u8, reg_lower, "r11")) {
            self.r11 = value;
        } else if (std.mem.eql(u8, reg_lower, "r12")) {
            self.r12 = value;
        } else if (std.mem.eql(u8, reg_lower, "r13")) {
            self.r13 = value;
        } else if (std.mem.eql(u8, reg_lower, "r14")) {
            self.r14 = value;
        } else if (std.mem.eql(u8, reg_lower, "r15")) {
            self.r15 = value;
        } else if (std.mem.eql(u8, reg_lower, "rsi")) {
            self.rsi = value;
        } else if (std.mem.eql(u8, reg_lower, "rdi")) {
            self.rdi = value;
        } else if (std.mem.eql(u8, reg_lower, "rbp")) {
            self.rbp = value;
        } else if (std.mem.eql(u8, reg_lower, "rsp")) {
            self.rsp = value;
        } else if (std.mem.eql(u8, reg_lower, "rip") or std.mem.eql(u8, reg_lower, "pc")) {
            self.rip = value;
        } else if (std.mem.eql(u8, reg_lower, "cs")) {
            self.cs = value;
        } else if (std.mem.eql(u8, reg_lower, "ds")) {
            self.ds = value;
        } else if (std.mem.eql(u8, reg_lower, "es")) {
            self.es = value;
        } else if (std.mem.eql(u8, reg_lower, "fs")) {
            self.fs = value;
        } else if (std.mem.eql(u8, reg_lower, "gs")) {
            self.gs = value;
        } else if (std.mem.eql(u8, reg_lower, "ss")) {
            self.ss = value;
        } else if (std.mem.eql(u8, reg_lower, "cf")) {
            return setFlag(&self.eflags, EFLAGS_CF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "pf")) {
            return setFlag(&self.eflags, EFLAGS_PF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "af")) {
            return setFlag(&self.eflags, EFLAGS_AF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "zf")) {
            return setFlag(&self.eflags, EFLAGS_ZF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "sf")) {
            return setFlag(&self.eflags, EFLAGS_SF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "tf")) {
            return setFlag(&self.eflags, EFLAGS_TF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "if")) {
            return setFlag(&self.eflags, EFLAGS_IF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "df")) {
            return setFlag(&self.eflags, EFLAGS_DF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "of")) {
            return setFlag(&self.eflags, EFLAGS_OF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "iopl")) {
            return setFlag(&self.eflags, EFLAGS_IOPL, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "nt")) {
            return setFlag(&self.eflags, EFLAGS_NT, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "rf")) {
            return setFlag(&self.eflags, EFLAGS_RF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "vm")) {
            return setFlag(&self.eflags, EFLAGS_VM, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "ac")) {
            return setFlag(&self.eflags, EFLAGS_AC, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "vif")) {
            return setFlag(&self.eflags, EFLAGS_VIF, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "vip")) {
            return setFlag(&self.eflags, EFLAGS_VIP, @intCast(value));
        } else if (std.mem.eql(u8, reg_lower, "id")) {
            return setFlag(&self.eflags, EFLAGS_ID, @intCast(value));
        } else {
            return error.InvalidRegisterName;
        }
    }
};
