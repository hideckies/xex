const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../common.zig").stdout;

// Reference: https://en.wikipedia.org/wiki/FLAGS_register
const EFLAGS_CF: u32 = @intCast(1 << 0); // Carry Flag
const EFLAGS_PF: u32 = @intCast(1 << 2); // Parity Flag
const EFLAGS_AF: u32 = @intCast(1 << 4); // Auxiliary Carry Flag
const EFLAGS_ZF: u32 = @intCast(1 << 6); // Zero Flag
const EFLAGS_SF: u32 = @intCast(1 << 7); // Sign Flag
const EFLAGS_TF: u32 = @intCast(1 << 8); // Trap Flag
const EFLAGS_IF: u32 = @intCast(1 << 9); // Interrupt Enable Flag
const EFLAGS_DF: u32 = @intCast(1 << 10); // Direction Flag
const EFLAGS_OF: u32 = @intCast(1 << 11); // Overflow Flag
const EFLAGS_IOPL: u32 = @intCast(0b11 << 12); // I/O Privilege Level
const EFLAGS_NT: u32 = @intCast(1 << 14); // Nested Task Flag
const EFLAGS_RF: u32 = @intCast(1 << 15); // Resume Flag
const EFLAGS_VM: u32 = @intCast(1 << 16); // Virtual 8086 mode
const EFLAGS_AC: u32 = @intCast(1 << 18); // Alignment Check
const EFLAGS_VIF: u32 = @intCast(1 << 19); // Virtual Interrupt Flag
const EFLAGS_VIP: u32 = @intCast(1 << 20); // Virtual Interrupt Pending
const EFLAGS_ID: u32 = @intCast(1 << 21); // ID Flag

fn getFlag(eflags: u32, target_flag: u32) u8 {
    if ((eflags & target_flag) == 0) {
        return 0;
    } else {
        return 1;
    }
}

fn setFlag(eflags: *u34, target_flag: u34, value: u8) void {
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
// pub const X86Registers = c.user_regs_struct;
pub const X86Registers = extern struct {
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
    eax: u32,
    xds: u32,
    xes: u32,
    xfs: u32,
    xgs: u32,
    orig_eax: u32,
    eip: u32,
    xcs: u32,
    eflags: u32,
    esp: u32,
    xss: u32,

    const Self = @This();

    pub fn display(self: Self, allocator: std.mem.Allocator) !void {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        const str_generals = try std.fmt.allocPrint(arena_allocator,
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
        defer arena_allocator.free(str_generals);

        const str_segs = try std.fmt.allocPrint(arena_allocator,
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
        defer arena_allocator.free(str_segs);

        // Due to the max args size (32), devide with two parts.
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
        defer arena_allocator.free(str_eflags_keys);
        defer arena_allocator.free(str_eflags_values);

        try stdout.print("{s}\n\n", .{str_generals});
        try stdout.print("{s}\n\n", .{str_segs});
        try stdout.print("{s}\n\n", .{str_eflags_keys});
        try stdout.print("{s}\n{s}\n", .{ str_eflags_keys, str_eflags_values });
    }

    pub fn get(self: Self, allocator: std.mem.Allocator, reg: []const u8) !usize {
        const buf = try allocator.alloc(u8, reg.len);
        defer allocator.free(buf);
        const reg_lower = std.ascii.lowerString(buf, reg);

        if (std.mem.eql(u8, reg_lower, "eax")) {
            return self.eax;
        } else if (std.mem.eql(u8, reg_lower, "ebx")) {
            return self.ebx;
        } else if (std.mem.eql(u8, reg_lower, "ecx")) {
            return self.ecx;
        } else if (std.mem.eql(u8, reg_lower, "edx")) {
            return self.edx;
        } else if (std.mem.eql(u8, reg_lower, "esi")) {
            return self.esi;
        } else if (std.mem.eql(u8, reg_lower, "edi")) {
            return self.edi;
        } else if (std.mem.eql(u8, reg_lower, "ebp")) {
            return self.ebp;
        } else if (std.mem.eql(u8, reg_lower, "esp")) {
            return self.esp;
        } else if (std.mem.eql(u8, reg_lower, "eip") or std.mem.eql(u8, reg_lower, "pc")) {
            return self.eip;
        } else if (std.mem.eql(u8, reg_lower, "cs")) {
            return self.xcs;
        } else if (std.mem.eql(u8, reg_lower, "ds")) {
            return self.xds;
        } else if (std.mem.eql(u8, reg_lower, "es")) {
            return self.xes;
        } else if (std.mem.eql(u8, reg_lower, "fs")) {
            return self.xfs;
        } else if (std.mem.eql(u8, reg_lower, "gs")) {
            return self.xgs;
        } else if (std.mem.eql(u8, reg_lower, "ss")) {
            return self.xss;
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

    pub fn set(self: *Self, allocator: std.mem.Allocator, reg: []const u8, value: usize) !void {
        const buf = try allocator.alloc(u8, reg.len);
        defer allocator.free(buf);
        const reg_lower = std.ascii.lowerString(buf, reg);

        if (std.mem.eql(u8, reg_lower, "eax")) {
            self.eax = value;
        } else if (std.mem.eql(u8, reg_lower, "ebx")) {
            self.ebx = value;
        } else if (std.mem.eql(u8, reg_lower, "ecx")) {
            self.ecx = value;
        } else if (std.mem.eql(u8, reg_lower, "edx")) {
            self.edx = value;
        } else if (std.mem.eql(u8, reg_lower, "esi")) {
            self.esi = value;
        } else if (std.mem.eql(u8, reg_lower, "edi")) {
            self.edi = value;
        } else if (std.mem.eql(u8, reg_lower, "ebp")) {
            self.ebp = value;
        } else if (std.mem.eql(u8, reg_lower, "esp")) {
            self.esp = value;
        } else if (std.mem.eql(u8, reg_lower, "eip") or std.mem.eql(u8, reg_lower, "pc")) {
            self.eip = value;
        } else if (std.mem.eql(u8, reg_lower, "cs")) {
            self.xcs = value;
        } else if (std.mem.eql(u8, reg_lower, "ds")) {
            self.xds = value;
        } else if (std.mem.eql(u8, reg_lower, "es")) {
            self.xes = value;
        } else if (std.mem.eql(u8, reg_lower, "fs")) {
            self.xfs = value;
        } else if (std.mem.eql(u8, reg_lower, "gs")) {
            self.xgs = value;
        } else if (std.mem.eql(u8, reg_lower, "ss")) {
            self.xss = value;
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
