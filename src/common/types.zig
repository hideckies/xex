const builtin = @import("builtin");
const std = @import("std");

pub const trap_inst_t = switch (builtin.cpu.arch) {
    .x86_64 => u8,
    .aarch64, .aarch64_be => u32,
    else => unreachable,
};

pub const TRAP_INST: trap_inst_t = switch (builtin.cpu.arch) {
    .x86_64 => 0xcc, // "int3"
    .aarch64, .aarch64_be => 0xd420_0000, // "brk #0"
    else => unreachable,
};

pub const TRAP_INST_MASK: usize = ~@as(usize, std.math.maxInt(trap_inst_t));
