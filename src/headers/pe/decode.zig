// Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

pub const MAGIC_MZ = [_]u8{ 'M', 'Z' };
pub const MAGIC_PE = [_]u8{ 'P', 'E', 0, 0 };

const std = @import("std");
const stdout = @import("stdout");

pub const BitType = enum {
    bit32,
    bit64,
};

pub const Bit = struct {
    bit_type: BitType,
    str: []const u8,

    const Self = @This();

    // value: MAGIC in IMAGE_OPTIONAL_HEADER
    pub fn parse(value: u8) !Self {
        switch (value) {
            0x010b => return Self{ .bit_type = BitType.bit32, .str = "32-bit" },
            0x020b => return Self{ .bit_type = BitType.bit64, .str = "64-bit" },
            else => return error.InvalidBitType,
        }
    }
};

// Reference: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
pub const MachineType = enum {
    intel_itanium,
    x86,
    x86_64,
    unknown,
};

pub const Machine = struct {
    machine_type: MachineType,
    str: []const u8,

    const Self = @This();

    // value: Machine in IMAGE_FILE_HEADER
    pub fn parse(value: u16) !Self {
        switch (value) {
            0x014c => return Self{ .machine_type = MachineType.x86, .str = "x86" },
            0x0200 => return Self{ .machine_type = MachineType.intel_itanium, .str = "Intel Itanium" },
            0x8664 => return Self{ .machine_type = MachineType.x86_64, .str = "x86-64" },
            else => return Self{ .machine_type = MachineType.unknown, .str = "Unknown" },
        }
    }
};

// Characteristics of IMAGE_FILE_HEADER
pub const IFCharType = enum {
    image_file_relocs_stripped,
    image_file_executable_image,
    image_file_line_nums_stripped,
    image_file_local_syms_stripped,
    image_file_aggresive_ws_trim,
    image_file_large_address_aware,
    image_file_bytes_reversed_lo,
    image_file_32bit_machine,
    image_file_debug_stripped,
    image_file_removable_run_from_swap,
    image_file_net_run_from_swap,
    image_file_system,
    image_file_dll,
    image_file_up_system_only,
    image_file_bytes_reversed_hi,
    image_file_unknown,
};

pub const IFChars = struct {
    str: []const u8,

    const Self = @This();

    // value: Characteristics in IMAGE_FILE_HEADER
    pub fn parse(value: u16) !Self {
        switch (value) {
            0x0001 => return Self{ .str = "RELOCS_STRIPPED" },
            0x0002 => return Self{ .str = "EXECUTABLE" },
            0x0004 => return Self{ .str = "LINE_NUMS_STRIPPED" },
            0x0008 => return Self{ .str = "LOCAL_SYMS_STRIPPED" },
            0x0010 => return Self{ .str = "AGGRESIVE_WS_TRIM" },
            0x0020 => return Self{ .str = "LARGE_ADDRESS_AWARE" },
            0x0022 => return Self{ .str = "EXECUTABLE LARGE_ADDRESS_AWARE" },
            0x0080 => return Self{ .str = "BYTES_REVERSED_LO" },
            0x0100 => return Self{ .str = "32BIT_MACHINE" },
            0x0200 => return Self{ .str = "DEBUG_STRIPPED" },
            0x0300 => return Self{ .str = "32BIT_MACHINE DEBUG_STRIPPED" },
            0x0400 => return Self{ .str = "REMOVABLE_RUN_FROM_SWAP" },
            0x0800 => return Self{ .str = "NET_RUN_FROM_SWAP" },
            0x1000 => return Self{ .str = "SYSTEM" },
            0x2000 => return Self{ .str = "DLL" },
            0x2002 => return Self{ .str = "EXECUTABLE DLL" },
            0x2020 => return Self{ .str = "LARGE_ADDRESS_AWARE DLL" },
            0x2022 => return Self{ .str = "EXECUTABLE LARGE_ADDRESS_AWARE DLL" },
            0x4000 => return Self{ .str = "UP_SYSTEM_ONLY" },
            0x8000 => return Self{ .str = "BYTES_REVERSED_HI" },
            else => return Self{ .str = "" },
        }
    }
};

pub const ISCharType = enum {
    image_scn_type_no_pad,
    image_scn_cnt_code,
    image_scn_cnt_initialized_data,
    image_scn_cnt_uninitialized_data,
    image_scn_lnk_other,
    image_scn_lnk_info,
    image_scn_lnk_remove,
    image_scn_lnk_comdat,
    image_scn_no_defer_spec_exc,
    image_scn_gprel,
    image_scn_mem_purgeable,
    image_scn_mem_locked,
    image_scn_mem_preload,
    image_scn_align_1bytes,
    image_scn_align_2bytes,
    image_scn_align_4bytes,
    image_scn_align_8bytes,
    image_scn_align_16bytes,
    image_scn_align_32bytes,
    image_scn_align_64bytes,
    image_scn_align_128bytes,
    image_scn_align_256bytes,
    image_scn_align_512bytes,
    image_scn_align_1024bytes,
    image_scn_align_2048bytes,
    image_scn_align_4096bytes,
    image_scn_align_8192bytes,
    image_scn_lnk_nreloc_ovfl,
    image_scn_mem_discardable,
    image_scn_mem_not_cached,
    image_scn_mem_not_paged,
    image_scn_mem_shared,
    image_scn_mem_execute,
    image_scn_mem_read,
    image_scn_mem_write,
};

pub const ISChars = struct {
    str: []const u8,

    const Self = @This();

    pub fn parse(value: u32) !Self {
        switch (value) {
            0x00000008 => return Self{ .str = "NO_PAD" },
            0x00000020 => return Self{ .str = "EXECUTABLE" },
            0x00000040 => return Self{ .str = "INITIALIZED" },
            0x00000080 => return Self{ .str = "UNINITIALIZED" },
            0x00000200 => return Self{ .str = "LNK_INFO" },
            0x00000800 => return Self{ .str = "LNK_REMOVE" },
            0x00001000 => return Self{ .str = "LNK_COMDAT" },
            0x00004000 => return Self{ .str = "NO_DEFER_SPEC_EXC" },
            0x00008000 => return Self{ .str = "GLOBAL_PTR" },
            0x00100000 => return Self{ .str = "ALIGN_1" },
            0x00200000 => return Self{ .str = "ALIGN_2" },
            0x00300000 => return Self{ .str = "ALIGN_4" },
            0x00400000 => return Self{ .str = "ALIGN_8" },
            0x00500000 => return Self{ .str = "ALIGN_16" },
            0x00600000 => return Self{ .str = "ALIGN_32" },
            0x00700000 => return Self{ .str = "ALIGN_64" },
            0x00800000 => return Self{ .str = "ALIGN_128" },
            0x00900000 => return Self{ .str = "ALIGN_256" },
            0x00A00000 => return Self{ .str = "ALIGN_512" },
            0x00B00000 => return Self{ .str = "ALIGN_1024" },
            0x00C00000 => return Self{ .str = "ALIGN_2048" },
            0x00D00000 => return Self{ .str = "ALIGN_4096" },
            0x00E00000 => return Self{ .str = "ALIGN_8192" },
            0x01000000 => return Self{ .str = "LNK_NRELOC_OVFL" },
            0x02000000 => return Self{ .str = "DISCARDABLE" },
            0x04000000 => return Self{ .str = "NOT_CACHED" },
            0x08000000 => return Self{ .str = "NOT_PAGED" },
            0x10000000 => return Self{ .str = "SHARED" },
            0x20000000 => return Self{ .str = "EXECUTE" },
            0x20000020 => return Self{ .str = "EXECUTABLE EXECUTE" },
            0x40000000 => return Self{ .str = "READ" },
            0x40000020 => return Self{ .str = "EXECUTABLE READ" },
            0x40000040 => return Self{ .str = "INITIALIZED READ" },
            0x42000040 => return Self{ .str = "INITIALIZED DISCARDABLE READ" },
            0x60000000 => return Self{ .str = "EXECUTE READ" },
            0x60000020 => return Self{ .str = "EXECUTABLE EXECUTE READ" },
            0x60000040 => return Self{ .str = "INITIALIZED EXECUTE READ" },
            0x62000040 => return Self{ .str = "INITIALIZED DISCARDABLE EXECUTE READ" },
            0x80000000 => return Self{ .str = "WRITE" },
            0x80000020 => return Self{ .str = "EXECUTABLE WRITE" },
            0x80000040 => return Self{ .str = "INITIALIZED WRITE" },
            0x82000040 => return Self{ .str = "INITIALIZED DISCARDABLE WRITE" },
            0xA0000000 => return Self{ .str = "EXECUTE WRITE" },
            0xA0000020 => return Self{ .str = "EXECUTABLE EXECUTE WRITE" },
            0xA0000040 => return Self{ .str = "INITIALIZED EXECUTE WRITE" },
            0xA2000020 => return Self{ .str = "EXECUTABLE DISCARDABLE EXECUTE WRITE" },
            0xA2000040 => return Self{ .str = "INITIALIZED DISCARDABLE EXECUTE WRITE" },
            0xC0000000 => return Self{ .str = "READ WRITE" },
            0xC0000020 => return Self{ .str = "EXECUTABLE READ WRITE" },
            0xC0000040 => return Self{ .str = "INITIALIZED READ WRITE" },
            0xC2000040 => return Self{ .str = "INITIALIZED DISCARDABLE READ WRITE" },
            0xE0000000 => return Self{ .str = "EXECUTE READ WRITE" },
            0xE0000020 => return Self{ .str = "EXECUTABLE EXECUTE READ WRITE" },
            0xE0000040 => return Self{ .str = "INITIALIZED EXECUTE READ WRITE" },
            0xE2000020 => return Self{ .str = "EXECUTABLE DISCARDABLE EXECUTE READ WRITE" },
            0xE2000040 => return Self{ .str = "INITIALIZED DISCARDABLE EXECUTE READ WRITE" },
            else => return Self{ .str = "" },
        }
    }
};
