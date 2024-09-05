// Reference: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

pub const MAGIC_ELF = [_]u8{ 0x7f, 'E', 'L', 'F' };

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

    // value: e_ident[4] in ELF Header.
    pub fn parse(value: u8) !Self {
        switch (value) {
            1 => return Self{ .bit_type = BitType.bit32, .str = "32-bit" },
            2 => return Self{ .bit_type = BitType.bit64, .str = "64-bit" },
            else => return error.InvalidBitType,
        }
    }
};

pub const Endian = struct {
    endian: std.builtin.Endian,
    str: []const u8,

    const Self = @This();

    // value: e_ident[5] in ELF Header.
    pub fn parse(value: u8) !Self {
        switch (value) {
            1 => return Self{ .endian = .little, .str = "LSB" },
            2 => return Self{ .endian = .big, .str = "MSB" },
            else => return error.InvalidEndian,
        }
    }
};

pub const ABIType = enum {
    system_v,
    hp_ux,
    netbsd,
    linux,
    gnu_hurd,
    solaris,
    aix,
    irix,
    freebsd,
    tru64,
    novell_modesto,
    openbsd,
    openvms,
    nonstop_kernel,
    aros,
    fenixos,
    nuxi_cloudabi,
    stratus_technologies_openvos,
    unknown,
};

pub const ABI = struct {
    abi_type: ABIType,
    str: []const u8,

    const Self = @This();

    // value: e_ident[7] in FLF Header.
    pub fn parse(value: u8) !Self {
        switch (value) {
            0x00 => return Self{ .abi_type = ABIType.system_v, .str = "System V" },
            0x01 => return Self{ .abi_type = ABIType.hp_ux, .str = "HP-UX" },
            0x02 => return Self{ .abi_type = ABIType.netbsd, .str = "NetBSD" },
            0x03 => return Self{ .abi_type = ABIType.linux, .str = "Linux" },
            0x04 => return Self{ .abi_type = ABIType.gnu_hurd, .str = "GNU Hurd" },
            0x05 => return Self{ .abi_type = ABIType.solaris, .str = "Solaris" },
            0x06 => return Self{ .abi_type = ABIType.aix, .str = "AIX" },
            0x07 => return Self{ .abi_type = ABIType.irix, .str = "IRIX" },
            0x08 => return Self{ .abi_type = ABIType.freebsd, .str = "FreeBSD" },
            0x09 => return Self{ .abi_type = ABIType.tru64, .str = "Tru64" },
            0x10 => return Self{ .abi_type = ABIType.novell_modesto, .str = "Novell Modesto" },
            0x11 => return Self{ .abi_type = ABIType.openbsd, .str = "OpenBSD" },
            0x12 => return Self{ .abi_type = ABIType.openvms, .str = "OpenVMS" },
            0x13 => return Self{ .abi_type = ABIType.nonstop_kernel, .str = "NonStop Kernel" },
            0x14 => return Self{ .abi_type = ABIType.aros, .str = "AROS" },
            0x15 => return Self{ .abi_type = ABIType.fenixos, .str = "FenixOS" },
            0x16 => return Self{ .abi_type = ABIType.nuxi_cloudabi, .str = "Nuxi CloudABI" },
            0x17 => return Self{ .abi_type = ABIType.stratus_technologies_openvos, .str = "Stratus Technologies OpenVOS" },
            else => return Self{ .abi_type = ABIType.unknown, .str = "Unknown" },
        }
    }
};

pub const ET = enum {
    et_none,
    et_rel,
    et_exec,
    et_dyn,
    et_core,
    et_loos,
    et_hios,
    et_loproc,
    et_hiproc,
    et_unknown,
};

pub const ObjectType = struct {
    et: ET,
    str: []const u8,

    const Self = @This();

    // value: e_type in ELF Header
    pub fn parse(value: u16) !Self {
        switch (value) {
            0x00 => return Self{ .et = ET.et_none, .str = "Unknown" },
            0x01 => return Self{ .et = ET.et_rel, .str = "ET_REL" },
            0x02 => return Self{ .et = ET.et_exec, .str = "Executable" },
            0x03 => return Self{ .et = ET.et_dyn, .str = "Dynamically linked" },
            0x04 => return Self{ .et = ET.et_core, .str = "Core" },
            0xfe00...0xfeff => return Self{ .et = ET.et_hios, .str = "Reserved" },
            0xff00...0xffff => return Self{ .et = ET.et_hiproc, .str = "Reserved" },
            else => return Self{ .et = ET.et_unknown, .str = "Unknown" },
        }
    }
};

pub const MachineType = enum {
    no,
    att_wei_32100,
    sparc,
    x86,
    motorola_68000,
    motorola_88000,
    intel_mcu,
    intel_80860,
    mips,
    ibm_system_370,
    mips_rs3000_le,
    pa_risc,
    intel_80960,
    powerpc,
    powerpc_64bit,
    s390,
    ibm_spu_spc,
    nec_v800,
    fujitsu_fr20,
    trw_rh_32,
    motorola_rce,
    arm,
    digital_alpha,
    superh,
    sparc_version_9,
    siemens_tricore,
    argonaut_risc_core,
    hitachi_h8_300,
    hitachi_h8_300h,
    hitachi_h8s,
    hitachi_h8_500,
    ia_64,
    stanford_mips_x,
    motorola_coldfire,
    motorola_m68hc12,
    fujitsu_mma,
    siemens_pcp,
    sony_ncpu,
    denso_ndr1,
    motorola_starcore,
    toyota_me16,
    stmicroelectronics_st100,
    tinyj,
    amd_x86_64,
    sony_dsp_processor,
    rdp10,
    rdp11,
    siemens_fx66,
    stmicroelectronics_st9_8_16bit,
    stmicroelectronics_st7_8bit,
    motorola_mc68hc16,
    motorola_mc68hc11,
    motorola_mc68hc08,
    motorola_mc68hc05,
    silicon_graphics_svx,
    stmicroelectronics_st19_8bit,
    digital_vax,
    axis_communications_32bit,
    infineon_technologies_32bit,
    element_14_64bit_dsp,
    lsi_logic_16bit_dsp,
    tms320c6000_family,
    mcst_elbrus_e2k,
    arm_64bits,
    zilog_z80,
    risc_v,
    berkeley_packet_filter,
    wdc_65c816,
    loongarch,
    unknown,
};

pub const Machine = struct {
    machine_type: MachineType,
    str: []const u8,

    const Self = @This();

    // value: e_machine in ELF Header.
    pub fn parse(value: u16) !Self {
        switch (value) {
            0x00 => return Self{ .machine_type = MachineType.no, .str = "No specific instruction set" },
            0x01 => return Self{ .machine_type = MachineType.att_wei_32100, .str = "AT&T WE 32100" },
            0x02 => return Self{ .machine_type = MachineType.sparc, .str = "SPARC" },
            0x03 => return Self{ .machine_type = MachineType.x86, .str = "x86" },
            0x04 => return Self{ .machine_type = MachineType.motorola_68000, .str = "Motorola 68000 (M68k)" },
            0x05 => return Self{ .machine_type = MachineType.motorola_88000, .str = "Motorola 88000 (M88k)" },
            0x06 => return Self{ .machine_type = MachineType.intel_mcu, .str = "Intel MCU" },
            0x07 => return Self{ .machine_type = MachineType.intel_80860, .str = "Intel 80860" },
            0x08 => return Self{ .machine_type = MachineType.mips, .str = "MIPS" },
            0x09 => return Self{ .machine_type = MachineType.ibm_system_370, .str = "IBM System/370" },
            0x0a => return Self{ .machine_type = MachineType.mips_rs3000_le, .str = "MIPS RS3000 Little-endian" },
            0x0f => return Self{ .machine_type = MachineType.pa_risc, .str = "Hewlett-Packard PA-RISC" },
            0x13 => return Self{ .machine_type = MachineType.intel_80960, .str = "Intel 80960" },
            0x14 => return Self{ .machine_type = MachineType.powerpc, .str = "PowerPC" },
            0x15 => return Self{ .machine_type = MachineType.powerpc_64bit, .str = "PowerPC (64-bit)" },
            0x16 => return Self{ .machine_type = MachineType.s390, .str = "S390" },
            0x17 => return Self{ .machine_type = MachineType.ibm_spu_spc, .str = "IBM SPU/SPC" },
            0x24 => return Self{ .machine_type = MachineType.nec_v800, .str = "NEC V800" },
            0x25 => return Self{ .machine_type = MachineType.fujitsu_fr20, .str = "Fujitsu FR20" },
            0x26 => return Self{ .machine_type = MachineType.trw_rh_32, .str = "TRW RH-32" },
            0x27 => return Self{ .machine_type = MachineType.motorola_rce, .str = "Motorola RCE" },
            0x28 => return Self{ .machine_type = MachineType.arm, .str = "Arm" },
            0x29 => return Self{ .machine_type = MachineType.digital_alpha, .str = "Digital Alpha" },
            0x2a => return Self{ .machine_type = MachineType.superh, .str = "SuperH" },
            0x2b => return Self{ .machine_type = MachineType.sparc_version_9, .str = "SPARC Version 9" },
            0x2c => return Self{ .machine_type = MachineType.siemens_tricore, .str = "Siemens TriCore embedded processor" },
            0x2d => return Self{ .machine_type = MachineType.argonaut_risc_core, .str = "Argonaut RISC Core" },
            0x2e => return Self{ .machine_type = MachineType.hitachi_h8_300, .str = "Hitachi H8/300" },
            0x2f => return Self{ .machine_type = MachineType.hitachi_h8_300h, .str = "Hitachi H8/300H" },
            0x30 => return Self{ .machine_type = MachineType.hitachi_h8s, .str = "Hitachi H8S" },
            0x31 => return Self{ .machine_type = MachineType.hitachi_h8_500, .str = "Hitachi H8/500" },
            0x32 => return Self{ .machine_type = MachineType.ia_64, .str = "IA-64" },
            0x33 => return Self{ .machine_type = MachineType.stanford_mips_x, .str = "Stanford MIPS-X" },
            0x34 => return Self{ .machine_type = MachineType.motorola_coldfire, .str = "Motorola ColdFire" },
            0x35 => return Self{ .machine_type = MachineType.motorola_m68hc12, .str = "Motorola M68Hc12" },
            0x36 => return Self{ .machine_type = MachineType.fujitsu_mma, .str = "Fujitsu MMA Multimedia Accelerator" },
            0x37 => return Self{ .machine_type = MachineType.siemens_pcp, .str = "Siemens PCP" },
            0x38 => return Self{ .machine_type = MachineType.sony_ncpu, .str = "Sony nCPU embedded RISC processor" },
            0x39 => return Self{ .machine_type = MachineType.denso_ndr1, .str = "Denso NDR1 microprocessor" },
            0x3a => return Self{ .machine_type = MachineType.motorola_starcore, .str = "Motorola Star*Core processor" },
            0x3b => return Self{ .machine_type = MachineType.toyota_me16, .str = "Toyota ME16 processor" },
            0x3c => return Self{ .machine_type = MachineType.stmicroelectronics_st100, .str = "STMicroelectronics ST100 processor" },
            0x3d => return Self{ .machine_type = MachineType.tinyj, .str = "Advanced Logic Corp. TinyJ embedded processor family" },
            0x3e => return Self{ .machine_type = MachineType.amd_x86_64, .str = "AMD x86-64" },
            0x3f => return Self{ .machine_type = MachineType.sony_dsp_processor, .str = "Sony DSP Processor" },
            0x40 => return Self{ .machine_type = MachineType.rdp10, .str = "Digital Equipment Corp. PDP-10" },
            0x41 => return Self{ .machine_type = MachineType.rdp11, .str = "Digital Equipment Corp. PDP-11" },
            0x42 => return Self{ .machine_type = MachineType.siemens_fx66, .str = "Siemens FX66 microcontroller" },
            0x43 => return Self{ .machine_type = MachineType.stmicroelectronics_st9_8_16bit, .str = "STMicroelectronics ST9+ 8/16 bit microcontroller" },
            0x44 => return Self{ .machine_type = MachineType.stmicroelectronics_st7_8bit, .str = "STMicroelectronics ST7 8-bit microcontroller" },
            0x45 => return Self{ .machine_type = MachineType.motorola_mc68hc16, .str = "Motorola MC68HC16 Microcontroller" },
            0x46 => return Self{ .machine_type = MachineType.motorola_mc68hc11, .str = "Motorola MC68HC11 Microcontroller" },
            0x47 => return Self{ .machine_type = MachineType.motorola_mc68hc08, .str = "Motorola MC68HC08 Microcontroller" },
            0x48 => return Self{ .machine_type = MachineType.motorola_mc68hc05, .str = "Motorola MC68HC05 Microcontroller" },
            0x49 => return Self{ .machine_type = MachineType.silicon_graphics_svx, .str = "Silicon Graphics SVx" },
            0x4a => return Self{ .machine_type = MachineType.stmicroelectronics_st19_8bit, .str = "STMicroelectronics ST19 8-bit microcontroller" },
            0x4b => return Self{ .machine_type = MachineType.digital_vax, .str = "Digital VAX" },
            0x4c => return Self{ .machine_type = MachineType.axis_communications_32bit, .str = "Axis Communications 32-bit embedded processor" },
            0x4d => return Self{ .machine_type = MachineType.infineon_technologies_32bit, .str = "Infineon Technologies 32-bit embedded processor" },
            0x4e => return Self{ .machine_type = MachineType.element_14_64bit_dsp, .str = "Element 14 64-bit DSP Processor" },
            0x4f => return Self{ .machine_type = MachineType.lsi_logic_16bit_dsp, .str = "LSI Logic 16-bit DSP Processor" },
            0x8c => return Self{ .machine_type = MachineType.tms320c6000_family, .str = "TMS320C6000 Family" },
            0xaf => return Self{ .machine_type = MachineType.mcst_elbrus_e2k, .str = "MCST Elbrus e2k" },
            0xb7 => return Self{ .machine_type = MachineType.arm_64bits, .str = "Arm 64-bits (Armv8/AArch64)" },
            0xdc => return Self{ .machine_type = MachineType.zilog_z80, .str = "Zilog Z80" },
            0xf3 => return Self{ .machine_type = MachineType.risc_v, .str = "RISC-V" },
            0xf7 => return Self{ .machine_type = MachineType.berkeley_packet_filter, .str = "Berkeley Packet Filter" },
            0x101 => return Self{ .machine_type = MachineType.wdc_65c816, .str = "WDC 65C816" },
            0x102 => return Self{ .machine_type = MachineType.wdc_65c816, .str = "LoongArch" },
            else => return Self{ .machine_type = MachineType.unknown, .str = "Unknown" },
        }
    }
};

pub const Align = enum {
    _2_0,
    _2_1,
    _2_2,
    _2_3,
    _2_4,
    _2_12,
    unknown,
};

pub const HAlign = struct {
    algn: Align,
    str: []const u8,

    const Self = @This();

    // value: p_align in Program Header
    pub fn parse(value: u64) !Self {
        switch (value) {
            0x0001 => return Self{ .algn = Align._2_0, .str = "2**0" },
            0x0002 => return Self{ .algn = Align._2_1, .str = "2**1" },
            0x0004 => return Self{ .algn = Align._2_4, .str = "2**2" },
            0x0008 => return Self{ .algn = Align._2_3, .str = "2**3" },
            0x0010 => return Self{ .algn = Align._2_4, .str = "2**4" },
            0x1000 => return Self{ .algn = Align._2_12, .str = "2**12" },
            else => return Self{ .algn = Align.unknown, .str = "unknown" },
        }
    }
};

pub const PT = enum {
    pt_null,
    pt_load,
    pt_dynamic,
    pt_interp,
    pt_note,
    pt_shlib,
    pt_phdr,
    pt_tls,
    pt_eh_frame,
    pt_stack,
    pt_relro,
    // pt_loos,
    // pt_hios,
    // pt_loproc,
    // pt_hiproc,
    pt_unknown,
};

pub const PHType = struct {
    pt: PT,
    str: []const u8,

    const Self = @This();

    // value: p_type in Program Header
    pub fn parse(value: u32) !Self {
        var buffer: [10]u8 = undefined;
        _ = try std.fmt.bufPrint(&buffer, "0x{x:0>8}", .{value});

        switch (value) {
            0x00000000 => return Self{ .pt = PT.pt_null, .str = "NULL" },
            0x00000001 => return Self{ .pt = PT.pt_load, .str = "LOAD" },
            0x00000002 => return Self{ .pt = PT.pt_dynamic, .str = "DYNAMIC" },
            0x00000003 => return Self{ .pt = PT.pt_interp, .str = "INTERP" },
            0x00000004 => return Self{ .pt = PT.pt_note, .str = "NOTE" },
            0x00000005 => return Self{ .pt = PT.pt_shlib, .str = "SHLIB" },
            0x00000006 => return Self{ .pt = PT.pt_phdr, .str = "PHDR" },
            0x00000007 => return Self{ .pt = PT.pt_tls, .str = "TLS" },
            0x6474e550 => return Self{ .pt = PT.pt_eh_frame, .str = "EH_FRAME" },
            0x6474e551 => return Self{ .pt = PT.pt_stack, .str = "STACK" },
            0x6474e552 => return Self{ .pt = PT.pt_relro, .str = "RELRO" },
            // 0x60000000...0x6fffffff => return Self{ .pt = PT.pt_loos, .str = &buffer },
            // 0x70000000...0x7fffffff => return Self{ .pt = PT.pt_loproc, .str = &buffer },
            else => return Self{ .pt = PT.pt_unknown, .str = &buffer },
        }
    }
};

pub const PF = enum {
    ___,
    __x,
    _w_,
    _wx,
    r__,
    rw_,
    r_x,
    rwx,
    unknown,
};

pub const PHFlags = struct {
    pf: PF,
    str: []const u8,

    const Self = @This();

    // value: p_flags in Program Header
    pub fn parse(value: u32) !Self {
        switch (value) {
            0x0 => return Self{ .pf = PF.___, .str = "---" },
            0x1 => return Self{ .pf = PF.__x, .str = "--x" },
            0x2 => return Self{ .pf = PF._w_, .str = "-w-" },
            0x3 => return Self{ .pf = PF._wx, .str = "--wx" },
            0x4 => return Self{ .pf = PF.r__, .str = "r--" },
            0x5 => return Self{ .pf = PF.r_x, .str = "r-x" },
            0x6 => return Self{ .pf = PF.rw_, .str = "rw-" },
            0x7 => return Self{ .pf = PF.rwx, .str = "rwx" },
            else => return Self{ .pf = PF.unknown, .str = "???" },
        }
    }
};

pub const SHT = enum {
    sht_null,
    sht_progbits,
    sht_symtab,
    sht_strtab,
    sht_rela,
    sht_hash,
    sht_dynamic,
    sht_note,
    sht_nobits,
    sht_rel,
    sht_shlib,
    sht_dynsym,
    sht_init_array,
    sht_fini_array,
    sht_preinit_array,
    sht_group,
    sht_symtab_shdnx,
    sht_num,
    sht_loos,
    sht_unknown,
};

pub const SHType = struct {
    sht: SHT,
    str: []const u8,

    const Self = @This();

    // value: sh_type in Section Header
    pub fn parse(value: u32) !Self {
        switch (value) {
            0x0 => return Self{ .sht = SHT.sht_null, .str = "NULL" },
            0x1 => return Self{ .sht = SHT.sht_progbits, .str = "PROGBITS" },
            0x2 => return Self{ .sht = SHT.sht_symtab, .str = "SYMTAB" },
            0x3 => return Self{ .sht = SHT.sht_strtab, .str = "STRTAB" },
            0x4 => return Self{ .sht = SHT.sht_rela, .str = "RELA" },
            0x5 => return Self{ .sht = SHT.sht_hash, .str = "HASH" },
            0x6 => return Self{ .sht = SHT.sht_dynamic, .str = "DYNAMIC" },
            0x7 => return Self{ .sht = SHT.sht_note, .str = "NOTE" },
            0x8 => return Self{ .sht = SHT.sht_nobits, .str = "NOBITS" },
            0x9 => return Self{ .sht = SHT.sht_rel, .str = "REL" },
            0x0a => return Self{ .sht = SHT.sht_shlib, .str = "SHLIB" },
            0x0b => return Self{ .sht = SHT.sht_dynsym, .str = "DYNSYM" },
            0x0e => return Self{ .sht = SHT.sht_init_array, .str = "INIT_ARRAY" },
            0x0f => return Self{ .sht = SHT.sht_fini_array, .str = "FINI_ARRAY" },
            0x10 => return Self{ .sht = SHT.sht_preinit_array, .str = "PREINIT_ARRAY" },
            0x11 => return Self{ .sht = SHT.sht_group, .str = "GROUP" },
            0x12 => return Self{ .sht = SHT.sht_symtab_shdnx, .str = "SYMTAB_SHDNX" },
            0x13 => return Self{ .sht = SHT.sht_num, .str = "NUM" },
            // 0x60000000 => return Self{ .sht = SHT.sht_loos, .str = "LOOS" },
            else => return Self{ .sht = SHT.sht_unknown, .str = "UNKNOWN" },
        }
    }
};

pub const SHF = enum {
    shf_write,
    shf_alloc,
    shf_execinstr,
    shf_merge,
    shf_strings,
    shf_info_link,
    shf_link_order,
    shf_os_nonconforming,
    shf_group,
    shf_tls,
    shf_maskos,
    shf_maskproc,
    shf_ordered,
    shf_exclude,
    shf_unknown,
};

pub const SHFlags = struct {
    // shf: SHF,
    str: []const u8,

    const Self = @This();

    // value: sh_flags in Section Header
    pub fn parse(value: u64) !Self {
        // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        // defer _ = gpa.deinit();
        // const allocator = gpa.allocator();

        // var buffer = std.ArrayList([]const u8).init(allocator);
        // defer buffer.deinit();

        // if ((value & 0x1) != 0) try buffer.append("WRITE");
        // if ((value & 0x2) != 0) try buffer.append("ALLOC");
        // if ((value & 0x4) != 0) try buffer.append("EXECUTE");
        // if ((value & 0x10) != 0) try buffer.append("MERGE");
        // if ((value & 0x20) != 0) try buffer.append("STRINGS");
        // if ((value & 0x40) != 0) try buffer.append("INFO_LINK");
        // if ((value & 0x80) != 0) try buffer.append("LINK_ORDER");
        // if ((value & 0x100) != 0) try buffer.append("OS_NONCONFIRMING");
        // if ((value & 0x200) != 0) try buffer.append("GROUP");
        // if ((value & 0x400) != 0) try buffer.append("TLS");
        // if ((value & 0x0ff00000) != 0) try buffer.append("OS_SPECIFIC");
        // if ((value & 0xf0000000) != 0) try buffer.append("PROCESSOR_SPECIFIC");
        // if ((value & 0x40000000) != 0) try buffer.append("ORDERED");
        // if ((value & 0x80000000) != 0) try buffer.append("EXCLUDE");

        // return Self{
        //     .str = try std.mem.join(
        //         allocator,
        //         ", ",
        //         try allocator.dupe([]const u8, buffer.items),
        //     ),
        // };

        // -----------------------------------------------------------

        // The code above leads memory leak, so hardcode only commonly used items as below.
        switch (value) {
            0x00000000 => return Self{ .str = "" },
            0x00000001 => return Self{ .str = "WRITE" },
            0x00000002 => return Self{ .str = "ALLOC" },
            0x00000003 => return Self{ .str = "WRITE ALLOC" },
            0x00000004 => return Self{ .str = "EXECUTE" },
            0x00000005 => return Self{ .str = "WRITE EXECUTE" },
            0x00000006 => return Self{ .str = "ALLOC EXECUTE" },
            0x00000007 => return Self{ .str = "WRITE ALLOC EXECUTE" },
            0x00000010 => return Self{ .str = "MERGE" },
            0x00000011 => return Self{ .str = "WRITE MERGE" },
            0x00000012 => return Self{ .str = "ALLOC MERGE" },
            0x00000013 => return Self{ .str = "WRITE ALLOC MERGE" },
            0x00000014 => return Self{ .str = "EXECUTE MERGE" },
            0x00000015 => return Self{ .str = "WRITE EXECUTE MERGE" },
            0x00000016 => return Self{ .str = "ALLOC EXECUTE MERGE" },
            0x00000017 => return Self{ .str = "WRITE ALLOC EXECUTE MERGE" },
            0x00000020 => return Self{ .str = "STRINGS" },
            0x00000021 => return Self{ .str = "WRITE STRINGS" },
            0x00000022 => return Self{ .str = "ALLOC STRINGS" },
            0x00000023 => return Self{ .str = "WRITe ALLOC STRINGS" },
            0x00000024 => return Self{ .str = "EXECUTE STRINGS" },
            0x00000025 => return Self{ .str = "WRITE EXECUTE STRINGS" },
            0x00000026 => return Self{ .str = "ALLOC EXECUTE STRINGS" },
            0x00000027 => return Self{ .str = "WRITE ALLOC EXECUTE STRINGS" },
            0x00000030 => return Self{ .str = "MERGE STRINGS" },
            0x00000031 => return Self{ .str = "WRITE MERGE STRINGS" },
            0x00000032 => return Self{ .str = "ALLOC MERGE STRINGS" },
            0x00000033 => return Self{ .str = "WRITE ALLOC MERGE STRINGS" },
            0x00000042 => return Self{ .str = "ALLOC INFO" },
            0x00000080 => return Self{ .str = "LINK" },
            0x00000081 => return Self{ .str = "WRITE LINK" },
            0x00000082 => return Self{ .str = "ALLOC LINK" },
            0x00000083 => return Self{ .str = "WRITE ALLOC LINK" },
            0x00000084 => return Self{ .str = "EXECUTE LINK" },
            0x00000100 => return Self{ .str = "OS_NONCONFIRMING" },
            0x00000200 => return Self{ .str = "GROUP" },
            0x00000300 => return Self{ .str = "OS_NONCONFIRMING GROUP" },
            0x00000400 => return Self{ .str = "TLS" },
            0x0ff00000 => return Self{ .str = "OS_SPECIFIC" },
            0xf0000000 => return Self{ .str = "PROCESS_SPECIFIC" },
            0x40000000 => return Self{ .str = "ORDERED" },
            0x80000000 => return Self{ .str = "EXCLUDE" },
            else => return Self{ .str = "" },
        }
    }
};

// Reference: https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
pub const STT = enum {
    stt_notype,
    stt_object,
    stt_func,
    stt_section,
    stt_file,
    stt_common,
    stt_tls,
    stt_loos,
    stt_hios,
    stt_loproc,
    stt_sparc_register,
    stt_hiproc,
    stt_unknown,
};

pub const SymbolType = struct {
    stt: STT,
    str: []const u8,

    const Self = @This();

    // value: st_info in symbol table
    pub fn parse(value: u8) !Self {
        switch (value & 0xf) {
            0x00 => return Self{ .stt = STT.stt_notype, .str = "NOTYPE" },
            0x01 => return Self{ .stt = STT.stt_object, .str = "OBJECT" },
            0x02 => return Self{ .stt = STT.stt_func, .str = "FUNC" },
            0x03 => return Self{ .stt = STT.stt_section, .str = "SECTION" },
            0x04 => return Self{ .stt = STT.stt_file, .str = "FILE" },
            0x05 => return Self{ .stt = STT.stt_common, .str = "COMMON" },
            0x06 => return Self{ .stt = STT.stt_tls, .str = "TLS" },
            // 0x10 => return Self{ .stt = STT.stt_loos, .str = "LOOS" },
            // 0x12 => return Self{ .stt = STT.stt_hios, .str = "HIOS" },
            // 0x13 => return Self{ .stt = STT.stt_loproc, .str = "LOPROC SPARC_REGISTER" },
            // 0x15 => return Self{ .stt = STT.stt_hiproc, .str = "HIPROC" },
            else => return Self{ .stt = STT.stt_unknown, .str = "<UNKNOWN>" },
        }
    }
};
