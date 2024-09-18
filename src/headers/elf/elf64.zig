const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../../common.zig").stdout;
const util = @import("../../common.zig").util;

const decode = @import("./decode.zig");
const MultiEntriesString = @import("../fmt.zig").MultiEntriesString;

// Reference: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
pub const ELFHeader64 = struct {
    allocator: std.mem.Allocator,

    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        const fmt_e_ident =
            \\  Magic   {s}
            \\  Class                               {s}
            \\  Version                             {s}
            \\  OS/ABI                              {s}
            \\  ABI Version                         {s}
        ;
        const str_e_ident = try std.fmt.allocPrint(arena_allocator, fmt_e_ident, .{
            try cham.greenBright().fmt("{x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
                self.e_ident[0],
                self.e_ident[1],
                self.e_ident[2],
                self.e_ident[3],
                self.e_ident[4],
                self.e_ident[5],
                self.e_ident[6],
                self.e_ident[7],
                self.e_ident[8],
                self.e_ident[9],
                self.e_ident[10],
                self.e_ident[11],
                self.e_ident[12],
                self.e_ident[13],
                self.e_ident[14],
                self.e_ident[15],
            }),
            try cham.magentaBright().fmt("ELF {s}, {s}", .{
                (try decode.Bit.parse(self.e_ident[4])).str,
                (try decode.Endian.parse(self.e_ident[5])).str,
            }),
            try cham.greenBright().fmt("{d}", .{self.e_ident[6]}),
            try cham.magentaBright().fmt("{s}", .{(try decode.ABI.parse(self.e_ident[7])).str}),
            try cham.greenBright().fmt("{d}", .{self.e_ident[8]}),
        });
        defer arena_allocator.free(str_e_ident);

        const str =
            \\{s}
            \\  Type                                {s}
            \\  Machine                             {s}
            \\  Version                             {s}
            \\  Entry point                         {s}
            \\  Offset of program headers           {s}
            \\  Offset of section headers           {s}
            \\  Flags                               {s}
            \\  Size of this header                 {s} (bytes)
            \\  Size of program headers             {s} (bytes)
            \\  Number of program headers           {s}
            \\  Size of section headers             {s} (bytes)
            \\  Number of section headers           {s}
            \\  Section header string table index   {s}
        ;
        return writer.print(str, .{
            str_e_ident,
            try cham.magentaBright().fmt("{s}", .{(try decode.ObjectType.parse(self.e_type)).str}),
            try cham.magentaBright().fmt("{s}", .{(try decode.Machine.parse(self.e_machine)).str}),
            try cham.cyanBright().fmt("0x{x}", .{self.e_version}),
            try cham.cyanBright().fmt("0x{x}", .{self.e_entry}),
            try cham.cyanBright().fmt("0x{x}", .{self.e_phoff}),
            try cham.cyanBright().fmt("0x{x}", .{self.e_shoff}),
            try cham.cyanBright().fmt("0x{x}", .{self.e_flags}),
            try cham.cyanBright().fmt("{d}", .{self.e_ehsize}),
            try cham.cyanBright().fmt("{d}", .{self.e_phentsize}),
            try cham.cyanBright().fmt("{d}", .{self.e_phnum}),
            try cham.cyanBright().fmt("{d}", .{self.e_shentsize}),
            try cham.cyanBright().fmt("{d}", .{self.e_shnum}),
            try cham.cyanBright().fmt("{d}", .{self.e_shstrndx}),
        });
    }
};

// Reference: https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html
pub const ELFProgramHeader64 = struct {
    allocator: std.mem.Allocator,

    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        const str =
            \\{s}:
            \\    flags  {s}
            \\    offset {s} vaddr  {s}
            \\    paddr  {s} filesz {s}
            \\    memsz  {s} align  {s}
        ;
        return writer.print(str, .{
            try cham.yellow().fmt("{s}", .{(try decode.PHType.parse(self.p_type)).str}),
            try cham.magentaBright().fmt("{s}", .{(try decode.PHFlags.parse(self.p_flags)).str}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.p_offset}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.p_vaddr}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.p_paddr}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.p_filesz}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.p_memsz}),
            try cham.blue().fmt("{s}", .{(try decode.HAlign.parse(self.p_align)).str}),
        });
    }
};

// Reference: https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
pub const ELFSectionHeader64 = struct {
    allocator: std.mem.Allocator,

    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,

    sh_name_str: []const u8,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        const str =
            \\{s}:
            \\    type  {s}
            \\    flags {s}
            \\    addr  {s} offset  {s}
            \\    size  {s} entsize {s}
            \\    link  {s}
            \\    info  {s}
            \\    align {s}
        ;

        return writer.print(str, .{
            try cham.yellow().fmt("{s}", .{self.sh_name_str}),
            try cham.blueBright().fmt("{s}", .{(try decode.SHType.parse(self.sh_type)).str}),
            try cham.blueBright().fmt("{s}", .{(try decode.SHFlags.parse(self.sh_flags)).str}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.sh_addr}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.sh_offset}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.sh_size}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.sh_entsize}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.sh_link}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.sh_info}),
            try cham.magentaBright().fmt("{s}", .{(try decode.HAlign.parse(self.sh_addralign)).str}),
        });
    }
};

// Reference: https://docs.oracle.com/cd/E19620-01/805-5821/chapter6-79797/index.html
pub const ELF64_Sym = struct {
    allocator: std.mem.Allocator,

    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,

    st_name_str: []const u8,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        const str =
            \\{s}:
            \\    type  {s}
            \\    other {s} shndx {s}
            \\    value {s} size {s}
        ;
        return writer.print(str, .{
            try cham.yellow().fmt("{s}", .{self.st_name_str}),
            try cham.magentaBright().fmt("{s}", .{(decode.SymbolType.parse(self.st_info)).str}),
            try cham.cyanBright().fmt("0x{x:0>2}", .{self.st_other}),
            try cham.cyanBright().fmt("0x{x:0>4}", .{self.st_shndx}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.st_value}),
            try cham.cyanBright().fmt("0x{x:0>16}", .{self.st_size}),
        });
    }
};

pub const ELFHeaders64 = struct {
    allocator: std.mem.Allocator,
    file_path: []const u8,
    file_header: ELFHeader64,
    program_headers: []ELFProgramHeader64,
    section_headers: []ELFSectionHeader64,
    symbols: []ELF64_Sym,
    dynsymbols: []ELF64_Sym,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var ms_phs = try MultiEntriesString.init(
            self.allocator,
            ELFProgramHeader64,
            self.program_headers,
            "No program headers",
            true,
            0,
        );
        defer ms_phs.deinit();
        const str_phs = ms_phs.str_joined;

        var ms_shs = try MultiEntriesString.init(
            self.allocator,
            ELFSectionHeader64,
            self.section_headers,
            "No section headers",
            true,
            0,
        );
        defer ms_shs.deinit();
        const str_shs = ms_shs.str_joined;

        var ms_symbols = try MultiEntriesString.init(
            self.allocator,
            ELF64_Sym,
            self.symbols,
            "No symbols",
            true,
            0,
        );
        defer ms_symbols.deinit();
        const str_symbols = ms_symbols.str_joined;

        var ms_dynsymbols = try MultiEntriesString.init(
            self.allocator,
            ELF64_Sym,
            self.dynsymbols,
            "No dynamic symbols",
            true,
            0,
        );
        defer ms_dynsymbols.deinit();
        const str_dynsymbols = ms_dynsymbols.str_joined;

        const str =
            \\ELF Header
            \\==========
            \\
            \\{s}
            \\
            \\Program Headers
            \\===============
            \\
            \\{s}
            \\
            \\Sections
            \\========
            \\
            \\{s}
            \\
            \\Symbol Table
            \\============
            \\
            \\{s}
            \\
            \\Dynamic Symbol Table
            \\====================
            \\
            \\{s}
        ;
        return writer.print(str, .{
            self.file_header,
            str_phs,
            str_shs,
            str_symbols,
            str_dynsymbols,
        });
    }

    pub fn printInfo(self: Self) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        var str_exec_or_shared: []const u8 = undefined;
        if (self.file_header.e_entry == 0) {
            str_exec_or_shared = "Shared object";
        } else {
            str_exec_or_shared = "Executable";
        }
        const str = try std.fmt.allocPrint(arena_allocator,
            \\{s: <14}: {s}
            \\{s: <14}: {s}
            \\{s: <14}: {s}
            \\{s: <14}: {s}
            \\{s: <14}: {s}
        , .{
            "File",
            try cham.greenBright().fmt("{s}", .{self.file_path}),
            "File Type",
            try cham.cyanBright().fmt("ELF 64-bit, {s}, {s}, {s}", .{
                str_exec_or_shared,
                (try decode.Endian.parse(self.file_header.e_ident[5])).str,
                (try decode.ObjectType.parse(self.file_header.e_type)).str,
            }),
            "ABI",
            try cham.cyanBright().fmt("{s}", .{(try decode.ABI.parse(self.file_header.e_ident[7])).str}),
            "Architecture",
            try cham.cyanBright().fmt("{s}", .{(try decode.Machine.parse(self.file_header.e_machine)).str}),
            "Start Address",
            try cham.greenBright().fmt("0x{x:0>16}", .{self.file_header.e_entry}),
        });
        defer arena_allocator.free(str);
        try stdout.print("{s}\n", .{str});
    }

    pub fn analyze(allocator: std.mem.Allocator, file_path: []const u8, reader: anytype) !Self {
        const e_ident = [16]u8{
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
            (try reader.readBytesNoEof(1))[0],
        };
        const endian = (try decode.Endian.parse(e_ident[5])).endian;

        const elf_header64 = ELFHeader64{
            .allocator = allocator,
            .e_ident = e_ident,
            .e_type = try reader.readInt(u16, endian),
            .e_machine = try reader.readInt(u16, endian),
            .e_version = try reader.readInt(u32, endian),
            .e_entry = try reader.readInt(u64, endian),
            .e_phoff = try reader.readInt(u64, endian),
            .e_shoff = try reader.readInt(u64, endian),
            .e_flags = try reader.readInt(u32, endian),
            .e_ehsize = try reader.readInt(u16, endian),
            .e_phentsize = try reader.readInt(u16, endian),
            .e_phnum = try reader.readInt(u16, endian),
            .e_shentsize = try reader.readInt(u16, endian),
            .e_shnum = try reader.readInt(u16, endian),
            .e_shstrndx = try reader.readInt(u16, endian),
        };
        // const object_type = try decode.ObjectType.parse(elf_header64.e_type);

        try reader.context.seekTo(elf_header64.e_phoff);

        var program_headers = std.ArrayList(ELFProgramHeader64).init(allocator);
        defer program_headers.deinit();
        for (0..elf_header64.e_phnum) |_| {
            const ph = ELFProgramHeader64{
                .allocator = allocator,
                .p_type = try reader.readInt(u32, endian),
                .p_flags = try reader.readInt(u32, endian),
                .p_offset = try reader.readInt(u64, endian),
                .p_vaddr = try reader.readInt(u64, endian),
                .p_paddr = try reader.readInt(u64, endian),
                .p_filesz = try reader.readInt(u64, endian),
                .p_memsz = try reader.readInt(u64, endian),
                .p_align = try reader.readInt(u64, endian),
            };
            try program_headers.append(ph);
        }

        try reader.context.seekTo(elf_header64.e_shoff);

        var section_headers = std.ArrayList(ELFSectionHeader64).init(allocator);
        defer section_headers.deinit();
        for (0..elf_header64.e_shnum) |_| {
            const sh = ELFSectionHeader64{
                .allocator = allocator,
                .sh_name = try reader.readInt(u32, endian),
                .sh_type = try reader.readInt(u32, endian),
                .sh_flags = try reader.readInt(u64, endian),
                .sh_addr = try reader.readInt(u64, endian),
                .sh_offset = try reader.readInt(u64, endian),
                .sh_size = try reader.readInt(u64, endian),
                .sh_link = try reader.readInt(u32, endian),
                .sh_info = try reader.readInt(u32, endian),
                .sh_addralign = try reader.readInt(u64, endian),
                .sh_entsize = try reader.readInt(u64, endian),
                .sh_name_str = undefined,
            };
            try section_headers.append(sh);
        }

        // Get Section Header String Table (".shstrtab") to decode sections names and symbol names.
        const shstrtab_hdr = section_headers.items[elf_header64.e_shstrndx];
        try reader.context.seekTo(shstrtab_hdr.sh_offset);
        const shstrtab_tmp: []u8 = try allocator.alloc(u8, shstrtab_hdr.sh_size);
        defer allocator.free(shstrtab_tmp);
        _ = try reader.read(shstrtab_tmp);
        // Copy to another variable.
        const shstrtab = try allocator.dupe(u8, shstrtab_tmp);
        defer allocator.free(shstrtab);

        // Get section names
        for (section_headers.items) |*sh| {
            const section_name_start = sh.sh_name;
            if (section_name_start >= shstrtab.len) {
                sh.sh_name_str = try allocator.dupe(u8, "<none>");
                continue;
            }
            const section_name_slice = shstrtab[section_name_start..];
            const section_name_end = std.mem.indexOfScalar(u8, section_name_slice, 0);
            if (section_name_end) |end_idx| {
                if (end_idx == 0) {
                    sh.sh_name_str = try allocator.dupe(u8, "<none>");
                    continue;
                }
                const section_name = section_name_slice[0..end_idx];
                sh.sh_name_str = try allocator.dupe(u8, section_name);
            }
        }

        // Find symbol table, dynamical link symbol table, string table
        var symtab_hdr: ?ELFSectionHeader64 = null;
        var strtab_hdr: ?ELFSectionHeader64 = null;
        var dynsym_hdr: ?ELFSectionHeader64 = null;
        var dynstr_hdr: ?ELFSectionHeader64 = null;
        for (section_headers.items) |sh| {
            const shtype = try decode.SHType.parse(sh.sh_type);
            if (shtype.sht == decode.SHT.sht_symtab) {
                symtab_hdr = sh;
            }
            if (shtype.sht == decode.SHT.sht_strtab) {
                if (std.mem.eql(u8, sh.sh_name_str, ".strtab")) {
                    strtab_hdr = sh;
                } else if (std.mem.eql(u8, sh.sh_name_str, ".dynstr")) {
                    dynstr_hdr = sh;
                }
            }
            if (shtype.sht == decode.SHT.sht_dynsym) {
                dynsym_hdr = sh;
            }
        }
        // Get strtab from strtab_hdr
        var strtab: ?[]u8 = null;
        defer {
            if (strtab) |st| {
                allocator.free(st);
            }
        }
        if (strtab_hdr) |sh| {
            try reader.context.seekTo(sh.sh_offset);
            const strtab_tmp: []u8 = try allocator.alloc(u8, sh.sh_size);
            defer allocator.free(strtab_tmp);
            _ = try reader.read(strtab_tmp);
            strtab = try allocator.dupe(u8, strtab_tmp);
        }
        // Get dynstr from dynstr_hdr
        var dynstr: ?[]u8 = null;
        defer {
            if (dynstr) |ds| {
                allocator.free(ds);
            }
        }
        if (dynstr_hdr) |sh| {
            try reader.context.seekTo(sh.sh_offset);
            const dynstr_tmp: []u8 = try allocator.alloc(u8, sh.sh_size);
            defer allocator.free(dynstr_tmp);
            _ = try reader.read(dynstr_tmp);
            dynstr = try allocator.dupe(u8, dynstr_tmp);
        }

        // Get symbols
        const real_sym_size: usize = @sizeOf(u8) * 2 + @sizeOf(u16) + @sizeOf(u32) + @sizeOf(u64) * 2;
        var symbols = std.ArrayList(ELF64_Sym).init(allocator);
        defer symbols.deinit();
        if (symtab_hdr) |sth| {
            // Seek to the symbol table.
            try reader.context.seekTo(sth.sh_offset);

            const num_symbols = sth.sh_size / real_sym_size;
            for (num_symbols) |_| {
                // const st_name = try reader.readInt(u32, endian);
                var sym = ELF64_Sym{
                    .allocator = allocator,
                    .st_name = try reader.readInt(u32, endian),
                    .st_info = try reader.readInt(u8, endian),
                    .st_other = try reader.readInt(u8, endian),
                    .st_shndx = try reader.readInt(u16, endian),
                    .st_value = try reader.readInt(u64, endian),
                    .st_size = try reader.readInt(u64, endian),
                    .st_name_str = undefined,
                };
                // Get symbol name strings
                if (strtab) |st| {
                    if (sym.st_name != 0) {
                        const symbol_name_slice = st[sym.st_name..];
                        const end_idx = std.mem.indexOfScalar(u8, symbol_name_slice, 0) orelse strtab_hdr.?.sh_size;
                        const symbol_name = symbol_name_slice[0..end_idx];
                        sym.st_name_str = try allocator.dupe(u8, symbol_name);
                    } else {
                        sym.st_name_str = try allocator.dupe(u8, "<none>");
                    }
                } else {
                    sym.st_name_str = try allocator.dupe(u8, "<unknown>");
                }
                try symbols.append(sym);
            }
        }

        // Get dynamic symbols
        var dynsymbols = std.ArrayList(ELF64_Sym).init(allocator);
        defer dynsymbols.deinit();
        if (dynsym_hdr) |dsh| {
            // Seek to the dynamic symbol table.
            try reader.context.seekTo(dsh.sh_offset);

            const num_symbols = dsh.sh_size / real_sym_size;
            for (num_symbols) |_| {
                var sym = ELF64_Sym{
                    .allocator = allocator,
                    .st_name = try reader.readInt(u32, endian),
                    .st_info = try reader.readInt(u8, endian),
                    .st_other = try reader.readInt(u8, endian),
                    .st_shndx = try reader.readInt(u16, endian),
                    .st_value = try reader.readInt(u64, endian),
                    .st_size = try reader.readInt(u64, endian),
                    .st_name_str = undefined,
                };
                // Get symbol name strings
                if (dynstr) |ds| {
                    if (sym.st_name != 0) {
                        const symbol_name_slice = ds[sym.st_name..];
                        const end_idx = std.mem.indexOfScalar(u8, symbol_name_slice, 0) orelse dynstr_hdr.?.sh_size;
                        const symbol_name = symbol_name_slice[0..end_idx];
                        sym.st_name_str = try allocator.dupe(u8, symbol_name);
                    } else {
                        sym.st_name_str = try allocator.dupe(u8, "<none>");
                    }
                } else {
                    sym.st_name_str = try allocator.dupe(u8, "<unknown>");
                }
                try dynsymbols.append(sym);
            }
        }

        return Self{
            .allocator = allocator,
            .file_path = try allocator.dupe(u8, file_path),
            .file_header = elf_header64,
            .program_headers = try program_headers.toOwnedSlice(),
            .section_headers = try section_headers.toOwnedSlice(),
            .symbols = try symbols.toOwnedSlice(),
            .dynsymbols = try dynsymbols.toOwnedSlice(),
        };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.file_path);
        self.allocator.free(self.program_headers);

        for (self.section_headers) |sh| {
            self.allocator.free(sh.sh_name_str);
        }
        self.allocator.free(self.section_headers);

        for (self.symbols) |s| {
            self.allocator.free(s.st_name_str);
        }
        self.allocator.free(self.symbols);

        for (self.dynsymbols) |ds| {
            self.allocator.free(ds.st_name_str);
        }
        self.allocator.free(self.dynsymbols);
    }
};
