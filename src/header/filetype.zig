const std = @import("std");
const elf = @import("./elf/elf.zig");
const pe = @import("./pe/pe.zig");

pub const FileType = enum {
    elf32,
    elf64,
    pe32,
    pe64,
    unknown,

    const Self = @This();

    pub fn init(reader: anytype) !Self {
        const magic = try reader.readBytesNoEof(4);

        if (std.mem.eql(u8, &magic, &elf.decode.MAGIC_ELF)) {
            // ELF
            const e_ident_idx4 = try reader.readBytesNoEof(1);
            if (e_ident_idx4[0] == 1) {
                return FileType.elf32;
            } else if (e_ident_idx4[0] == 2) {
                return FileType.elf64;
            } else {
                return FileType.unknown;
            }
        } else if (std.mem.eql(u8, magic[0..2], &pe.decode.MAGIC_MZ)) {
            // PE
            // Skip until IMAGE_DOS_HEADER.e_lfanew
            try reader.skipBytes(0x3c - 4, .{});
            const e_lfanew = try reader.readInt(i32, .little);
            // Skip until PE Header (IMAGE_NT_HEADERS)
            try reader.skipBytes(@intCast(e_lfanew - 0x3c - 4), .{});

            // Read IMAGE_NT_HEADERS.Signature
            const pe_header_magic = try reader.readBytesNoEof(4);
            if (std.mem.eql(u8, &pe_header_magic, &pe.decode.MAGIC_PE)) {
                // Check for PE32 or PE64

                // Skip IMAGE_NT_HEADERS.FileHeader
                try reader.skipBytes(@sizeOf(pe.common.IMAGE_FILE_HEADER), .{});

                const optional_header_magic = try reader.readInt(u16, .little);
                if (optional_header_magic == 0x010b) {
                    // PE32
                    return FileType.pe32;
                } else if (optional_header_magic == 0x020b) {
                    // PE64
                    return FileType.pe64;
                }
            } else {
                return FileType.unknown;
            }
        } else {
            return FileType.unknown;
        }

        return FileType.unknown;
    }
};
