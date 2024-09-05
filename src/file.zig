const std = @import("std");
const chameleon = @import("chameleon");
const elf = @import("./headers.zig").elf;
const pe = @import("./headers.zig").pe;

pub const FileType = enum {
    elf32,
    elf64,
    pe32,
    pe64,
    unknown,

    const Self = @This();

    pub fn detect(reader: anytype) !Self {
        try reader.context.seekTo(0);

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

pub const FileHash = struct {
    md5: []u8,
    sha1: []u8,
    sha2_256: []u8,
    sha2_384: []u8,
    sha2_512: []u8,
    sha3_256: []u8,
    sha3_384: []u8,
    sha3_512: []u8,

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

        return writer.print(
            \\{s: <10}: {s}
            \\{s: <10}: {s}
            \\{s: <10}: {s}
            \\{s: <10}: {s}
            \\{s: <10}: {s}
            \\{s: <10}: {s}
            \\{s: <10}: {s}
            \\{s: <10}: {s}
        ,
            .{
                "MD5",
                try cham.cyanBright().fmt("{s}", .{self.md5}),
                "SHA1",
                try cham.cyanBright().fmt("{s}", .{self.sha1}),
                "SHA2-256",
                try cham.cyanBright().fmt("{s}", .{self.sha2_256}),
                "SHA2-384",
                try cham.cyanBright().fmt("{s}", .{self.sha2_384}),
                "SHA2-512",
                try cham.cyanBright().fmt("{s}", .{self.sha2_512}),
                "SHA3-256",
                try cham.cyanBright().fmt("{s}", .{self.sha3_256}),
                "SHA3-384",
                try cham.cyanBright().fmt("{s}", .{self.sha3_384}),
                "SHA3-512",
                try cham.cyanBright().fmt("{s}", .{self.sha3_512}),
            },
        );
    }

    pub fn init(file_buf: []const u8) !Self {
        const allocator = std.heap.page_allocator;

        var self = Self{
            .md5 = undefined,
            .sha1 = undefined,
            .sha2_256 = undefined,
            .sha2_384 = undefined,
            .sha2_512 = undefined,
            .sha3_256 = undefined,
            .sha3_384 = undefined,
            .sha3_512 = undefined,
        };

        {
            // MD5
            var hash_out: [16]u8 = undefined;
            var h = std.crypto.hash.Md5.init(.{});
            h.update(file_buf);
            h.final(&hash_out);
            const buf = try allocator.alloc(u8, 16 * 2);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.md5 = try allocator.dupe(u8, str);
        }
        {
            // SHA1
            var hash_out: [20]u8 = undefined;
            var h = std.crypto.hash.Sha1.init(.{});
            h.update(file_buf);
            h.final(&hash_out);
            const buf = try allocator.alloc(u8, 20 * 2);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.sha1 = try allocator.dupe(u8, str);
        }
        {
            // SHA2-256
            var hash_out: [32]u8 = undefined;
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(file_buf);
            h.final(&hash_out);
            const buf = try allocator.alloc(u8, 32 * 2);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.sha2_256 = try allocator.dupe(u8, str);
        }
        {
            // SHA2-384
            var hash_out: [48]u8 = undefined;
            var h = std.crypto.hash.sha2.Sha384.init(.{});
            h.update(file_buf);
            h.final(&hash_out);
            const buf = try allocator.alloc(u8, 48 * 2);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.sha2_384 = try allocator.dupe(u8, str);
        }
        {
            // SHA2-512
            var hash_out: [64]u8 = undefined;
            var h = std.crypto.hash.sha2.Sha512.init(.{});
            h.update(file_buf);
            h.final(&hash_out);
            const buf = try allocator.alloc(u8, 64 * 2);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.sha2_512 = try allocator.dupe(u8, str);
        }
        {
            // SHA3-256
            var hash_out: [32]u8 = undefined;
            var h = std.crypto.hash.sha3.Sha3_256.init(.{});
            h.update(file_buf);
            h.final(&hash_out);
            const buf = try allocator.alloc(u8, 32 * 2);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.sha3_256 = try allocator.dupe(u8, str);
        }
        {
            // SHA3-384
            var hash_out: [48]u8 = undefined;
            var h = std.crypto.hash.sha3.Sha3_384.init(.{});
            h.update(file_buf);
            h.final(&hash_out);
            const buf = try allocator.alloc(u8, 48 * 2);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.sha3_384 = try allocator.dupe(u8, str);
        }
        {
            // SHA3-512
            var hash_out: [64]u8 = undefined;
            var h = std.crypto.hash.sha3.Sha3_512.init(.{});
            h.update(file_buf);
            h.final(&hash_out);
            const buf = try allocator.alloc(u8, 64 * 2);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.sha3_512 = try allocator.dupe(u8, str);
        }

        return self;
    }
};

pub const File = struct {
    path: []const u8,
    args: ?[*:null]const ?[*:0]const u8, // it is used for passing arguments to execveZ
    buffer: []const u8,
    type_: FileType,
    hash: FileHash,

    const Self = @This();

    pub fn init(path: []const u8, args: ?[*:null]const ?[*:0]const u8) !Self {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        const reader = file.reader();
        const file_size = try file.getEndPos();
        const file_buf = try file.readToEndAlloc(std.heap.page_allocator, file_size);

        return Self{
            .path = path,
            .args = args,
            .buffer = file_buf,
            .type_ = try FileType.detect(reader),
            .hash = try FileHash.init(file_buf),
        };
    }
};
