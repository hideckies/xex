const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("./common.zig").stdout;
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
                const image_file_header_size = @sizeOf(u16) * 4 + @sizeOf(u32) * 3; // See the IMAGE_FILE_HEADER struct
                try reader.skipBytes(image_file_header_size, .{});

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
    allocator: std.mem.Allocator,
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
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
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

    pub fn init(allocator: std.mem.Allocator, file_buf: []const u8) !Self {
        var self = Self{
            .allocator = allocator,
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
            defer allocator.free(buf);
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
            defer allocator.free(buf);
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
            defer allocator.free(buf);
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
            defer allocator.free(buf);
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
            defer allocator.free(buf);
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
            defer allocator.free(buf);
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
            defer allocator.free(buf);
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
            defer allocator.free(buf);
            const str = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            self.sha3_512 = try allocator.dupe(u8, str);
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.md5);
        self.allocator.free(self.sha1);
        self.allocator.free(self.sha2_256);
        self.allocator.free(self.sha2_384);
        self.allocator.free(self.sha2_512);
        self.allocator.free(self.sha3_256);
        self.allocator.free(self.sha3_384);
        self.allocator.free(self.sha3_512);
    }
};

pub const File = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    args: ?[*:null]const ?[*:0]const u8, // it is used for passing arguments to execveZ
    buf: []const u8,
    type_: FileType,
    hash: FileHash,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, path: []const u8, args: ?[*:null]const ?[*:0]const u8) !Self {
        // Get absolute path.
        const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd_path);
        const path_abs = try std.fs.path.resolve(
            allocator,
            &.{
                cwd_path,
                path,
            },
        );
        defer allocator.free(path_abs);

        const file = try std.fs.cwd().openFile(path_abs, .{});
        defer file.close();
        const reader = file.reader();
        const file_size = try file.getEndPos();
        const file_buf = try file.readToEndAlloc(allocator, file_size);
        defer allocator.free(file_buf);

        return Self{
            .allocator = allocator,
            .path = try allocator.dupe(u8, path_abs),
            .args = args,
            .buf = try allocator.dupe(u8, file_buf),
            .type_ = try FileType.detect(reader),
            .hash = try FileHash.init(allocator, file_buf),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.path);
        self.allocator.free(self.buf);

        self.hash.deinit();
    }
};
