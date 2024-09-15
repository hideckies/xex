const std = @import("std");
const stdout = @import("./common.zig").stdout;
const FileType = @import("./file.zig").FileType;

pub const elf = @import("./headers/elf/elf.zig");
pub const MultiEntriesString = @import("./headers/fmt.zig").MultiEntriesString;
pub const pe = @import("./headers/pe/pe.zig");

pub const ELFProgramHeader32 = elf.elf32.ELFProgramHeader32;
pub const ELFSectionHeader32 = elf.elf32.ELFSectionHeader32;
pub const ELF32_Sym = elf.elf32.ELF32_Sym;
pub const ELFHeaders32 = elf.elf32.ELFHeaders32;

pub const ELFProgramHeader64 = elf.elf64.ELFProgramHeader64;
pub const ELFSectionHeader64 = elf.elf64.ELFSectionHeader64;
pub const ELF64_Sym = elf.elf64.ELF64_Sym;
pub const ELFHeaders64 = elf.elf64.ELFHeaders64;

pub const IMAGE_SECTION_HEADER = pe.common.IMAGE_SECTION_HEADER;
pub const FUNCS = pe.common.FUNCS;

pub const PEHeaders32 = pe.pe32.PEHeaders32;

pub const PEHeaders64 = pe.pe64.PEHeaders64;

pub const Hdrs = union(enum) {
    ELFHeaders32: ELFHeaders32,
    ELFHeaders64: ELFHeaders64,
    PEHeaders32: PEHeaders32,
    PEHeaders64: PEHeaders64,
};

pub const Headers = struct {
    allocator: std.mem.Allocator,
    hdrs: Hdrs,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8, file_type: FileType) !Self {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();
        const reader = file.reader();

        // Reset reader seek
        try reader.context.seekTo(0);

        // Analyze headers
        switch (file_type) {
            FileType.elf32 => return Self{
                .allocator = allocator,
                .hdrs = Hdrs{ .ELFHeaders32 = try elf.elf32.ELFHeaders32.analyze(
                    allocator,
                    file_path,
                    reader,
                ) },
            },
            FileType.elf64 => return Self{
                .allocator = allocator,
                .hdrs = Hdrs{ .ELFHeaders64 = try elf.elf64.ELFHeaders64.analyze(
                    allocator,
                    file_path,
                    reader,
                ) },
            },
            FileType.pe32 => return Self{
                .allocator = allocator,
                .hdrs = Hdrs{ .PEHeaders32 = try pe.pe32.PEHeaders32.analyze(
                    allocator,
                    file_path,
                    reader,
                ) },
            },
            FileType.pe64 => return Self{
                .allocator = allocator,
                .hdrs = Hdrs{ .PEHeaders64 = try pe.pe64.PEHeaders64.analyze(
                    allocator,
                    file_path,
                    reader,
                ) },
            },
            FileType.unknown => return error.UnknownFileType,
        }
    }

    pub fn deinit(self: *Self) void {
        switch (self.hdrs) {
            .ELFHeaders32 => self.hdrs.ELFHeaders32.deinit(),
            .ELFHeaders64 => self.hdrs.ELFHeaders64.deinit(),
            .PEHeaders32 => self.hdrs.PEHeaders32.deinit(),
            .PEHeaders64 => self.hdrs.PEHeaders64.deinit(),
        }
    }

    pub fn getEntryPoint(self: Self) !usize {
        switch (self.hdrs) {
            .ELFHeaders32 => return self.hdrs.ELFHeaders32.file_header.e_entry,
            .ELFHeaders64 => return self.hdrs.ELFHeaders64.file_header.e_entry,
            .PEHeaders32 => return self.hdrs.PEHeaders32.image_nt_headers.OptionalHeader.AddressOfEntryPoint,
            .PEHeaders64 => return self.hdrs.PEHeaders64.image_nt_headers.OptionalHeader.AddressOfEntryPoint,
        }
    }

    pub fn printInfo(self: Self) !void {
        switch (self.hdrs) {
            .ELFHeaders32 => try self.hdrs.ELFHeaders32.printInfo(),
            .ELFHeaders64 => try self.hdrs.ELFHeaders64.printInfo(),
            .PEHeaders32 => try self.hdrs.PEHeaders32.printInfo(),
            .PEHeaders64 => try self.hdrs.PEHeaders64.printInfo(),
        }
    }

    pub fn printHeaders(self: Self) !void {
        switch (self.hdrs) {
            .ELFHeaders32 => try stdout.print("{}", .{self.hdrs.ELFHeaders32}),
            .ELFHeaders64 => try stdout.print("{}", .{self.hdrs.ELFHeaders64}),
            .PEHeaders32 => try stdout.print("{}", .{self.hdrs.PEHeaders32}),
            .PEHeaders64 => try stdout.print("{}", .{self.hdrs.PEHeaders64}),
        }
    }

    pub fn printFileHeader(self: Self) !void {
        switch (self.hdrs) {
            .ELFHeaders32 => try stdout.print("{}\n", .{self.hdrs.ELFHeaders32.file_header}),
            .ELFHeaders64 => try stdout.print("{}\n", .{self.hdrs.ELFHeaders64.file_header}),
            .PEHeaders32 => try stdout.print("{}\n", .{self.hdrs.PEHeaders32.image_dos_header}),
            .PEHeaders64 => try stdout.print("{}\n", .{self.hdrs.PEHeaders64.image_dos_header}),
        }
    }

    pub fn printProgramHeaders(self: Self) !void {
        const empty_message = "No program headers.";

        switch (self.hdrs) {
            .ELFHeaders32 => {
                var ms = try MultiEntriesString.init(
                    self.allocator,
                    ELFProgramHeader32,
                    self.hdrs.ELFHeaders32.program_headers,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .ELFHeaders64 => {
                var ms = try MultiEntriesString.init(
                    self.allocator,
                    ELFProgramHeader64,
                    self.hdrs.ELFHeaders64.program_headers,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .PEHeaders32 => try stdout.printError("{s}\n", .{empty_message}),
            .PEHeaders64 => try stdout.printError("{s}\n", .{empty_message}),
        }
    }

    pub fn printSectionHeaders(self: Self) !void {
        const empty_message = "No section headers.";

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        switch (self.hdrs) {
            .ELFHeaders32 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    ELFSectionHeader32,
                    self.hdrs.ELFHeaders32.section_headers,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .ELFHeaders64 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    ELFSectionHeader64,
                    self.hdrs.ELFHeaders64.section_headers,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .PEHeaders32 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    IMAGE_SECTION_HEADER,
                    self.hdrs.PEHeaders32.image_section_headers,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .PEHeaders64 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    IMAGE_SECTION_HEADER,
                    self.hdrs.PEHeaders64.image_section_headers,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
        }
    }

    pub fn printSymbols(self: Self) !void {
        const empty_message = "No symbols.";

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        switch (self.hdrs) {
            .ELFHeaders32 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    ELF32_Sym,
                    self.hdrs.ELFHeaders32.symbols,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .ELFHeaders64 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    ELF64_Sym,
                    self.hdrs.ELFHeaders64.symbols,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .PEHeaders32 => try stdout.printError("{s}\n", .{empty_message}),
            .PEHeaders64 => try stdout.printError("{s}\n", .{empty_message}),
        }
    }

    pub fn printDynSymbols(self: Self) !void {
        const empty_message = "No dynamic symbols.";

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        switch (self.hdrs) {
            .ELFHeaders32 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    ELF32_Sym,
                    self.hdrs.ELFHeaders32.dynsymbols,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .ELFHeaders64 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    ELF64_Sym,
                    self.hdrs.ELFHeaders64.dynsymbols,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .PEHeaders32 => try stdout.printError("{s}\n", .{empty_message}),
            .PEHeaders64 => try stdout.printError("{s}\n", .{empty_message}),
        }
    }

    pub fn printExportTable(self: Self) !void {
        const empty_message = "No export table.";

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        switch (self.hdrs) {
            .ELFHeaders32 => try stdout.printError("{s}\n", .{empty_message}),
            .ELFHeaders64 => try stdout.printError("{s}\n", .{empty_message}),
            .PEHeaders32 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    FUNCS,
                    self.hdrs.PEHeaders32.exported_funcs,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .PEHeaders64 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    FUNCS,
                    self.hdrs.PEHeaders64.exported_funcs,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
        }
    }

    pub fn printImportTable(self: Self) !void {
        const empty_message = "No import table.";

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        switch (self.hdrs) {
            .ELFHeaders32 => try stdout.printError("{s}\n", .{empty_message}),
            .ELFHeaders64 => try stdout.printError("{s}\n", .{empty_message}),
            .PEHeaders32 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    FUNCS,
                    self.hdrs.PEHeaders32.imported_funcs,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
            .PEHeaders64 => {
                var ms = try MultiEntriesString.init(
                    arena_allocator,
                    FUNCS,
                    self.hdrs.PEHeaders64.imported_funcs,
                    empty_message,
                    true,
                    0,
                );
                defer ms.deinit();
                try stdout.print("{s}", .{ms.str_joined});
            },
        }
    }
};
