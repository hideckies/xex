const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../../common.zig").stdout;
const util = @import("../../common.zig").util;

const common = @import("./common.zig");
const IMAGE_DOS_HEADER = common.IMAGE_DOS_HEADER;
const IMAGE_FILE_HEADER = common.IMAGE_FILE_HEADER;
const IMAGE_DATA_DIRECTORY = common.IMAGE_DATA_DIRECTORY;
const IMAGE_SECTION_HEADER = common.IMAGE_SECTION_HEADER;
const IMAGE_EXPORT_DIRECTORY = common.IMAGE_EXPORT_DIRECTORY;
const IMAGE_IMPORT_DESCRIPTOR = common.IMAGE_IMPORT_DESCRIPTOR;
const FUNCS = common.FUNCS;

const decode = @import("./decode.zig");
const MultiEntriesString = @import("../fmt.zig").MultiEntriesString;

// Reference: https://www.vergiliusproject.com/kernels/x86/windows-10/22h2/_IMAGE_OPTIONAL_HEADER
pub const IMAGE_OPTIONAL_HEADER32 = struct {
    allocator: std.mem.Allocator,

    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializeData: u32,
    SizeOfUninitializeData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u32,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u32,
    SizeOfStackCommit: u32,
    SizeOfHeapReserve: u32,
    SizeOfHeapCommit: u32,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,

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

        var ms_data_dir = try MultiEntriesString.init(
            self.allocator,
            IMAGE_DATA_DIRECTORY,
            @constCast(&self.DataDirectory),
            "DataDirectory is empty",
            true,
            0,
        );
        defer ms_data_dir.deinit();
        const str_data_dir = ms_data_dir.str_joined;

        const str =
            \\  Magic                         {s}
            \\  MajorLinkerVersion            {s}
            \\  MinorLinkerVersion            {s}
            \\  SizeOfCode                    {s}
            \\  SizeOfInitializeData          {s}
            \\  SizeOfUninitializeData        {s}
            \\  AddressOfEntryPoint           {s}
            \\  BaseOfCode                    {s}
            \\  ImageBase                     {s}
            \\  SectionAlignment              {s}
            \\  FileAlignment                 {s}
            \\  MajorOperatingSystemVersion   {s}
            \\  MinorOperatingSystemVersion   {s}
            \\  MajorImageVersion             {s}
            \\  MinorImageVersion             {s}
            \\  MajorSubsystemVersion         {s}
            \\  MinorSubsystemVersion         {s}
            \\  Win32VersionValue             {s}
            \\  SizeOfImage                   {s}
            \\  SizeOfHeaders                 {s}
            \\  CheckSum                      {s}
            \\  Subsystem                     {s}
            \\  DllCharacteristics            {s}
            \\  SizeOfStackReserve            {s}
            \\  SizeOfStackCommit             {s}
            \\  SizeOfHeapReserve             {s}
            \\  SizeOfHeapCommit              {s}
            \\  LoaderFlags                   {s}
            \\  NumberOfRvaAndSizes           {s}
            \\  DataDirectory:
            \\{s}
        ;
        return writer.print(str, .{
            try cham.greenBright().fmt("0x{x:0>4}", .{self.Magic}),
            try cham.greenBright().fmt("0x{x:0>2}", .{self.MajorLinkerVersion}),
            try cham.greenBright().fmt("0x{x:0>2}", .{self.MinorLinkerVersion}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfCode}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfInitializeData}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfUninitializeData}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.AddressOfEntryPoint}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.BaseOfCode}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.ImageBase}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SectionAlignment}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.FileAlignment}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.MajorOperatingSystemVersion}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.MinorOperatingSystemVersion}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.MajorImageVersion}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.MinorImageVersion}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.MajorSubsystemVersion}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.MinorSubsystemVersion}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.Win32VersionValue}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfImage}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfHeaders}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.CheckSum}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.Subsystem}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.DllCharacteristics}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfStackReserve}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfStackCommit}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfHeapReserve}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfHeapCommit}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.LoaderFlags}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.NumberOfRvaAndSizes}),
            str_data_dir,
        });
    }
};

// Reference: https://www.vergiliusproject.com/kernels/x86/windows-10/22h2/_IMAGE_NT_HEADERS
pub const IMAGE_NT_HEADERS32 = struct {
    allocator: std.mem.Allocator,

    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,

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
            \\  Signature   {s}
            \\
            \\  FileHeader
            \\  ----------
            \\
            \\{s}
            \\
            \\  OptionalHeader
            \\  --------------
            \\
            \\{s}
        ;
        return writer.print(str, .{
            try cham.greenBright().fmt("0x{x:0>8}", .{self.Signature}),
            self.FileHeader,
            self.OptionalHeader,
        });
    }
};

pub const PEHeaders32 = struct {
    allocator: std.mem.Allocator,

    file_path: []const u8,
    image_dos_header: IMAGE_DOS_HEADER,
    image_nt_headers: IMAGE_NT_HEADERS32,
    image_section_headers: []IMAGE_SECTION_HEADER,
    image_export_directory: IMAGE_EXPORT_DIRECTORY,
    exported_funcs: []FUNCS,
    image_import_descriptors: []IMAGE_IMPORT_DESCRIPTOR,
    imported_funcs: []FUNCS,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var ms_shs = try MultiEntriesString.init(
            self.allocator,
            IMAGE_SECTION_HEADER,
            self.image_section_headers,
            "No image section headers",
            true,
            0,
        );
        defer ms_shs.deinit();
        const str_shs = ms_shs.str_joined;

        var ms_exported_funcs = try MultiEntriesString.init(
            self.allocator,
            FUNCS,
            self.exported_funcs,
            "No exported functions",
            true,
            0,
        );
        defer ms_exported_funcs.deinit();
        const str_exported_funcs = ms_exported_funcs.str_joined;

        var ms_imported_funcs = try MultiEntriesString.init(
            self.allocator,
            FUNCS,
            self.imported_funcs,
            "No imported functions",
            true,
            0,
        );
        defer ms_imported_funcs.deinit();
        const str_imported_funcs = ms_imported_funcs.str_joined;

        const str =
            \\DOS Header
            \\==========
            \\
            \\{s}
            \\
            \\NT Headers
            \\==========
            \\
            \\{s}
            \\
            \\Sections
            \\========
            \\
            \\{s}
            \\
            \\Export Directory
            \\================
            \\
            \\{s}
            \\
            \\Export Table
            \\============
            \\
            \\{s}
            \\
            \\Import Table
            \\============
            \\
            \\{s}
        ;
        return writer.print(str, .{
            self.image_dos_header,
            self.image_nt_headers,
            str_shs,
            self.image_export_directory,
            str_exported_funcs,
            str_imported_funcs,
        });
    }

    pub fn printInfo(self: Self) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        var image_type: []const u8 = undefined;
        const chars = try decode.IFChars.parse(self.image_nt_headers.FileHeader.Characteristics);
        if (std.mem.indexOf(u8, chars.str, "EXECUTABLE") != null) {
            if (std.mem.indexOf(u8, chars.str, "DLL") != null) {
                image_type = "Executable (DLL)";
            } else {
                image_type = "Executable";
            }
        } else {
            image_type = "Unknown";
        }

        const str = try std.fmt.allocPrint(arena_allocator,
            \\{s: <14}: {s}
            \\{s: <14}: {s}
            \\{s: <14}: {s}
            \\{s: <14}: {s}
        , .{
            "File",
            try cham.greenBright().fmt("{s}", .{self.file_path}),
            "File Type",
            // image_type,
            try cham.cyanBright().fmt("PE32, {s}, LSB", .{image_type}),
            "Architecture",
            try cham.cyanBright().fmt("{s}", .{(try decode.Machine.parse(self.image_nt_headers.FileHeader.Machine)).str}),
            "Start Address",
            try cham.greenBright().fmt("0x{x}", .{self.image_nt_headers.OptionalHeader.AddressOfEntryPoint}),
        });
        defer arena_allocator.free(str);
        try stdout.print("{s}\n", .{str});
    }

    pub fn analyze(allocator: std.mem.Allocator, file_path: []const u8, reader: anytype) !Self {
        const image_dos_header = IMAGE_DOS_HEADER{
            .allocator = allocator,
            .e_magic = try reader.readInt(u16, .little),
            .e_cblp = try reader.readInt(u16, .little),
            .e_cp = try reader.readInt(u16, .little),
            .e_crlc = try reader.readInt(u16, .little),
            .e_cparhdr = try reader.readInt(u16, .little),
            .e_minalloc = try reader.readInt(u16, .little),
            .e_maxalloc = try reader.readInt(u16, .little),
            .e_ss = try reader.readInt(u16, .little),
            .e_sp = try reader.readInt(u16, .little),
            .e_csum = try reader.readInt(u16, .little),
            .e_ip = try reader.readInt(u16, .little),
            .e_cs = try reader.readInt(u16, .little),
            .e_lfarlc = try reader.readInt(u16, .little),
            .e_ovno = try reader.readInt(u16, .little),
            .e_res = [4]u16{
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
            },
            .e_oemid = try reader.readInt(u16, .little),
            .e_oeminfo = try reader.readInt(u16, .little),
            .e_res2 = [10]u16{
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
                try reader.readInt(u16, .little),
            },
            .e_lfanew = try reader.readInt(i32, .little),
        };

        const nt_headers_offset: usize = @intCast(image_dos_header.e_lfanew);
        try reader.context.seekTo(nt_headers_offset);

        const image_nt_headers = IMAGE_NT_HEADERS32{
            .allocator = allocator,
            .Signature = try reader.readInt(u32, .little),
            .FileHeader = IMAGE_FILE_HEADER{
                .allocator = allocator,
                .Machine = try reader.readInt(u16, .little),
                .NumberOfSections = try reader.readInt(u16, .little),
                .TimeDateStamp = try reader.readInt(u32, .little),
                .PointerToSymbolTable = try reader.readInt(u32, .little),
                .NumberOfSymbols = try reader.readInt(u32, .little),
                .SizeOfOptionalHeader = try reader.readInt(u16, .little),
                .Characteristics = try reader.readInt(u16, .little),
            },
            .OptionalHeader = IMAGE_OPTIONAL_HEADER32{
                .allocator = allocator,
                .Magic = try reader.readInt(u16, .little),
                .MajorLinkerVersion = try reader.readInt(u8, .little),
                .MinorLinkerVersion = try reader.readInt(u8, .little),
                .SizeOfCode = try reader.readInt(u32, .little),
                .SizeOfInitializeData = try reader.readInt(u32, .little),
                .SizeOfUninitializeData = try reader.readInt(u32, .little),
                .AddressOfEntryPoint = try reader.readInt(u32, .little),
                .BaseOfCode = try reader.readInt(u32, .little),
                .ImageBase = try reader.readInt(u32, .little),
                .SectionAlignment = try reader.readInt(u32, .little),
                .FileAlignment = try reader.readInt(u32, .little),
                .MajorOperatingSystemVersion = try reader.readInt(u16, .little),
                .MinorOperatingSystemVersion = try reader.readInt(u16, .little),
                .MajorImageVersion = try reader.readInt(u16, .little),
                .MinorImageVersion = try reader.readInt(u16, .little),
                .MajorSubsystemVersion = try reader.readInt(u16, .little),
                .MinorSubsystemVersion = try reader.readInt(u16, .little),
                .Win32VersionValue = try reader.readInt(u32, .little),
                .SizeOfImage = try reader.readInt(u32, .little),
                .SizeOfHeaders = try reader.readInt(u32, .little),
                .CheckSum = try reader.readInt(u32, .little),
                .Subsystem = try reader.readInt(u16, .little),
                .DllCharacteristics = try reader.readInt(u16, .little),
                .SizeOfStackReserve = try reader.readInt(u32, .little),
                .SizeOfStackCommit = try reader.readInt(u32, .little),
                .SizeOfHeapReserve = try reader.readInt(u32, .little),
                .SizeOfHeapCommit = try reader.readInt(u32, .little),
                .LoaderFlags = try reader.readInt(u32, .little),
                .NumberOfRvaAndSizes = try reader.readInt(u32, .little),
                .DataDirectory = [16]IMAGE_DATA_DIRECTORY{
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                    IMAGE_DATA_DIRECTORY{
                        .allocator = allocator,
                        .VirtualAddress = try reader.readInt(u32, .little),
                        .Size = try reader.readInt(u32, .little),
                    },
                },
            },
        };

        // Get Section Headers
        var image_section_headers = std.ArrayList(IMAGE_SECTION_HEADER).init(allocator);
        defer image_section_headers.deinit();
        for (0..image_nt_headers.FileHeader.NumberOfSections) |_| {
            const image_section_header = IMAGE_SECTION_HEADER{
                .allocator = allocator,
                .Name = [8]u8{
                    try reader.readInt(u8, .little),
                    try reader.readInt(u8, .little),
                    try reader.readInt(u8, .little),
                    try reader.readInt(u8, .little),
                    try reader.readInt(u8, .little),
                    try reader.readInt(u8, .little),
                    try reader.readInt(u8, .little),
                    try reader.readInt(u8, .little),
                },
                .VirtualSize = try reader.readInt(u32, .little),
                .VirtualAddress = try reader.readInt(u32, .little),
                .SizeOfRawData = try reader.readInt(u32, .little),
                .PointerToRawData = try reader.readInt(u32, .little),
                .PointerToRelocations = try reader.readInt(u32, .little),
                .PointerToLinenumbers = try reader.readInt(u32, .little),
                .NumberOfRelocations = try reader.readInt(u16, .little),
                .NumberOfLinenumbers = try reader.readInt(u16, .little),
                .Characteristics = try reader.readInt(u32, .little),
            };

            try image_section_headers.append(image_section_header);
        }

        // Get Export Table
        var image_export_directory: IMAGE_EXPORT_DIRECTORY = undefined;
        var exported_funcs = std.ArrayList(FUNCS).init(allocator);
        defer exported_funcs.deinit();

        const export_dir = image_nt_headers.OptionalHeader.DataDirectory[0];

        // Find target section header
        var target_section_header: IMAGE_SECTION_HEADER = undefined;
        for (image_section_headers.items) |sh| {
            if (export_dir.VirtualAddress >= sh.VirtualAddress and export_dir.VirtualAddress < sh.VirtualAddress + sh.SizeOfRawData) {
                target_section_header = sh;
                break;
            }
        }

        if (export_dir.Size != 0) {
            const export_dir_offset: usize = @intCast(export_dir.VirtualAddress - target_section_header.VirtualAddress + target_section_header.PointerToRawData);
            try reader.context.seekTo(export_dir_offset);

            image_export_directory = IMAGE_EXPORT_DIRECTORY{
                .Characteristics = try reader.readInt(u32, .little),
                .TimeDateStamp = try reader.readInt(u32, .little),
                .MajorVersion = try reader.readInt(u16, .little),
                .MinorVersion = try reader.readInt(u16, .little),
                .Name = try reader.readInt(u32, .little),
                .Base = try reader.readInt(u32, .little),
                .NumberOfFunctions = try reader.readInt(u32, .little),
                .NumberOfNames = try reader.readInt(u32, .little),
                .AddressOfFunctions = try reader.readInt(u32, .little),
                .AddressOfNames = try reader.readInt(u32, .little),
                .AddressOfNameOrdinals = try reader.readInt(u32, .little),
            };

            // Get DLL name
            const dll_name_offset = common.rvaToOffset(
                image_export_directory.Name,
                image_section_headers.items[0..image_nt_headers.FileHeader.NumberOfSections],
            );
            const dll_name = try util.readCstring(allocator, reader, dll_name_offset);
            defer allocator.free(dll_name);

            const address_of_names_offset = common.rvaToOffset(
                image_export_directory.AddressOfNames,
                image_section_headers.items[0..image_nt_headers.FileHeader.NumberOfSections],
            );

            // Get functions
            var functions = std.ArrayList([]const u8).init(allocator);
            defer functions.deinit();
            for (0..image_export_directory.NumberOfNames, 0..) |_, i| {
                // Get function RVA
                try reader.context.seekTo(address_of_names_offset + i * @sizeOf(u32));
                const func_name_rva = try reader.readInt(u32, .little);
                const func_name_offset = common.rvaToOffset(
                    func_name_rva,
                    image_section_headers.items[0..image_nt_headers.FileHeader.NumberOfSections],
                );
                if (func_name_offset >= try reader.context.getEndPos()) break;

                try reader.context.seekTo(func_name_rva);

                // Read CString
                const func_name = try util.readCstring(allocator, reader, func_name_offset);
                defer allocator.free(func_name);
                try functions.append(func_name);
            }

            try exported_funcs.append(FUNCS{
                .allocator = allocator,
                .DllName = try allocator.dupe(u8, dll_name),
                .Functions = try allocator.dupe([]const u8, functions.items),
            });
        }

        // Get Import Table
        var image_import_descriptors = std.ArrayList(IMAGE_IMPORT_DESCRIPTOR).init(allocator);
        defer image_import_descriptors.deinit();
        var imported_funcs = std.ArrayList(FUNCS).init(allocator);
        defer imported_funcs.deinit();

        const import_dir = image_nt_headers.OptionalHeader.DataDirectory[1];

        // Find target section header
        for (image_section_headers.items) |sh| {
            if (import_dir.VirtualAddress >= sh.VirtualAddress and import_dir.VirtualAddress < sh.VirtualAddress + sh.SizeOfRawData) {
                target_section_header = sh;
                break;
            }
        }

        if (import_dir.Size != 0) {
            var import_dir_offset: usize = @intCast(import_dir.VirtualAddress - target_section_header.VirtualAddress + target_section_header.PointerToRawData);

            while (true) {
                try reader.context.seekTo(import_dir_offset);
                const image_import_descriptor = IMAGE_IMPORT_DESCRIPTOR{
                    .OriginalFirstThunk = try reader.readInt(u32, .little),
                    .TimeDateStamp = try reader.readInt(u32, .little),
                    .ForwarderChain = try reader.readInt(u32, .little),
                    .Name = try reader.readInt(u32, .little),
                    .FirstThunk = try reader.readInt(u32, .little),
                };
                if (image_import_descriptor.Name == 0) break;

                // Get DLL name
                const dll_name_offset = common.rvaToOffset(
                    image_import_descriptor.Name,
                    image_section_headers.items[0..image_nt_headers.FileHeader.NumberOfSections],
                );
                if (dll_name_offset >= try reader.context.getEndPos()) break;
                // Read CString
                const dll_name = try util.readCstring(allocator, reader, dll_name_offset);
                defer allocator.free(dll_name);

                // Get functions
                var functions = std.ArrayList([]const u8).init(allocator);
                defer functions.deinit();
                var thunk_offset = common.rvaToOffset(
                    image_import_descriptor.OriginalFirstThunk,
                    image_section_headers.items[0..image_nt_headers.FileHeader.NumberOfSections],
                );

                while (true) {
                    try reader.context.seekTo(thunk_offset);

                    const thunk = try reader.readInt(u32, .little);
                    if (thunk == 0) break;

                    const func_name_offset = common.rvaToOffset(
                        thunk + 2,
                        image_section_headers.items[0..image_nt_headers.FileHeader.NumberOfSections],
                    );
                    if (func_name_offset >= try reader.context.getEndPos()) break;

                    // Read CString
                    const func_name = try util.readCstring(allocator, reader, func_name_offset);
                    defer allocator.free(func_name);
                    try functions.append(try allocator.dupe(u8, func_name));

                    thunk_offset += @sizeOf(u32);
                }

                try imported_funcs.append(FUNCS{
                    .allocator = allocator,
                    .DllName = try allocator.dupe(u8, dll_name),
                    .Functions = try allocator.dupe([]const u8, functions.items),
                });

                try image_import_descriptors.append(image_import_descriptor);

                import_dir_offset += @sizeOf(IMAGE_IMPORT_DESCRIPTOR);
            }
        }

        return PEHeaders32{
            .allocator = allocator,
            .file_path = try allocator.dupe(u8, file_path),
            .image_dos_header = image_dos_header,
            .image_nt_headers = image_nt_headers,
            .image_section_headers = try allocator.dupe(IMAGE_SECTION_HEADER, image_section_headers.items),
            .image_export_directory = image_export_directory,
            .exported_funcs = try allocator.dupe(FUNCS, exported_funcs.items),
            .image_import_descriptors = try allocator.dupe(IMAGE_IMPORT_DESCRIPTOR, image_import_descriptors.items),
            .imported_funcs = try allocator.dupe(FUNCS, imported_funcs.items),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.file_path);
        self.allocator.free(self.image_section_headers);

        for (self.exported_funcs) |ef| {
            self.allocator.free(ef.DllName);

            for (ef.Functions) |func_name| {
                self.allocator.free(func_name);
            }
            self.allocator.free(ef.Functions);
        }
        self.allocator.free(self.exported_funcs);

        self.allocator.free(self.image_import_descriptors);

        for (self.imported_funcs) |if_| {
            self.allocator.free(if_.DllName);

            for (if_.Functions) |func_name| {
                self.allocator.free(func_name);
            }
            self.allocator.free(if_.Functions);
        }
        self.allocator.free(self.imported_funcs);
    }
};
