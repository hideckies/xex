const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../../common.zig").stdout;
const util = @import("../../common.zig").util;
const decode = @import("./decode.zig");

const MultiEntriesString = @import("../fmt.zig").MultiEntriesString;

// Reference: https://www.vergiliusproject.com/kernels/x64/windows-11/23h2/_IMAGE_DOS_HEADER
pub const IMAGE_DOS_HEADER = struct {
    allocator: std.mem.Allocator,

    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,

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
            \\  e_magic     {s}
            \\  e_cblp      {s}
            \\  e_cp        {s}
            \\  e_crlc      {s}
            \\  e_cparhdr   {s}
            \\  e_minalloc  {s}
            \\  e_maxalloc  {s}
            \\  e_ss        {s}
            \\  e_sp        {s}
            \\  e_csum      {s}
            \\  e_ip        {s}
            \\  e_cs        {s}
            \\  e_lfarlc    {s}
            \\  e_ovno      {s}
            \\  e_res       {s}
            \\              {s}
            \\              {s}
            \\              {s}
            \\  e_oemid     {s}
            \\  e_oeminfo   {s}
            \\  e_res2      {s}
            \\              {s}
            \\              {s}
            \\              {s}
            \\              {s}
            \\              {s}
            \\              {s}
            \\              {s}
            \\              {s}
            \\              {s}
            \\  e_lfanew    {s}
        ;
        return writer.print(str, .{
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_magic}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_cblp}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_cp}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_crlc}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_cparhdr}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_minalloc}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_maxalloc}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_ss}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_sp}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_csum}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_ip}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_cs}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_lfarlc}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_ovno}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res[0]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res[1]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res[2]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res[3]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_oemid}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_oeminfo}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[0]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[1]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[2]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[3]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[4]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[5]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[6]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[7]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[8]}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.e_res2[9]}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.e_lfanew}),
        });
    }
};

// Reference: https://www.vergiliusproject.com/kernels/x64/windows-11/23h2/_IMAGE_FILE_HEADER
pub const IMAGE_FILE_HEADER = struct {
    allocator: std.mem.Allocator,

    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,

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

        const date_str = try util.timestampToDateStr(self.allocator, @intCast(self.TimeDateStamp));
        defer self.allocator.free(date_str);

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        const str =
            \\  Machine               {s}
            \\  NumberOfSections      {s}
            \\  TimeDateStamp         {s}
            \\  PointerToSymbolTable  {s}
            \\  NumberOfSymbols       {s}
            \\  SizeOfOptionalHeader  {s}
            \\  Characteristics       {s}
        ;
        return writer.print(str, .{
            try cham.cyanBright().fmt("{s}", .{(try decode.Machine.parse(self.Machine)).str}),
            try cham.greenBright().fmt("{d}", .{self.NumberOfSections}),
            try cham.cyanBright().fmt("{s}", .{date_str}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.PointerToSymbolTable}),
            try cham.greenBright().fmt("{d}", .{self.NumberOfSymbols}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.SizeOfOptionalHeader}),
            try cham.magentaBright().fmt("{s}", .{(try decode.IFChars.parse(self.Characteristics)).str}),
        });
    }
};

// Reference: https://www.vergiliusproject.com/kernels/x64/windows-11/23h2/_IMAGE_DATA_DIRECTORY
pub const IMAGE_DATA_DIRECTORY = struct {
    allocator: std.mem.Allocator,

    VirtualAddress: u32,
    Size: u32,

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
            \\  VirtualAddress {s} Size {s}
        ;
        return writer.print(str, .{
            try cham.greenBright().fmt("0x{x:0>8}", .{self.VirtualAddress}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.Size}),
        });
    }
};

// Reference: https://www.vergiliusproject.com/kernels/x64/windows-11/23h2/_IMAGE_SECTION_HEADER
pub const IMAGE_SECTION_HEADER = struct {
    allocator: std.mem.Allocator,

    Name: [8]u8,
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,

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
            \\    VirtualSize             {s}
            \\    VirtualAddress          {s}
            \\    SizeOfRawData           {s}
            \\    PointerToRawData        {s}
            \\    PointerToRelocations    {s}
            \\    PointerToLinenumbers    {s}
            \\    NumberOfRelocations     {s}
            \\    NumberOfLinenumbers     {s}
            \\    Characteristics         {s}
        ;
        return writer.print(str, .{
            try cham.yellow().fmt("{s}", .{self.Name}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.VirtualSize}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.VirtualAddress}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.SizeOfRawData}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.PointerToRawData}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.PointerToRelocations}),
            try cham.greenBright().fmt("0x{x:0>8}", .{self.PointerToLinenumbers}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.NumberOfRelocations}),
            try cham.greenBright().fmt("0x{x:0>4}", .{self.NumberOfLinenumbers}),
            try cham.magentaBright().fmt("{s}", .{(try decode.ISChars.parse(self.Characteristics)).str}),
        });
    }
};

// Reference:
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/SystemServices/struct.IMAGE_EXPORT_DIRECTORY.html
pub const IMAGE_EXPORT_DIRECTORY = struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const str =
            \\  Characteristics       0x{x:0>8}
            \\  TimeDateStamp         0x{x:0>8}
            \\  MajorVersion          0x{x:0>4}
            \\  MinorVersion          0x{x:0>4}
            \\  Name                  0x{x:0>8}
            \\  Base                  0x{x:0>8}
            \\  NumberOfFunctions     0x{x:0>8}
            \\  NumberOfNames         0x{x:0>8}
            \\  AddressOfFunctions    0x{x:0>8}
            \\  AddressOfNames        0x{x:0>8}
            \\  AddressOfNameOrdinals 0x{x:0>8}
        ;
        return writer.print(str, .{
            self.Characteristics,
            self.TimeDateStamp,
            self.MajorVersion,
            self.MinorVersion,
            self.Name,
            self.Base,
            self.NumberOfFunctions,
            self.NumberOfNames,
            self.AddressOfFunctions,
            self.AddressOfNames,
            self.AddressOfNameOrdinals,
        });
    }
};

// References:
// - https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-tools/widl/include/winnt.h#L2978
// - https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/SystemServices/struct.IMAGE_IMPORT_DESCRIPTOR.html
pub const IMAGE_IMPORT_DESCRIPTOR = struct {
    OriginalFirstThunk: u32,
    TimeDateStamp: u32,
    ForwarderChain: u32,
    Name: u32,
    FirstThunk: u32,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const str =
            \\  OriginalFirstThunk    0x{x:0>8}
            \\  TimeDateStamp         0x{x:0>8}
            \\  ForwarderChain        0x{x:0>8}
            \\  Name                  0x{x:0>8}
            \\  FirstThunk            0x{x:0>8}
        ;
        return writer.print(str, .{
            self.OriginalFirstThunk,
            self.TimeDateStamp,
            self.ForwarderChain,
            self.Name,
            self.FirstThunk,
        });
    }
};

pub const FUNCS = struct {
    allocator: std.mem.Allocator,

    DllName: []const u8,
    Functions: [][]const u8,

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

        var ms_funcs = try MultiEntriesString.init(
            self.allocator,
            []const u8,
            self.Functions,
            "Functions not found",
            false,
            6,
        );
        defer ms_funcs.deinit();
        const str_funcs = ms_funcs.str_joined;

        const str =
            \\{s}:
            \\{s}
        ;
        return writer.print(str, .{
            try cham.yellow().fmt("{s}", .{self.DllName}),
            str_funcs,
        });
    }
};

pub fn rvaToOffset(rva: u32, sections: []IMAGE_SECTION_HEADER) u32 {
    for (sections) |section| {
        if (section.VirtualAddress <= rva and rva < section.VirtualAddress + section.VirtualSize) {
            return section.PointerToRawData + (rva - section.VirtualAddress);
        }
    }
    return rva;
}
