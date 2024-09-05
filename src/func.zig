const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("./common.zig").stdout;
const Breakpoint = @import("./breakpoint.zig").Breakpoint;
const FileType = @import("./file.zig").FileType;
const Headers = @import("./headers.zig").Headers;
const ELF32_Sym = @import("./headers.zig").elf.elf32.ELF32_Sym;
const ELF64_Sym = @import("./headers.zig").elf.elf64.ELF64_Sym;
const ELFHeader64 = @import("./headers.zig").elf.elf64.ELFHeader64;
const ELFSectionHeader64 = @import("./headers.zig").elf.elf64.ELFSectionHeader64;
const decode_elf = @import("./headers.zig").elf.decode;
const Process = @import("./process.zig").Process;

const c = @cImport({
    @cInclude("dlfcn.h");
    @cInclude("unistd.h");
});

const LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6";
const LIBC_PATH_2 = "/usr/lib/x86_64-linux-gnu/libc.so.6";

pub const Function = struct {
    name: []const u8,
    addr: usize,

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

        return writer.print("{s}\t{s}", .{
            try cham.greenBright().fmt("0x{x}", .{self.addr}),
            try cham.yellow().fmt("{s}", .{self.name}),
        });
    }

    pub fn init(name: []const u8, addr: usize) Self {
        return Self{
            .name = name,
            .addr = addr,
        };
    }
};

// Helper functions for sorting functions.
fn cmpByFuncAddr(context: void, a: Function, b: Function) bool {
    _ = context;
    if (a.addr < b.addr) {
        return true;
    } else {
        return false;
    }
}

// Helper function to find .text section
fn findTextSectionData(file_buf: []const u8, section_headers: []ELFSectionHeader64) ![]const u8 {
    for (section_headers) |sh| {
        if (std.mem.eql(u8, sh.sh_name_str, ".text")) {
            return file_buf[sh.sh_offset..][0..sh.sh_size];
        }
    }
    return error.TextSectionNotFound;
}

// Helper function to find a function start offset.
fn findFuncStartOffsets(
    allocator: std.mem.Allocator,
    text_section_data: []const u8,
) ![]usize {
    const func_start_pattern: []const u8 = &[_]u8{ 0x55, 0x48, 0x89, 0xe5 }; // push rbp; mov rbp, rsp

    var start_offsets = std.ArrayList(usize).init(allocator);
    defer start_offsets.deinit();

    for (text_section_data, 0..) |byte, i| {
        _ = byte;
        if (i + func_start_pattern.len <= text_section_data.len) {
            const slice = text_section_data[i .. i + func_start_pattern.len];
            if (std.mem.eql(u8, slice, func_start_pattern)) {
                try start_offsets.append(i);
            }
        }
    }
    if (start_offsets.items.len > 0) {
        return start_offsets.toOwnedSlice();
    }
    return error.FunctionStartOffsetNotFound;
}

pub fn getFunctions(
    allocator: std.mem.Allocator,
    process: Process,
    headers: Headers,
    breakpoints: std.ArrayList(Breakpoint),
    file_path: []const u8,
    file_buf: []const u8,
) ![]Function {
    const exe_filename = std.fs.path.basename(file_path);
    var memmap = process.memmap;

    // const exe_base_addr = process.memmap.base_addr_info.exe_base_addr.?;
    // const ld_base_addr = process.memmap.base_addr_info.ld_base_addr.?;
    _ = breakpoints;

    var funcs = std.ArrayList(Function).init(allocator);
    defer funcs.deinit();

    switch (headers.hdrs) {
        .ELFHeaders32 => {
            const symbols = headers.hdrs.ELFHeaders32.symbols;
            if (symbols.len > 0) {
                const memseg = try memmap.findMemSeg(null, exe_filename, 0);
                const exe_base_addr = memseg.start_addr;

                // Find functions from symbol table.
                var func_symbols_tmp = std.ArrayList(ELF32_Sym).init(allocator);
                defer func_symbols_tmp.deinit();
                for (symbols) |symbol| {
                    if ((try decode_elf.SymbolType.parse(symbol.st_info)).stt == decode_elf.STT.stt_func) {
                        try funcs.append(Function.init(symbol.st_name_str, exe_base_addr + symbol.st_value));
                    }
                }
            } else {
                // TODO
            }
        },
        .ELFHeaders64 => {
            const symbols = headers.hdrs.ELFHeaders64.symbols;
            const dynsymbols = headers.hdrs.ELFHeaders64.dynsymbols;

            if (symbols.len > 0) {
                const memseg = try memmap.findMemSeg(null, exe_filename, 0);
                const exe_base_addr = memseg.start_addr;

                // Find functions from symbol table.
                var func_symbols_tmp = std.ArrayList(ELF64_Sym).init(allocator);
                defer func_symbols_tmp.deinit();
                for (symbols) |symbol| {
                    if ((try decode_elf.SymbolType.parse(symbol.st_info)).stt == decode_elf.STT.stt_func) {
                        try funcs.append(Function.init(symbol.st_name_str, exe_base_addr + symbol.st_value));
                    }
                }
            } else if (dynsymbols.len > 0) {
                // ----------------------------------------------------------------------------------------
                // WARNING: This implementation is not very accurate

                const memseg = try memmap.findMemSeg(null, exe_filename, 0);
                const exe_base_addr = memseg.start_addr;
                // const memseg_x = try memmap.findMemSeg("r-xp", exe_filename, 0);
                // const exe_x_base_addr = memseg_x.start_addr;

                // Add '_start' function.
                const entry_offset = headers.hdrs.ELFHeaders64.file_header.e_entry;
                try funcs.append(Function.init("_start", exe_base_addr + entry_offset));

                // Get the GOT address & entry size from `.plt.got` section.
                const section_headers = headers.hdrs.ELFHeaders64.section_headers;
                var plt_got_addr: usize = undefined;
                var plt_got_size: usize = undefined;
                var plt_got_entsize: usize = undefined;
                var got_addr: usize = undefined;
                for (section_headers) |sh| {
                    if (std.mem.eql(u8, sh.sh_name_str, ".plt.got")) {
                        plt_got_addr = sh.sh_addr;
                        plt_got_size = sh.sh_size;
                        plt_got_entsize = sh.sh_entsize;
                    }
                    if (std.mem.eql(u8, sh.sh_name_str, ".got")) {
                        got_addr = sh.sh_addr;
                    }
                }
                // Resolve function addresses using GOT address.
                var idx: usize = 0;
                for (dynsymbols) |symbol| {
                    // Check if the symbol type is FUNC.
                    if ((try decode_elf.SymbolType.parse(symbol.st_info)).stt == decode_elf.STT.stt_func) {
                        if (std.mem.eql(u8, symbol.st_name_str, "__libc_start_main")) continue;

                        var func_addr: usize = undefined;
                        if (symbol.st_value == 0) {
                            // func_addr = exe_base_addr + plt_got_addr + 0x20 + (plt_got_entsize * idx);
                            // func_addr = exe_base_addr + plt_got_addr + plt_got_entsize * (idx + 1);
                            // func_addr = exe_base_addr + plt_got_addr + 0x10 + plt_got_entsize * (idx + 1);
                            func_addr = exe_base_addr + plt_got_addr + plt_got_size + (plt_got_entsize * idx);
                        } else {
                            func_addr = exe_base_addr + symbol.st_value;
                        }
                        try funcs.append(Function.init(symbol.st_name_str, func_addr));
                        idx += 1;
                    }
                }
                // ----------------------------------------------------------------------------------------
            } else {
                // Find functions by parsing .text section.
                const section_headers = headers.hdrs.ELFHeaders64.section_headers;
                const text_data = try findTextSectionData(file_buf, section_headers);
                const start_offsets = try findFuncStartOffsets(allocator, text_data);
                try stdout.print("start_offsets len: {d}\n", .{start_offsets.len});
                if (start_offsets.len > 0) {
                    for (start_offsets) |offset| {
                        const func_addr = headers.hdrs.ELFHeaders64.file_header.e_entry + offset;
                        try stdout.print("func_addr: 0x{x}\n", .{func_addr});
                    }
                }
            }
        },
        .PEHeaders32 => {
            // TODO
        },
        .PEHeaders64 => {
            // TODO
        },
    }

    // Sort
    const funcs_own = try funcs.toOwnedSlice();
    std.mem.sort(Function, funcs_own, {}, cmpByFuncAddr);

    return funcs_own;
}

pub fn findFuncByName(funcs: []Function, name: []const u8) !Function {
    if (funcs.len == 0) return error.NoFunctions;
    for (funcs) |func| {
        if (std.mem.eql(u8, func.name, name)) return func;
    }
    return error.FunctionNotFound;
}

pub fn findFuncByAddr(funcs: []Function, addr: usize) !Function {
    if (funcs.len == 0) return error.NoFunctions;
    for (funcs) |func| {
        if (func.addr == addr) return func;
    }
}
