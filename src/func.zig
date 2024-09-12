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
const Disas = @import("./disas.zig").Disas;

const c = @cImport({
    @cInclude("dlfcn.h");
    @cInclude("unistd.h");
});

pub const Function = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    base_addr: usize,
    start_addr: usize,
    end_addr: usize,

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

        return writer.print("{s}-{s}\t{s}", .{
            try cham.greenBright().fmt("0x{x}", .{self.start_addr}),
            try cham.greenBright().fmt("0x{x}", .{self.end_addr}),
            try cham.yellow().fmt("{s}", .{self.name}),
        });
    }

    pub fn init(
        allocator: std.mem.Allocator,
        name: []const u8,
        base_addr: usize,
        start_addr: usize,
        end_addr: usize,
    ) Self {
        return Self{
            .allocator = allocator,
            .name = name,
            .base_addr = base_addr,
            .start_addr = start_addr,
            .end_addr = end_addr,
        };
    }
};

// Helper functions for sorting functions.
fn cmpByFuncAddr(context: void, a: Function, b: Function) bool {
    _ = context;
    if (a.start_addr < b.start_addr) {
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

pub fn getFunctions(
    allocator: std.mem.Allocator,
    process: Process,
    headers: Headers,
    file_path: []const u8,
    file_buf: []const u8,
    breakpoints: std.ArrayList(Breakpoint),
) ![]Function {
    _ = file_buf;

    const file_name = std.fs.path.basename(file_path);

    var memmap = process.memmap;

    var funcs = std.ArrayList(Function).init(allocator);
    defer funcs.deinit();

    switch (headers.hdrs) {
        .ELFHeaders32 => {
            const symbols = headers.hdrs.ELFHeaders32.symbols;
            const dynsymbols = headers.hdrs.ELFHeaders64.dynsymbols;

            if (symbols.len > 0) {
                const memseg = try memmap.findMemSeg(null, file_name, 0);
                const exe_base_addr = memseg.start_addr;

                // Find functions from symbol table.
                var func_symbols_tmp = std.ArrayList(ELF32_Sym).init(allocator);
                defer func_symbols_tmp.deinit();
                for (symbols) |symbol| {
                    if ((try decode_elf.SymbolType.parse(symbol.st_info)).stt == decode_elf.STT.stt_func) {
                        try funcs.append(Function.init(
                            allocator,
                            symbol.st_name_str,
                            exe_base_addr,
                            exe_base_addr + symbol.st_value,
                            exe_base_addr + symbol.st_value + symbol.st_size,
                        ));
                    }
                }
            }
            if (dynsymbols.len > 0) {
                // TODO
            }
        },
        .ELFHeaders64 => {
            const symbols = headers.hdrs.ELFHeaders64.symbols;
            const dynsymbols = headers.hdrs.ELFHeaders64.dynsymbols;

            if (symbols.len > 0) {
                const memseg = try memmap.findMemSeg(null, file_name, 0);
                const exe_base_addr = memseg.start_addr;

                for (symbols) |symbol| {
                    if ((try decode_elf.SymbolType.parse(symbol.st_info)).stt == decode_elf.STT.stt_func) {
                        if (symbol.st_value == 0) continue;

                        // Get the start address of the function.
                        const func_start_addr = exe_base_addr + symbol.st_value;

                        // Get the end address of the function.
                        var disas = try Disas.init(
                            allocator,
                            process.pid,
                            breakpoints,
                            func_start_addr,
                            300,
                            null,
                        );
                        defer disas.deinit();
                        const func_end_addr = try disas.findFuncEndAddr();

                        try funcs.append(Function.init(
                            allocator,
                            symbol.st_name_str,
                            exe_base_addr,
                            func_start_addr,
                            func_end_addr,
                        ));
                    }
                }
            }

            if (dynsymbols.len > 0) {
                // ----------------------------------------------------------------------------------------
                // WARNING: This implementation is not very accurate

                const memseg = try memmap.findMemSeg(null, file_name, 0);
                const exe_base_addr = memseg.start_addr;

                // Add '_start' function if it does not exist.
                if (symbols.len == 0) {
                    const entry_offset = headers.hdrs.ELFHeaders64.file_header.e_entry;
                    const func_start_addr = exe_base_addr + entry_offset;

                    // Get the end address of the function.
                    var disas = try Disas.init(
                        allocator,
                        process.pid,
                        breakpoints,
                        func_start_addr,
                        300,
                        null,
                    );
                    defer disas.deinit();
                    const func_end_addr = try disas.findFuncEndAddr();

                    try funcs.append(Function.init(
                        allocator,
                        "_start",
                        exe_base_addr,
                        func_start_addr,
                        func_end_addr, // TODO: How to find the end address?
                    ));
                }

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
                        if (std.mem.eql(u8, symbol.st_name_str, "__libc_start_main")) continue; // TODO: How to treat the '__libc_start_main'?

                        var func_start_addr: usize = 0;
                        if (symbol.st_value == 0) {
                            func_start_addr = exe_base_addr + plt_got_addr + plt_got_size + (plt_got_entsize * idx);
                        } else {
                            func_start_addr = exe_base_addr + symbol.st_value;
                        }

                        // Get the end address of the function.
                        // const func_end_addr = func_start_addr + plt_got_size;
                        var disas = try Disas.init(
                            allocator,
                            process.pid,
                            breakpoints,
                            func_start_addr,
                            300,
                            null,
                        );
                        defer disas.deinit();
                        const func_end_addr = try disas.findFuncEndAddr();

                        try funcs.append(Function.init(
                            allocator,
                            symbol.st_name_str,
                            exe_base_addr,
                            func_start_addr,
                            func_end_addr,
                        ));
                        idx += 1;
                    }
                }
                // ----------------------------------------------------------------------------------------
            }

            // {
            //     // Find functions by parsing .text section.
            //     const section_headers = headers.hdrs.ELFHeaders64.section_headers;
            //     const text_data = try findTextSectionData(file_buf, section_headers);
            //     const start_offsets = try findFuncStartOffsets(allocator, text_data);
            //     if (start_offsets.len > 0) {
            //         for (start_offsets) |offset| {
            //             const func_addr = headers.hdrs.ELFHeaders64.file_header.e_entry + offset;
            //             _ = func_addr;
            //         }
            //     }
            // }
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
