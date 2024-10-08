const std = @import("std");
const stdout = @import("./common/stdout.zig");
const FileType = @import("./file.zig").FileType;
const Function = @import("./func.zig").Function;

pub const DebugInfo = struct {
    allocator: std.mem.Allocator,
    elf: ?std.debug.Dwarf.ElfModule,
    pe: ?std.debug.Pdb.Module,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        file_path: []const u8,
        file_buf: []const u8,
        file_type: FileType,
        funcs: []Function,
    ) !Self {
        _ = file_buf;

        switch (file_type) {
            FileType.elf32, FileType.elf64 => {
                var sections: std.debug.Dwarf.SectionArray = std.debug.Dwarf.null_section_array;
                const debug_info = std.debug.SelfInfo.readElfDebugInfo(
                    allocator,
                    file_path,
                    null,
                    null,
                    &sections,
                    null,
                ) catch null;

                // Update pc_range of functions.
                if (debug_info) |di| {
                    const dwarf = di.dwarf;
                    const dwarf_func_list = dwarf.func_list;
                    for (dwarf_func_list.items) |*dwarf_func| {
                        if (dwarf_func.pc_range == null) {
                            // Find target functions.
                            for (funcs) |func| {
                                if (std.mem.eql(u8, func.name, dwarf_func.name.?)) {
                                    dwarf_func.pc_range = .{
                                        .start = func.start_addr - func.base_addr,
                                        .end = func.end_addr - func.base_addr,
                                    };
                                }
                            }
                        }
                    }
                }

                return Self{
                    .allocator = allocator,
                    .elf = debug_info,
                    .pe = null,
                };
            },
            FileType.pe32, FileType.pe64 => {
                // TODO: Implement this.
                // const coff_obj = std.coff.Coff.init(file_buf, true);
                // const debug_info = try std.debug.SelfInfo.readCoffDebugInfo(
                //     allocator,
                //     &coff_obj,
                // ) catch null;
                return Self{
                    .allocator = allocator,
                    .elf = null,
                    .pe = null,
                };
            },
            FileType.unknown => return error.UnknownFileType,
        }
    }

    pub fn deinit(self: *Self) void {
        if (self.elf) |*elf| {
            // self.allocator.free(elf);
            elf.deinit(self.allocator);
        }
    }
};

// ----------------------------------------------------------------
// DWARF STRUCTURE
//
// const debug_info = self.debug_info.elf.?;
// const dwarf = debug_info.dwarf;
// try stdout.print("debug_info: {}\n", .{debug_info});
// try stdout.print("base_address: 0x{x}\n", .{debug_info.base_address});
// try stdout.print("dwarf endian: {}\n", .{dwarf.endian});
// try stdout.print("dwarf sections: {any}\n", .{dwarf.sections});
// try stdout.print("dwarf abbrev_table_list: {any}\n", .{dwarf.abbrev_table_list.items});
// try stdout.print("dwarf compile unit list: {any}\n", .{dwarf.compile_unit_list.items});
// try stdout.print("dwarf func list: {any}\n", .{dwarf.func_list.items});
// try stdout.print("mapped_memory: {x}\n", .{dwarf.mapped_memory});
// ----------------------------------------------------------------
