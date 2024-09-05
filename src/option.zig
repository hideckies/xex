const std = @import("std");
const File = @import("./file.zig").File;

pub const Flags = struct {
    // DUMP
    info: bool,
    hash: bool,
    headers: bool,
    file_header: bool,
    program_headers: bool,
    sections: bool,
    symbols: bool,
    dynsymbols: bool,
    functions: bool,
    // GENERAL
    help: bool,
    version: bool,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .info = false,
            .hash = false,
            .headers = false,
            .file_header = false,
            .program_headers = false,
            .sections = false,
            .symbols = false,
            .dynsymbols = false,
            .functions = false,
            .help = false,
            .version = false,
        };
    }
};

pub const Option = struct {
    flags: Flags,
    // file_path: []const u8,
    // file_args: ?[*:null]const ?[*:0]const u8, // it is used for passing arguments to execveZ
    // file_buf: []const u8,
    // file_type: FileType,
    file: File,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .flags = Flags.init(),
            // .file_path = undefined,
            // .file_args = null,
            // .file_buf = undefined,
            // .file_type = undefined,
            .file = undefined,
        };
    }
};
