const build_options = @import("build_options");
const std = @import("std");
const stdout = @import("./common.zig").stdout;
const util = @import("./common.zig").stdout;
const File = @import("./file.zig").File;
const Option = @import("./option.zig").Option;

const USAGE =
    \\xex - reverse engineering tool
    \\
    \\USAGE
    \\-----
    \\  xex <OPTIONS> <FILE>
    \\
    \\OPTIONS
    \\-------
    \\
    \\  DUMP
    \\  ----
    \\    --info                    : Dump file information.
    \\    --hash                    : Dump file hashes.
    \\    --headers                 : Dump headers.
    \\    --file-header             : Dump file header.
    \\    --program-headers         : Dump program headers.
    \\    --sections                : Dump sections.
    \\    --symbols, --syms         : Dump symbol table.
    \\    --dynsymbols, --dynsyms   : Dump dynamic symbol table for ELF.
    \\    --export-table            : Dump export table for PE.
    \\    --import-table            : Dump import table for PE.
    \\    --functions, --funcs      : Dump functions.
    \\
    \\  GENERAL
    \\  -------
    \\    -h, --help      : Display the usage of the xex.
    \\    -v, --version   : Display the version of the xex.
    \\
    \\EXAMPLES: DEBUG
    \\---------------
    \\  xex example.exe                 : Start debugging 'example.exe'.
    \\  xex /bin/ls -al ./              : Start debugging with arguments.
    \\
    \\EXAMPLES: DUMP
    \\--------------
    \\  xex --info example.exe          : Dump file information.
    \\  xex --headers example.exe       : Dump headers.
    \\  xex --file-header example.exe   : Dump file header (ELF Header, DOS Header).
;

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
    export_table: bool,
    import_table: bool,
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
            .export_table = false,
            .import_table = false,
            .functions = false,
            .help = false,
            .version = false,
        };
    }
};

pub const Cli = struct {
    flags: Flags,
    file_path: []const u8,
    file_args: ?[*:null]const ?[*:0]const u8, // it is used for passing arguments to execveZ

    const Self = @This();

    pub fn parse(allocator: std.mem.Allocator) !Self {
        const args = try std.process.argsAlloc(allocator);
        defer std.process.argsFree(allocator, args);

        if (args.len < 2) {
            try stdout.print("{s}\n", .{USAGE});
            std.posix.exit(0);
        }

        // Parse flag and get positional arguments
        var flags = Flags.init();
        var pos_args_start: bool = false;
        var pos_args_start_idx: usize = 1;
        // var positional_args_end_idx: usize = 1;
        var pos_args_len: usize = 0;
        for (args[1..]) |arg| {
            if (std.mem.startsWith(u8, arg, "--") or std.mem.startsWith(u8, arg, "-")) {
                // Options
                if (pos_args_start) continue;
                if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
                    flags.help = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
                    flags.version = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--info")) {
                    flags.info = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--hash")) {
                    flags.hash = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--headers")) {
                    flags.headers = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--file-header")) {
                    flags.file_header = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--program-headers")) {
                    flags.program_headers = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--sections")) {
                    flags.sections = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--symbols") or std.mem.eql(u8, arg, "--syms")) {
                    flags.symbols = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--dynsymbols") or std.mem.eql(u8, arg, "--dynsyms")) {
                    flags.dynsymbols = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--export-table")) {
                    flags.export_table = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--import-table")) {
                    flags.import_table = true;
                    pos_args_start_idx += 1;
                } else if (std.mem.eql(u8, arg, "--functions") or std.mem.eql(u8, arg, "--funcs")) {
                    flags.functions = true;
                    pos_args_start_idx += 1;
                } else {
                    return error.InvalidArguments;
                }
            } else {
                // Positional arguments.
                pos_args_start = true;
                pos_args_len += 1;
            }
        }

        if (flags.help) {
            try stdout.print("{s}\n", .{USAGE});
            std.posix.exit(0);
        }
        if (flags.version) {
            try stdout.print("xex v{s}\n", .{build_options.version});
            std.posix.exit(0);
        }
        if (pos_args_len == 0) {
            try stdout.print("{s}\n", .{USAGE});
            std.posix.exit(0);
        }

        const file_path_len = std.mem.len(std.os.argv[pos_args_start_idx]);

        return Self{
            .flags = flags,
            .file_path = std.os.argv[pos_args_start_idx][0..file_path_len],
            .file_args = @ptrCast(std.os.argv[pos_args_start_idx..].ptr),
        };
    }
};
