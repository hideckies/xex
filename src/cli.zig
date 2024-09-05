const build_options = @import("build_options");
const std = @import("std");
const stdout = @import("./common.zig").stdout;
const util = @import("./common.zig").stdout;
const File = @import("./file.zig").File;
const Flags = @import("./option.zig").Flags;
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
    \\    --dynsymbols, --dynsyms   : Dump dynamic symbol table.
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

pub fn parse(allocator: std.mem.Allocator, option: *Option) !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try stdout.print("{s}\n", .{USAGE});
        std.posix.exit(0);
    }

    // Parse flag and get positional arguments
    var pos_args_start: bool = false;
    var pos_args_start_idx: usize = 1;
    // var positional_args_end_idx: usize = 1;
    var pos_args_len: usize = 0;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--") or std.mem.startsWith(u8, arg, "-")) {
            // Options
            if (pos_args_start) continue;
            if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
                option.flags.help = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
                option.flags.version = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--info")) {
                option.flags.info = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--hash")) {
                option.flags.hash = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--headers")) {
                option.flags.headers = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--file-header")) {
                option.flags.file_header = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--program-headers")) {
                option.flags.program_headers = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--sections")) {
                option.flags.sections = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--symbols") or std.mem.eql(u8, arg, "--syms")) {
                option.flags.symbols = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--dynsymbols") or std.mem.eql(u8, arg, "--dynsyms")) {
                option.flags.dynsymbols = true;
                pos_args_start_idx += 1;
            } else if (std.mem.eql(u8, arg, "--functions") or std.mem.eql(u8, arg, "--funcs")) {
                option.flags.functions = true;
                pos_args_start_idx += 1;
            } else {
                return error.InvalidOption;
            }
        } else {
            // Positional arguments.
            pos_args_start = true;
            pos_args_len += 1;
        }
    }

    if (option.flags.help) {
        try stdout.print("{s}\n", .{USAGE});
        std.posix.exit(0);
    }
    if (option.flags.version) {
        try stdout.print("xex v{s}\n", .{build_options.version});
        std.posix.exit(0);
    }
    if (pos_args_len == 0) {
        try stdout.print("{s}\n", .{USAGE});
        std.posix.exit(0);
    }

    // Set option
    const len = std.mem.len(std.os.argv[pos_args_start_idx]);
    const file_path = std.os.argv[pos_args_start_idx][0..len];
    const file_args: ?[*:null]const ?[*:0]const u8 = @ptrCast(std.os.argv[pos_args_start_idx..].ptr);

    option.file = try File.init(file_path, file_args);

    // const file = try std.fs.cwd().openFile(option.file_path, .{});
    // defer file.close();
    // const reader = file.reader();

    // const file_size = try file.getEndPos();
    // option.file_buf = try file.readToEndAlloc(std.heap.page_allocator, file_size);

    // option.file_type = try FileType.detect(reader);
}
