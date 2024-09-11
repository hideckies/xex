const std = @import("std");
const chameleon = @import("chameleon");
const Cli = @import("./cli.zig").Cli;
const Debugger = @import("./dbg.zig").Debugger;
const handler = @import("./handler.zig");
const Option = @import("./option.zig").Option;
const symbol = @import("./common.zig").symbol;
const stdout = @import("./common.zig").stdout;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const cli = Cli.parse(gpa.allocator()) catch |err| {
        switch (err) {
            error.InvalidArguments => return stdout.printError("Invalid arguments.\n", .{}),
            else => return stdout.printError("Failed to pasrse arguments: {}\n", .{err}),
        }
    };
    var option = Option.init(gpa.allocator(), cli.file_path, cli.file_args) catch |err| {
        return stdout.printError("Failed to initialize option: {}\n", .{err});
    };
    defer option.deinit();

    var dbg = Debugger.init(gpa.allocator(), option) catch |err| {
        return stdout.printError("Failed to initialize debugger: {}\n", .{err});
    };
    defer dbg.deinit();

    // Static Analysis: Dump information (no debugging)
    // if (option.flags.info) {
    //     return handler.analysis.info(&dbg);
    // } else if (option.flags.hash) {
    //     return handler.analysis.hash(&dbg);
    // } else if (option.flags.headers) {
    //     return handler.analysis.headers(&dbg);
    // } else if (option.flags.file_header) {
    //     return handler.analysis.file_header(&dbg);
    // } else if (option.flags.program_headers) {
    //     return handler.analysis.program_headers(&dbg);
    // } else if (option.flags.sections) {
    //     return handler.analysis.sections(&dbg);
    // } else if (option.flags.symbols) {
    //     return handler.analysis.symbols(&dbg);
    // } else if (option.flags.dynsymbols) {
    //     return handler.analysis.dynsymbols(&dbg);
    // } else if (option.flags.functions) {
    //     return handler.analysis.functions(&dbg);
    // }

    // // Run debugger if flag is not set.
    // dbg.run() catch |err| {
    //     return stdout.print_error(gpa.allocator(), "Failed to debug: {}\n", .{err});
    // };
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
