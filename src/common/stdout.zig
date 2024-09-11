const std = @import("std");
const chameleon = @import("chameleon");

pub fn print(comptime _format: []const u8, args: anytype) !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    try stdout.print(_format, args);
    try bw.flush();
}

pub fn printError(comptime _format: []const u8, args: anytype) !void {
    comptime var cham = chameleon.initComptime();
    return print("[{s}] " ++ _format, .{cham.red().fmt("x")} ++ args);
}

pub fn printInfo(comptime _format: []const u8, args: anytype) !void {
    comptime var cham = chameleon.initComptime();
    return print("[{s}] " ++ _format, .{cham.cyanBright().fmt("x")} ++ args);
}
