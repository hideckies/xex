const std = @import("std");
const chameleon = @import("chameleon");

pub fn print(comptime _format: []const u8, args: anytype) !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    try stdout.print(_format, args);
    try bw.flush();
}

pub fn print_error(allocator: std.mem.Allocator, comptime _format: []const u8, args: anytype) !void {
    var cham = chameleon.initRuntime(.{ .allocator = allocator });
    defer cham.deinit();

    const base_msg = try std.fmt.allocPrint(allocator, _format, args);
    const msg = try std.fmt.allocPrint(
        allocator,
        "[{s}] {s}",
        .{ try cham.red().fmt("x", .{}), base_msg },
    );
    return print("{s}", .{msg});
}

pub fn print_info(allocator: std.mem.Allocator, comptime _format: []const u8, args: anytype) !void {
    var cham = chameleon.initRuntime(.{ .allocator = allocator });
    defer cham.deinit();

    const base_msg = try std.fmt.allocPrint(allocator, _format, args);
    const msg = try std.fmt.allocPrint(
        allocator,
        "[{s}] {s}",
        .{ try cham.cyanBright().fmt("i", .{}), base_msg },
    );
    return print("{s}", .{msg});
}

pub fn banner() !void {
    try print("XEX\n", .{});
}
