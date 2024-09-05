const stdout = @import("../common.zig").stdout;
const Command = @import("../readline.zig").Command;
const Debugger = @import("../dbg.zig").Debugger;

pub fn unknown(dbg: *Debugger, cmd: Command) !void {
    try stdout.print_error(dbg.allocator, "Unknown command: {s}\n", .{cmd.command.items});
}
