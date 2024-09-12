const stdout = @import("../common.zig").stdout;
const Command = @import("../readline.zig").Command;
const Debugger = @import("../dbg.zig").Debugger;

pub fn unknown(dbg: *Debugger, cmd: Command) !void {
    _ = dbg;
    try stdout.printError("Unknown command: {s}\n", .{cmd.command.items});
}
