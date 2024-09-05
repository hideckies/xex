const Command = @import("../readline.zig").Command;
const Debugger = @import("../dbg.zig");

pub fn help(cmd: Command) !void {
    if (cmd.command_args.items.len == 0) {
        try cmd.help();
    } else {
        try cmd.helpCommand(cmd.command_args.items[0]);
    }
}
