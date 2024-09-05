const std = @import("std");
const stdout = @import("../common.zig").stdout;
const Debugger = @import("../dbg.zig").Debugger;
const findFuncByName = @import("../func.zig").findFuncByName;

// Get address from argument.
pub fn getAddrFromArg(dbg: *Debugger, arg: []const u8) !usize {
    var addr: usize = 0;

    // Find function address at first.
    const target_func = findFuncByName(dbg.funcs, arg) catch null;
    if (target_func) |func| {
        return func.addr;
    }

    // Get absolute address from hex.
    if (std.mem.startsWith(u8, arg, "0x")) {
        addr = std.fmt.parseInt(usize, arg[2..], 16) catch {
            return error.InvalidArgument;
        };
    } else {
        addr = std.fmt.parseInt(usize, arg, 16) catch {
            return error.InvalidArgument;
        };
    }
    return addr;
}
