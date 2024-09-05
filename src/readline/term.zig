const builtin = @import("builtin");
const std = @import("std");
const stdout = @import("../common.zig").stdout;

pub const Termios = extern struct {
    fd: i32,
    raw_old: std.posix.termios,
    raw_new: std.posix.termios,

    const Self = @This();

    pub fn init(fd: i32) !Self {
        const raw_old = try std.posix.tcgetattr(fd);

        var raw_new = raw_old;
        raw_new.lflag.ECHO = false;
        raw_new.lflag.ICANON = false;
        try std.posix.tcsetattr(fd, .FLUSH, raw_new);

        return Self{
            .fd = fd,
            .raw_old = raw_old,
            .raw_new = raw_new,
        };
    }

    pub fn deinit(self: *Self) void {
        std.posix.tcsetattr(self.fd, .FLUSH, self.raw_old) catch {};
    }
};
