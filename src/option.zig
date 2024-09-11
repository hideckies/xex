const std = @import("std");
const File = @import("./file.zig").File;

pub const Option = struct {
    file: File,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        file_path: []const u8,
        file_args: ?[*:null]const ?[*:0]const u8,
    ) !Self {
        return Self{
            .file = try File.init(allocator, file_path, file_args),
        };
    }

    pub fn deinit(self: *Self) void {
        self.file.deinit();
    }
};
