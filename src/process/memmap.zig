const std = @import("std");
const stdout = @import("../common.zig").stdout;

const BaseAddrInfo = @import("./base_addr_info.zig").BaseAddrInfo;

pub const MemorySegment = struct {
    allocator: std.mem.Allocator,
    start_addr: usize,
    end_addr: usize,
    perms: []const u8,
    offset: usize,
    dev: []const u8,
    inode: usize,
    path: []const u8,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        start_addr: usize,
        end_addr: usize,
        perms: []const u8,
        offset: usize,
        dev: []const u8,
        inode: usize,
        path: []const u8,
    ) !Self {
        return Self{
            .allocator = allocator,
            .start_addr = start_addr,
            .end_addr = end_addr,
            .perms = perms,
            .offset = offset,
            .dev = dev,
            .inode = inode,
            .path = path,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.perms);
        self.allocator.free(self.dev);
        self.allocator.free(self.path);
    }
};

pub const MemoryMap = struct {
    allocator: std.mem.Allocator,
    segs: []MemorySegment,
    base_addr_info: BaseAddrInfo,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pid: std.posix.pid_t, file_path: []const u8) !Self {
        // Parse memory map.
        const maps_path = try std.fmt.allocPrint(
            allocator,
            "/proc/{d}/maps",
            .{pid},
        );
        defer allocator.free(maps_path);

        const file = try std.fs.openFileAbsolute(maps_path, .{});
        defer file.close();

        var reader = file.reader();
        var line = std.ArrayList(u8).init(allocator);
        defer line.deinit();

        var memsegs = std.ArrayList(MemorySegment).init(allocator);
        defer memsegs.deinit();

        while (true) {
            line.clearRetainingCapacity();

            reader.streamUntilDelimiter(line.writer(), '\n', null) catch |err| {
                switch (err) {
                    error.EndOfStream => break,
                    else => unreachable,
                }
            };

            var line_spl = std.mem.splitSequence(u8, line.items, " ");
            // The start-end addresses part.
            const addrs = line_spl.next().?;
            // The permissions part.
            var perms = std.ArrayList(u8).init(allocator);
            defer perms.deinit();
            try perms.appendSlice(line_spl.next().?);
            // The offset part.
            const offset = try std.fmt.parseInt(usize, line_spl.next().?, 16);
            // The dev part.
            var dev = std.ArrayList(u8).init(allocator);
            defer dev.deinit();
            try dev.appendSlice(line_spl.next().?);
            // The inode part.
            const inode = try std.fmt.parseInt(usize, line_spl.next().?, 16);
            // The file path part.
            var path = std.ArrayList(u8).init(allocator);
            defer path.deinit();
            while (line_spl.next()) |item| {
                if (!std.mem.eql(u8, item, "")) {
                    try path.appendSlice(item);
                    break;
                }
            }

            // Get start address and end address.
            var addrs_spl = std.mem.splitSequence(u8, addrs, "-");
            const start_addr = try std.fmt.parseInt(usize, addrs_spl.next().?, 16);
            const end_addr = try std.fmt.parseInt(usize, addrs_spl.next().?, 16);

            try memsegs.append(try MemorySegment.init(
                allocator,
                start_addr,
                end_addr,
                try perms.toOwnedSlice(),
                offset,
                try dev.toOwnedSlice(),
                inode,
                try path.toOwnedSlice(),
            ));
        }

        // Get base addresses for each segment.
        var base_addr_info = BaseAddrInfo{
            .exe_base_addr = null,
            .exe_end_addr = null,
            .ld_base_addr = null,
            .ld_end_addr = null,
        };

        // Find base addresses
        for (memsegs.items) |memseg| {
            if (memseg.path.len > 0) {
                if (base_addr_info.exe_base_addr == null) {
                    if (std.mem.containsAtLeast(u8, memseg.path, 1, file_path)) {
                        base_addr_info.exe_base_addr = memseg.start_addr;
                        continue;
                    }
                }
                if (base_addr_info.ld_base_addr == null) {
                    if (std.mem.containsAtLeast(u8, memseg.path, 1, "ld-linux")) {
                        base_addr_info.ld_base_addr = memseg.start_addr;
                        continue;
                    }
                }
            }
        }

        // Find end addresses
        for (memsegs.items, 0..) |_, i| {
            const idx = memsegs.items.len - 1 - i;
            const memseg = memsegs.items[idx];
            if (memseg.path.len > 0) {
                if (base_addr_info.exe_end_addr == null) {
                    if (std.mem.containsAtLeast(u8, memseg.path, 1, file_path)) {
                        base_addr_info.exe_end_addr = memseg.end_addr;
                        continue;
                    }
                }
                if (base_addr_info.ld_end_addr == null) {
                    if (std.mem.containsAtLeast(u8, memseg.path, 1, "ld-linux")) {
                        base_addr_info.ld_end_addr = memseg.end_addr;
                        continue;
                    }
                }
            }
        }

        return Self{
            .allocator = allocator,
            .segs = try memsegs.toOwnedSlice(),
            .base_addr_info = base_addr_info,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.segs) |*seg| {
            seg.deinit();
        }
        self.allocator.free(self.segs);
    }

    pub fn findMemSeg(
        self: *Self,
        perms: ?[]const u8,
        path: []const u8,
        index: usize,
    ) !MemorySegment {
        const allocator = std.heap.page_allocator;
        var found_segs = std.ArrayList(MemorySegment).init(allocator);
        defer found_segs.deinit();

        for (self.segs) |seg| {
            if (perms) |p| {
                if (std.mem.eql(u8, seg.perms, p) and std.mem.containsAtLeast(u8, seg.path, 1, path)) {
                    try found_segs.append(seg);
                }
            } else {
                if (std.mem.containsAtLeast(u8, seg.path, 1, path)) {
                    try found_segs.append(seg);
                }
            }
        }

        if (found_segs.items.len == 0) {
            return error.MemorySegmentNotFound;
        }

        for (found_segs.items, 0..) |seg, i| {
            if (i == index) {
                return seg;
            }
        }

        return error.IndexError;
    }
};
