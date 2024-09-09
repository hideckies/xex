const stdout = @import("../common/stdout.zig");

pub const BaseAddrInfo = struct {
    exe_base_addr: ?usize,
    exe_end_addr: ?usize,
    ld_base_addr: ?usize,
    ld_end_addr: ?usize,

    const Self = @This();

    pub fn getOffset(self: Self, addr: usize) !usize {
        if (self.exe_base_addr.? <= addr and addr <= self.exe_end_addr.?) {
            return addr - self.exe_base_addr.?;
        } else if (self.ld_base_addr.? <= addr and addr <= self.ld_end_addr.?) {
            return addr - self.ld_base_addr.?;
        }
        return error.AddressOffsetNotFound;
    }
};
