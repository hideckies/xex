const c = @cImport({
    @cInclude("capstone/capstone.h");
});

pub const CapstoneError = error{
    OK,
    Memory,
    Arch,
    Handle,
    Csh,
    Mode,
    Option,
    Detail,
    MemSetup,
    Version,
    Diet,
    SkipData,
    X86_ATT,
    X86_INTEL,
    X86_MASM,
};

pub fn parseErrorCode(error_code: c_uint) ?CapstoneError {
    switch (error_code) {
        c.CS_ERR_OK => return CapstoneError.OK,
        c.CS_ERR_MEM => return CapstoneError.Memory,
        c.CS_ERR_ARCH => return CapstoneError.Arch,
        c.CS_ERR_HANDLE => return CapstoneError.Handle,
        c.CS_ERR_CSH => return CapstoneError.Csh,
        c.CS_ERR_MODE => return CapstoneError.Mode,
        c.CS_ERR_OPTION => return CapstoneError.Option,
        c.CS_ERR_DETAIL => return CapstoneError.Detail,
        c.CS_ERR_MEMSETUP => return CapstoneError.MemSetup,
        c.CS_ERR_VERSION => return CapstoneError.Version,
        c.CS_ERR_DIET => return CapstoneError.Diet,
        c.CS_ERR_SKIPDATA => return CapstoneError.SkipData,
        c.CS_ERR_X86_ATT => return CapstoneError.X86_ATT,
        c.CS_ERR_X86_INTEL => return CapstoneError.X86_INTEL,
        c.CS_ERR_X86_MASM => return CapstoneError.X86_MASM,
        else => return null,
    }
}
