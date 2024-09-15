const std = @import("std");
const Build = std.Build;
const LazyPath = Build.LazyPath;
const Module = Build.Module;
const OptimizeMode = std.builtin.OptimizeMode;
const ResolvedTarget = Build.ResolvedTarget;
const Version = std.SemanticVersion;

const APP_NAME: []const u8 = "xex";

const targets: []const std.Target.Query = &.{
    // .{ .cpu_arch = .aarch64, .os_tag = .macos },
    // .{ .cpu_arch = .aarch64, .os_tag = .linux },
    .{ .cpu_arch = .x86_64, .os_tag = .linux },
    // .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    // .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
    // .{ .cpu_arch = .x86_64, .os_tag = .windows },
};

const common_sources: []const []const u8 = &.{
    "cs.c",
    "Mapping.c",
    "MCInst.c",
    "MCInstrDesc.c",
    "MCRegisterInfo.c",
    "SStream.c",
    "utils.c",
};

const sources_x86 = &.{
    "X86Disassembler.c",
    "X86DisassemblerDecoder.c",
    "X86IntelInstPrinter.c",
    "X86InstPrinterCommon.c",
    "X86Mapping.c",
    "X86Module.c",
    // separately handled
    // "X86ATTInstPrinter.c",
};

fn getDestDirName(allocator: std.mem.Allocator, target: std.Target.Query, version: []const u8) ![]u8 {
    const os_tag = @tagName(target.os_tag.?);
    const arch = @tagName(target.cpu_arch.?);

    return std.fmt.allocPrint(
        allocator,
        "{s}-{s}-{s}-{s}",
        .{ APP_NAME, os_tag, arch, version },
    );
}

// Inspired by https://github.com/oven-sh/bun/blob/main/build.zig
const BuildOptions = struct {
    optimize: OptimizeMode,
    version: []const u8,
    is_release: bool,

    const Self = @This();

    fn init(b: *Build) !Self {
        // const optimize = b.standardOptimizeOption(.{});
        const optimize = .ReleaseSafe;

        b.enable_wine = true;

        const version = b.option(
            []const u8,
            "version",
            "Application version",
        ) orelse "0.0.0";
        // Check if the version format is correct.
        _ = try Version.parse(version);

        const is_release = b.option(
            bool,
            "release",
            "Build for release",
        ) orelse false;

        return Self{
            .optimize = optimize,
            .version = version,
            .is_release = is_release,
        };
    }

    fn addExe(self: *Self, b: *Build, target: ResolvedTarget) *Build.Step.Compile {
        const exe = b.addExecutable(.{
            .name = APP_NAME,
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = self.optimize,
            .link_libc = true,
        });
        b.installArtifact(exe);

        // -------------------------------------------------------------------------------
        // Add Capstone
        // Reference: https://github.com/allyourcodebase/capstone/blob/main/build.zig
        const capstone = b.dependency("capstone", .{});

        exe.addIncludePath(capstone.path("include"));
        exe.installHeadersDirectory(capstone.path("include/capstone"), "capstone", .{});
        exe.installHeader(capstone.path("include/platform.h"), "capstone/platform.h");

        // exe.defineCMacro("CAPSTONE_DIET", null);                 <- It does not work correctly.
        exe.defineCMacro("CAPSTONE_USE_SYS_DYN_MEM", null);
        // exe.defineCMacro("CAPSTONE_X86_REDUCE", null);           <- It does not work correctly.
        // exe.defineCMacro("CAPSTONE_X86_ATT_DISABLE", null);      <- ERROR
        // exe.defineCMacro("CAPSTONE_HAS_OSXKERNEL", null);
        // exe.defineCMacro("CAPSTONE_DEBUG", null);
        exe.defineCMacro(b.fmt("CAPSTONE_HAS_X86", .{}), null);

        exe.addCSourceFiles(.{ .root = capstone.path(""), .files = common_sources });
        exe.addCSourceFiles(.{
            .root = capstone.path(b.fmt("arch/X86", .{})),
            .files = sources_x86,
        });
        exe.addCSourceFile(.{ .file = capstone.path("arch/X86/X86ATTInstPrinter.c") });
        // -------------------------------------------------------------------------------

        // Add options for executable (e.g. `xex --version`)
        const opts = b.addOptions();
        opts.addOption([]const u8, "version", self.version);
        exe.root_module.addOptions("build_options", opts);

        // Add dependencies
        exe.root_module.addImport("chameleon", b.dependency("chameleon", .{}).module("chameleon"));

        return exe;
    }
};

pub fn build(b: *Build) !void {
    const allocator = std.heap.page_allocator;

    var build_options = try BuildOptions.init(b);

    if (build_options.is_release) {
        for (targets) |t| {
            const target = b.resolveTargetQuery(t);
            const exe = build_options.addExe(b, target);

            const target_output_exe = b.addInstallArtifact(
                exe,
                .{
                    .dest_dir = .{
                        .override = .{
                            .custom = try getDestDirName(
                                allocator,
                                t,
                                build_options.version,
                            ),
                        },
                    },
                },
            );
            b.getInstallStep().dependOn(&target_output_exe.step);
        }
    } else {
        // Compile executables
        const target = b.standardTargetOptions(.{});
        const exe = build_options.addExe(b, target);

        // "zig build run"
        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }
        const run_step = b.step("run", "Run the app");
        run_step.dependOn(&run_cmd.step);

        // "zig build test"
        const exe_unit_tests = b.addTest(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = build_options.optimize,
        });
        const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_exe_unit_tests.step);
    }
}
