const builtin = @import("builtin");
const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("./common.zig").stdout;
const Breakpoint = @import("./breakpoint.zig").Breakpoint;
const DebugInfo = @import("./debug_info.zig").DebugInfo;
const handler = @import("./handler.zig");
const Headers = @import("./headers.zig").Headers;
const machine = @import("./machine.zig");
const Option = @import("./option.zig").Option;
const readline = @import("./readline.zig");
const reg = @import("./reg.zig");
const Process = @import("./process.zig").Process;
const ptrace = @import("./process.zig").ptrace;
const func = @import("./func.zig");
const Function = func.Function;

pub const Debugger = struct {
    allocator: std.mem.Allocator,
    option: Option,
    machine: machine.Machine,
    headers: Headers,
    debug_info: DebugInfo,
    running: bool,
    process: Process,
    funcs: []Function,
    breakpoints: std.ArrayList(Breakpoint),

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        option: Option,
    ) !Self {
        const hdrs = try Headers.init(
            allocator,
            option.file.path,
            option.file.type_,
        );
        const process = try Process.init(
            allocator,
            option.file.path,
            option.file.args.?,
        );
        const breakpoints = std.ArrayList(Breakpoint).init(allocator);
        const funcs = try func.getFunctions(
            allocator,
            process,
            hdrs,
            option.file.path,
            option.file.buf,
            breakpoints,
        );

        return Debugger{
            .allocator = allocator,
            .option = option,
            .machine = try machine.Machine.init(allocator),
            .headers = hdrs,
            .debug_info = try DebugInfo.init(
                allocator,
                option.file.path,
                option.file.buf,
                option.file.type_,
                funcs,
            ),
            .running = false,
            .process = process,
            .funcs = funcs,
            .breakpoints = breakpoints,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.debug_info.deinit();
        self.process.deinit();
        self.allocator.free(self.funcs);
        self.breakpoints.deinit();
    }

    pub fn run(self: *Self) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var cham = chameleon.initRuntime(.{ .allocator = arena_allocator });
        defer cham.deinit();

        try stdout.printInfo(
            "Start debugging with child process ({s}).\n",
            .{try cham.cyanBright().fmt("{d}", .{self.process.pid})},
        );
        try stdout.printInfo(
            "Run '{s}' or '{s}' for the usage.\n",
            .{ try cham.cyanBright().fmt("?", .{}), try cham.cyanBright().fmt("help", .{}) },
        );

        // Handle commands
        const reader = std.io.getStdIn().reader();
        const writer = std.io.getStdOut().writer();
        var command = try readline.Command.init(self.allocator, reader.context.handle, self.process.pid);
        defer command.deinit();
        while (true) {
            try command.readCommand(reader, writer);
            switch (command.command_type) {
                // GENERAL
                readline.CommandType.help => try handler.general.help(command),
                readline.CommandType.quit => break,
                // ANALYSIS
                readline.CommandType.info => try handler.analysis.info(self),
                readline.CommandType.hash => try handler.analysis.hash(self),
                readline.CommandType.headers => try handler.analysis.headers(self),
                readline.CommandType.file_header => try handler.analysis.file_header(self),
                readline.CommandType.program_headers => try handler.analysis.program_headers(self),
                readline.CommandType.sections => try handler.analysis.sections(self),
                readline.CommandType.symbols => try handler.analysis.symbols(self),
                readline.CommandType.dynsymbols => try handler.analysis.dynsymbols(self),
                readline.CommandType.functions => try handler.analysis.functions(self),
                readline.CommandType.disassemble => try handler.analysis.disassemble(self, command),
                // readline.CommandType.decompile => try handler.analysis.decompile(self, command),
                // BREAKPOINTS
                readline.CommandType.breakpoint => try handler.breakpoints.breakpoint(self, command),
                readline.CommandType.breakpoint_add => try handler.breakpoints.breakpointAdd(self, command),
                readline.CommandType.breakpoint_delete => try handler.breakpoints.breakpointDelete(self, command),
                readline.CommandType.breakpoints => try handler.breakpoints.breakpoints(self),
                // RUNNING
                readline.CommandType.conti => try handler.running.conti(self, &command),
                readline.CommandType.stepi => try handler.running.stepi(self, &command),
                readline.CommandType.steps => try handler.running.steps(self, &command),
                readline.CommandType.restart => try handler.running.restart(self, &command),
                // VALUES
                readline.CommandType.registers => try handler.values.registers(self),
                readline.CommandType.printb,
                readline.CommandType.printd,
                readline.CommandType.printo,
                readline.CommandType.printx,
                => try handler.values.print(self, command),
                readline.CommandType.prints => try handler.values.prints(self, command),
                readline.CommandType.set => try handler.values.set(self, command),
                // PROCESSES
                readline.CommandType.processes => try handler.processes.processes(self),
                // MISC
                readline.CommandType.empty => continue,
                readline.CommandType.unknown => try handler.misc.unknown(self, command),
            }
        }

        try stdout.printInfo(
            "The process {s} exited.\n",
            .{try cham.cyanBright().fmt("{d}", .{self.process.pid})},
        );
    }
};
