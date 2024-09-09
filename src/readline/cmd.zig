const std = @import("std");
const chameleon = @import("chameleon");
const stdout = @import("../common.zig").stdout;
const symbol = @import("../common.zig").symbol;
const ptrace = @import("../process.zig").ptrace;
const constant = @import("./constant.zig");
const history = @import("./history.zig");
const term = @import("./term.zig");

pub const CommandType = enum {
    // GENERAL
    help,
    quit,

    // ANALYSIS
    info,
    hash,
    headers,
    file_header,
    program_headers,
    sections,
    symbols,
    dynsymbols,
    functions,
    disassemble,
    // decompile,

    // BREAKPOINTS
    breakpoint,
    breakpoint_add,
    breakpoint_delete,
    breakpoints,

    // RUNNING
    conti, // *the word 'continue' is reserved.
    stepi,
    steps,
    restart,

    // VALUES
    registers,
    printb,
    printo,
    printd,
    printx,
    prints,
    set,

    // PROCESSES
    processes,

    // MISC
    empty,
    unknown,

    const Self = @This();

    pub fn init(command: []const u8) Self {
        if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "?")) {
            return CommandType.help;
        } else if (std.mem.eql(u8, command, "exit") or std.mem.eql(u8, command, "quit")) {
            return CommandType.quit;
        } else if (std.mem.eql(u8, command, "info")) {
            return CommandType.info;
        } else if (std.mem.eql(u8, command, "hash")) {
            return CommandType.hash;
        } else if (std.mem.eql(u8, command, "headers")) {
            return CommandType.headers;
        } else if (std.mem.eql(u8, command, "file-header")) {
            return CommandType.file_header;
        } else if (std.mem.eql(u8, command, "program-headers")) {
            return CommandType.program_headers;
        } else if (std.mem.eql(u8, command, "section-headers") or std.mem.eql(u8, command, "sections")) {
            return CommandType.sections;
        } else if (std.mem.eql(u8, command, "symbols") or std.mem.eql(u8, command, "syms")) {
            return CommandType.symbols;
        } else if (std.mem.eql(u8, command, "dynsymbols") or std.mem.eql(u8, command, "dynsyms")) {
            return CommandType.dynsymbols;
        } else if (std.mem.eql(u8, command, "functions") or std.mem.eql(u8, command, "funcs")) {
            return CommandType.functions;
        } else if (std.mem.eql(u8, command, "disassemble") or std.mem.eql(u8, command, "disas") or std.mem.eql(u8, command, "dis")) {
            return CommandType.disassemble;
            // } else if (std.mem.eql(u8, command, "decompile")) {
            //     return CommandType.decompile;
        } else if (std.mem.eql(u8, command, "breakpoint") or std.mem.eql(u8, command, "bp")) {
            return CommandType.breakpoint;
        } else if (std.mem.eql(u8, command, "breakpoint+") or std.mem.eql(u8, command, "bp+")) {
            return CommandType.breakpoint_add;
        } else if (std.mem.eql(u8, command, "breakpoint-") or std.mem.eql(u8, command, "bp-")) {
            return CommandType.breakpoint_delete;
        } else if (std.mem.eql(u8, command, "breakpoints") or std.mem.eql(u8, command, "bps")) {
            return CommandType.breakpoints;
        } else if (std.mem.eql(u8, command, "continue")) {
            return CommandType.conti;
        } else if (std.mem.eql(u8, command, "stepi")) {
            return CommandType.stepi;
        } else if (std.mem.eql(u8, command, "steps")) {
            return CommandType.steps;
        } else if (std.mem.eql(u8, command, "restart")) {
            return CommandType.restart;
        } else if (std.mem.eql(u8, command, "registers") or std.mem.eql(u8, command, "regs")) {
            return CommandType.registers;
        } else if (std.mem.eql(u8, command, "printb") or std.mem.eql(u8, command, "pb")) {
            return CommandType.printb;
        } else if (std.mem.eql(u8, command, "printo") or std.mem.eql(u8, command, "po")) {
            return CommandType.printo;
        } else if (std.mem.eql(u8, command, "printd") or std.mem.eql(u8, command, "pd")) {
            return CommandType.printd;
        } else if (std.mem.eql(u8, command, "printx") or std.mem.eql(u8, command, "px")) {
            return CommandType.printx;
        } else if (std.mem.eql(u8, command, "prints") or std.mem.eql(u8, command, "ps")) {
            return CommandType.prints;
        } else if (std.mem.eql(u8, command, "set")) {
            return CommandType.set;
        } else if (std.mem.eql(u8, command, "processes") or (std.mem.eql(u8, command, "procs"))) {
            return CommandType.processes;
        } else if (command.len == 0) {
            return CommandType.empty;
        } else {
            return CommandType.unknown;
        }
    }
};

pub const Command = struct {
    allocator: std.mem.Allocator,
    command: std.ArrayList(u8),
    command_type: CommandType,
    command_args: std.ArrayList([]const u8),
    termios: term.Termios,
    history: history.History,
    current_history_idx: usize,
    pid: i32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, fd: i32, pid: i32) !Self {
        return Self{
            .allocator = allocator,
            .command = std.ArrayList(u8).init(allocator),
            .command_type = CommandType.unknown,
            .command_args = std.ArrayList([]const u8).init(allocator),
            .termios = try term.Termios.init(fd),
            .history = history.History.init(allocator, 10),
            .current_history_idx = 0,
            .pid = pid,
        };
    }

    pub fn deinit(self: *Self) void {
        self.command.deinit();
        self.command_args.deinit();
        self.termios.deinit();
        self.history.deinit();
    }

    pub fn help(_: Self) !void {
        try stdout.print("{s}\n", .{constant.HELP});
    }

    pub fn helpCommand(_: Self, command_name: []const u8) !void {
        if (std.mem.eql(u8, command_name, "info")) {
            try stdout.print("{s}\n", .{constant.HELP_INFO});
        } else if (std.mem.eql(u8, command_name, "hash")) {
            try stdout.print("{s}\n", .{constant.HELP_HASH});
        } else if (std.mem.eql(u8, command_name, "headers")) {
            try stdout.print("{s}\n", .{constant.HELP_HEADERS});
        } else if (std.mem.eql(u8, command_name, "file-header")) {
            try stdout.print("{s}\n", .{constant.HELP_FILE_HEADER});
        } else if (std.mem.eql(u8, command_name, "program-headers")) {
            try stdout.print("{s}\n", .{constant.HELP_PROGRAM_HEADERS});
        } else if (std.mem.eql(u8, command_name, "section-headers") or std.mem.eql(u8, command_name, "sections")) {
            try stdout.print("{s}\n", .{constant.HELP_SECTION_HEADERS});
        } else if (std.mem.eql(u8, command_name, "symbols") or std.mem.eql(u8, command_name, "syms")) {
            try stdout.print("{s}\n", .{constant.HELP_SYMBOLS});
        } else if (std.mem.eql(u8, command_name, "dynsymbols") or std.mem.eql(u8, command_name, "dynsyms")) {
            try stdout.print("{s}\n", .{constant.HELP_DYNSYMBOLS});
        } else if (std.mem.eql(u8, command_name, "functions") or std.mem.eql(u8, command_name, "funcs")) {
            try stdout.print("{s}\n", .{constant.HELP_FUNCTIONS});
        } else if (std.mem.eql(u8, command_name, "disassemble") or std.mem.eql(u8, command_name, "disas") or std.mem.eql(u8, command_name, "dis")) {
            try stdout.print("{s}\n", .{constant.HELP_DISASSEMBLE});
            // } else if (std.mem.eql(u8, command_name, "decompile")) {
            //     try stdout.print("{s}\n", .{constant.HELP_DECOMPILE});
        } else if (std.mem.eql(u8, command_name, "breakpoint") or std.mem.eql(u8, command_name, "bp")) {
            try stdout.print("{s}\n", .{constant.HELP_BREAKPOINT});
        } else if (std.mem.eql(u8, command_name, "breakpoint+") or std.mem.eql(u8, command_name, "bp+")) {
            try stdout.print("{s}\n", .{constant.HELP_BREAKPOINT_ADD});
        } else if (std.mem.eql(u8, command_name, "breakpoint-") or std.mem.eql(u8, command_name, "bp-")) {
            try stdout.print("{s}\n", .{constant.HELP_BREAKPOINT_DEL});
        } else if (std.mem.eql(u8, command_name, "breakpoints") or std.mem.eql(u8, command_name, "bps")) {
            try stdout.print("{s}\n", .{constant.HELP_BREAKPOINTS});
        } else if (std.mem.eql(u8, command_name, "continue")) {
            try stdout.print("{s}\n", .{constant.HELP_CONTINUE});
        } else if (std.mem.eql(u8, command_name, "stepi")) {
            try stdout.print("{s}\n", .{constant.HELP_STEPI});
        } else if (std.mem.eql(u8, command_name, "steps")) {
            try stdout.print("{s}\n", .{constant.HELP_STEPS});
        } else if (std.mem.eql(u8, command_name, "restart")) {
            try stdout.print("{s}\n", .{constant.HELP_RESTART});
        } else if (std.mem.eql(u8, command_name, "registers") or std.mem.eql(u8, command_name, "regs")) {
            try stdout.print("{s}\n", .{constant.HELP_REGISTERS});
        } else if (std.mem.eql(u8, command_name, "printb") or std.mem.eql(u8, command_name, "pb")) {
            try stdout.print("{s}\n", .{constant.HELP_PRINTB});
        } else if (std.mem.eql(u8, command_name, "printo") or std.mem.eql(u8, command_name, "po")) {
            try stdout.print("{s}\n", .{constant.HELP_PRINTO});
        } else if (std.mem.eql(u8, command_name, "printd") or std.mem.eql(u8, command_name, "pd")) {
            try stdout.print("{s}\n", .{constant.HELP_PRINTD});
        } else if (std.mem.eql(u8, command_name, "printx") or std.mem.eql(u8, command_name, "px")) {
            try stdout.print("{s}\n", .{constant.HELP_PRINTX});
        } else if (std.mem.eql(u8, command_name, "prints") or std.mem.eql(u8, command_name, "ps")) {
            try stdout.print("{s}\n", .{constant.HELP_PRINTS});
        } else if (std.mem.eql(u8, command_name, "set")) {
            try stdout.print("{s}\n", .{constant.HELP_SET});
        } else if (std.mem.eql(u8, command_name, "processes") or std.mem.eql(u8, command_name, "procs")) {
            try stdout.print("{s}\n", .{constant.HELP_PROCESSES});
        } else {
            try stdout.print("No usage for '{s}'.\n", .{command_name});
        }
    }

    pub fn displayPrompt(self: Self) !void {
        var cham = chameleon.initRuntime(.{ .allocator = self.allocator });
        defer cham.deinit();

        const pc = try ptrace.readRegister(self.pid, "pc");

        // Clear line
        try stdout.print("\r\x1b[2K\r", .{});
        try stdout.print("|{s}| {s} ", .{
            try cham.greenBright().fmt("0x{x}", .{pc}),
            try cham.red().fmt("►", .{}),
        });
    }

    pub fn readCommand(self: *Self, reader: anytype, writer: anytype) !void {
        try self.displayPrompt();
        var input: [256]u8 = undefined;
        var input_len: usize = 0;
        var cursor_pos: usize = 0;
        // Reset commands
        self.command.clearRetainingCapacity();
        self.command_type = CommandType.unknown;
        self.command_args.clearRetainingCapacity();

        // Parse keyboard inputs.
        while (true) {
            const byte = try reader.readByte();

            if (byte == 0x1b) { // Escape seqence

                var seq: [2]u8 = undefined;
                seq[0] = try reader.readByte();
                seq[1] = try reader.readByte();

                if (seq[0] == '[') {
                    if (seq[1] == 'A') { // Up arrow key
                        if (self.current_history_idx > 0) {
                            try stdout.print("up arrow", .{});
                            self.current_history_idx -= 1;
                            const prev_cmd = self.history.getEntry(self.current_history_idx);
                            if (prev_cmd) |c| {
                                try self.displayPrompt();
                                try stdout.print("{s}", .{c});
                                input_len = c.len;
                                cursor_pos = c.len;

                                self.command.clearRetainingCapacity();
                                try self.command.appendSlice(c);

                                // Copy prev command to input.
                                @memcpy(input[0..c.len], c[0..c.len]);
                            }
                        } else {
                            try self.displayPrompt();
                            input_len = 0;
                            cursor_pos = 0;
                            self.command.clearRetainingCapacity();
                        }
                    } else if (seq[1] == 'B') { // Down arrow key
                        if (self.history.entries.items.len > 0 and
                            self.current_history_idx < (self.history.entries.items.len - 1))
                        {
                            self.current_history_idx += 1;
                            const next_command = self.history.getEntry(self.current_history_idx);
                            if (next_command) |c| {
                                try self.displayPrompt();
                                try stdout.print("{s}", .{c});
                                input_len = c.len;
                                cursor_pos = c.len;

                                self.command.clearRetainingCapacity();
                                try self.command.appendSlice(c);

                                // Copy next command to input.
                                @memcpy(input[0..c.len], c[0..c.len]);
                            }
                        } else {
                            try self.displayPrompt();
                            input_len = 0;
                            cursor_pos = 0;
                            self.command.clearRetainingCapacity();
                        }
                    } else if (seq[1] == 'C') { // Right arrow key
                        if (cursor_pos < input_len) {
                            cursor_pos += 1;
                            try stdout.print("\x1b[C", .{});
                        }
                    } else if (seq[1] == 'D') { // Left arrow key
                        if (cursor_pos > 0) {
                            cursor_pos -= 1;
                            try stdout.print("\x1b[D", .{});
                        }
                    }
                }
            } else if (byte == 0x08 or byte == 0x7f) { // Backspace
                if (input_len > 0) {
                    input_len -= 1;
                    cursor_pos -= 1;
                    try stdout.print("\x08 \x08", .{});
                }
            } else if (byte == '\n') { // Enter key
                try stdout.print("\n", .{});
                const input_trim = std.mem.trim(u8, input[0..input_len], " ");
                self.command.clearRetainingCapacity();
                try self.command.appendSlice(input_trim);
                break;
            } else { // Normal characters
                input[input_len] = byte;
                input_len += 1;
                cursor_pos += 1;
                try writer.writeByte(byte);
            }
        }

        if (self.command.items.len > 0) {
            try self.history.addEntry(@constCast(self.command.items));
            self.current_history_idx = self.history.entries.items.len;
        }

        var command_split = std.mem.splitSequence(u8, self.command.items, " ");
        var commands = std.ArrayList([]const u8).init(self.allocator);
        defer commands.deinit();
        while (command_split.next()) |cmd| {
            try commands.append(cmd);
        }

        // Detect command type
        self.command_type = CommandType.init(commands.items[0]);
        _ = commands.orderedRemove(0);
        // Set command args
        for (commands.items) |cmd| {
            try self.command_args.append(cmd);
        }
    }
};
