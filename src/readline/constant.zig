pub const HELP =
    \\GENERAL
    \\-------
    \\  help, ?                     : Display the usage.
    \\  quit, exit                  : Quit the debugger.
    \\
    \\ANALYSIS
    \\--------
    \\  info                        : Display file information.
    \\  hash                        : Display file hashes.
    \\  headers                     : Display headers.
    \\  file-header                 : Display file header (ELF Header, DOS Header, ...)
    \\  program-headers             : Display program headers.
    \\  section-headers, sections   : Display sections.
    \\  symbols, syms               : Display symbol table.
    \\  dynsymbols, dynsyms         : Display dynamic symbol table for ELF.
    \\  export-table                : Display export table for PE.
    \\  import-table                : Display import table for PE.
    \\  functions, funcs            : List all functions.
    \\  disassemble, disas, dis     : Disassemble at specified address.
    // \\  decompile                   : Decompile.
    \\
    \\BREAKPOINTS
    \\-----------
    \\  breakpoint,  bp             : Display information of the breakpoint.
    \\  breakpoint+, bp+            : Add breakpoint at specified address/function.
    \\  breakpoint-, bp-            : Delete breakpoint at specified index.
    \\  breakpoints, bps            : List all breakpoints.
    \\
    \\RUNNING
    \\-------
    \\  continue                    : Continue the program until hitting a breakpoint.
    \\  stepi                       : Step instructions.
    \\  steps                       : Step source lines.
    // \\  step over                   : Assembly-level single step.
    // \\  next                        : Step over functions.
    // \\  jump                        : Go to a specified address or function.
    \\  restart                     : Restart the program with the new child process.
    \\
    \\VALUES
    \\------
    \\  registers, regs             : Print values of all registers.
    \\  printb, pb                  : print value of address/register in binary.
    \\  printo, po                  : Print value of address/register in octal.
    \\  printd, pd                  : Print value of address/register in decimal.
    \\  printx, px                  : Print value of address/register in hex.
    \\  prints, ps                  : Print value of address/register in string.
    \\  set                         : Set value to address/register.
    \\
    \\PROCESSES
    \\---------
    \\  processes, procs            : Display processes structure.
    \\
    \\*To display the usage of each command, run 'help <command>' or '? <command>'.
;

pub const HELP_INFO =
    \\info  : Display file information.
;

pub const HELP_HASH =
    \\hash  : Display file hashes.
;

pub const HELP_HEADERS =
    \\headers   : Display all headers of the file.
;

pub const HELP_FILE_HEADER =
    \\file-header   : Display file header (DOS header, ELF header).
;

pub const HELP_PROGRAM_HEADERS =
    \\program-headers   : Display program headers.
;

pub const HELP_SECTION_HEADERS =
    \\section-headers, sections : Display section.
;

pub const HELP_SYMBOLS =
    \\symbols, syms : Display symbol table.
;

pub const HELP_DYNSYMBOLS =
    \\dynsymbols, dynsyms   : Display dynamic symbol table for ELF.
;

pub const HELP_EXPORT_TABLE =
    \\export-table  : Display export table for PE.
;

pub const HELP_IMPORT_TABLE =
    \\import-table  : Display import table for PE.
;

pub const HELP_FUNCTIONS =
    \\functions, funcs  : List all functions.
;

pub const HELP_DISASSEMBLE =
    \\disassemble [ADDR/FUNC] [LINES]
    \\disas [ADDR/FUNC] [LINES]
    \\dis [ADDR/FUNC] [LINES]           : Disassemble from the address/function.
    \\
    \\EXAMPLE
    \\-------
    \\  disas 0x563c803d41b2    : Disassemble from the address.
    \\  disas main              : Disassemble from "main" function.
    \\  disas main 50           : Disassemble 50 lines from "main" function.
;

// pub const HELP_DECOMPILE =
//     \\decompile : Decompile.
// ;

pub const HELP_BREAKPOINT =
    \\breakpoint, bp [INDEX]    : Display information of breakpoint.
    \\
    \\EXAMPLE
    \\-------
    \\  breakpoint 0    : Display information of 0th breakpoint.
    \\  bp 0            : Same as above.
;

pub const HELP_BREAKPOINT_ADD =
    \\breakpoint+, bp+ [ADDR/FUNC]  : Add breakpoint at specified address/function.
    \\
    \\EXAMPLE
    \\-------
    \\  breakpoint+ 0x563c803d41b2  : Add breakpoint at the address 0x563c803d41b2.
    \\  bp+ 0x563c803d41b2          : Same as above.
    \\  bp+ main                    : Add breakpoint at "main" function.
;

pub const HELP_BREAKPOINT_DEL =
    \\breakpoint-, bp- [INDEX]  : Delete breakpoint at specified address/function.
    \\
    \\EXAMPLE
    \\-------
    \\  breakpoint- 1   : Delete the 1st breakpoint.
    \\  bp- 1           : Same as above.
;

pub const HELP_BREAKPOINTS =
    \\breakpoints, bps  : List all breakpoints.
;

pub const HELP_CONTINUE =
    \\continue  : Continue the program until hitting a breakpoint.
;

pub const HELP_STEPI =
    \\stepi [NUM]   : Step instructions.
    \\
    \\EXAMPLE
    \\-------
    \\  stepi       : Step one instruction.
    \\  stepi 3     : Step three instructions.
;

pub const HELP_STEPS =
    \\steps [NUM]   : Step source lines.
    \\
    \\EXAMPLE
    \\-------
    \\  steps       : Step one source line.
    \\  steps 3     : Step three source lines.
;

pub const HELP_RESTART =
    \\restart   : Restart the program with the new child process.
;

pub const HELP_REGISTERS =
    \\registers, regs   : Print values of all registers.
;

pub const HELP_PRINTB =
    \\printb, pb [ADDR/REG]    : Print value of address/register in binary.
    \\
    \\EXAMPLE
    \\-------
    \\  printb 0x563c803d41b2   : Print value of the address in binary.
    \\  pb 0x563c803d41b2       : Same as above.
;

pub const HELP_PRINTO =
    \\printo, po [ADDR/REG]    : Print value of address/register in octal.
    \\
    \\EXAMPLE
    \\-------
    \\  printo 0x563c803d41b2   : Print value of the address in octal.
    \\  po 0x563c803d41b2       : Same as above.
;

pub const HELP_PRINTD =
    \\printd, pd [ADDR/REG]    : Print value of address/register in decimal.
    \\
    \\EXAMPLE
    \\-------
    \\  printd zf   : Print value of Zero Flag in decimal.
    \\  pd zf       : Same as above.
;

pub const HELP_PRINTX =
    \\printx, px [ADDR/REG]    : Print value of address/register in hex.
    \\
    \\EXAMPLE
    \\-------
    \\  printx rbp  : Print value of RBP in hex.
    \\  px rbp      : Same as above.
;

pub const HELP_PRINTS =
    \\prints, ps [ADDR/REG]    : print value of address/register in string.
    \\
    \\EXAMPLE
    \\-------
    \\  prints 0x563c803d41b2   : Print value of the address in string.
    \\  ps 0x563c803d41b2       : Same as above.
;

pub const HELP_SET =
    \\set [ADDR/REG] [VALUE]    : Set value to address/register.
    \\
    \\EXAMPLE
    \\-------
    \\  set rip 0x563c803d41b2  : Set the address to RIP.
    \\  set cf 1                : Set 1 to Carry Flag.
;

pub const HELP_PROCESSES =
    \\processes, procs  : Display processes structure.
;
