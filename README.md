# MCP Server GDB

A GDB/MI protocol server based on the MCP protocol, providing remote application debugging capabilities with AI assistants.

Korean: `README.ko.md`

## Features

- Create and manage GDB debug sessions
- Set and manage breakpoints
- View stack information and variables
- Control program execution (run, pause, step, etc.)
- Support concurrent multi-session debugging
- A built-in TUI to inspect agent behaviors so that you can improve your prompt (WIP)

## Installation

### Pre-built Binaries
Find the binaries in the release page, choose one per your working platform, then you can run it directly.

### Build From Source
Clone the repository and build it by cargo
```bash
cargo build --release
cargo run
```

### Using Nix
If you have Nix installed, you can run the project without cloning:

#### Run locally (after cloning)
```bash
nix run .
```

#### Run remotely from GitHub
```bash
nix run "git+https://github.com/pansila/mcp_server_gdb.git" -- --help

```

#### Development environment
To enter a development shell with all dependencies:
```bash
nix develop
```

## Usage

1. Just run it directly: `./mcp-server-gdb`
2. The server supports two transport modes:
   - Stdio (default): Standard input/output transport
   - SSE: Server-Sent Events transport, default at `http://127.0.0.1:8080`

### CLI Options

```bash
./mcp-server-gdb \
  --log-level info \
  --transport stdio|sse \
  --enable-tui
```

- `--enable-tui` requires `--transport sse` (otherwise key events may be lost).

### TUI

Start with:

```bash
./mcp-server-gdb --enable-tui --transport sse
```

Key bindings:
- `Tab`: Cycle view modes
- `F1..F7`: All, Registers, Stack, Instructions, Output, Mapping, Hexdump
- `j/k`: Scroll down/up (Output/Mapping/Hexdump)
- `J/K`: Page down/up (Output/Mapping/Hexdump)
- `g/G`: Top/bottom (Output/Mapping/Hexdump)
- `H/T`: Load heap/stack into Hexdump (Hexdump view)
- `q`: Quit TUI

## Configuration

You can adjust server configuration by modifying the `src/config.rs` file or by environment variables:

- Server IP Address
- Server port
- GDB command timeout time (in seconds)

## Supported MCP Tools

### Core MCP Tools (MI-backed)

**Session Management**
- `create_session` - Create a new GDB debugging session (optionally with program, args, PTY, etc.)
- `get_session` - Get a session by ID
- `get_all_sessions` - List all sessions
- `close_session` - Close a session

**Debug Control**
- `start_debugging` - Start debugging in a session
- `stop_debugging` - Stop debugging in a session
- `continue_execution` - Continue execution
- `step_execution` - Step into next line
- `next_execution` - Step over next line

**Breakpoints**
- `get_breakpoints` - List breakpoints
- `set_breakpoint` - Set a breakpoint
- `delete_breakpoint` - Delete one or more breakpoints

**Debug Information**
- `get_stack_frames` - Get stack frames
- `get_local_variables` - Get locals in a frame
- `get_registers` - Get registers (optionally by index list)
- `get_register_names` - Get register names (optionally by index list)
- `read_memory` - Read memory bytes by address/range

**I/O**
- `execute_cli` - Execute a GDB/GEF CLI command in the session
- `get_inferior_output` - Read buffered inferior output from PTY
- `send_inferior_input` - Send input to the inferior process via PTY

### GEF Passthrough Tools

These tools forward to GEF CLI commands (optionally with `args`).

**Security**
- `checksec` - Inspect binary security features
- `canary` - Display stack canary value
- `aslr` - Show ASLR status
- `pie` - Display PIE information

**Memory**
- `vmmap` - Show memory mappings
- `memory` - Inspect or modify memory
- `hexdump` - Hexdump memory
- `dereference` - Dereference pointers
- `xinfo` - Display address information
- `xor-memory` - XOR memory contents

**Heap**
- `heap` - Inspect heap structures
- `heap-analysis-helper` - Heap analysis helper

**ELF / Binary**
- `elf-info` - Show ELF information
- `got` - Display GOT entries
- `xfiles` - List loaded files

**Search**
- `search-pattern` - Search for patterns in memory
- `scan` - Scan memory for values
- `pattern` - Generate or search patterns

**Patch**
- `nop` - Patch memory with NOPs
- `patch` - Patch memory
- `stub` - Stub functions

**Execution Control**
- `entry-break` - Break at program entry
- `name-break` - Set breakpoint by name
- `skipi` - Skip instructions
- `stepover` - Step over instructions
- `trace-run` - Trace execution

**Process**
- `process-status` - Show process status
- `process-search` - Search processes
- `hijack-fd` - Hijack file descriptor

**Misc**
- `context` - Show context
- `registers` - Show registers
- `arch` - Show architecture info
- `eval` - Evaluate expression
- `print-format` - Display format options
- `format-string-helper` - Format string helper
- `pcustom` - Custom structure printing
- `reset-cache` - Reset GEF cache
- `shellcode` - Generate shellcode
- `edit-flags` - Edit flags
- `functions` - List GEF functions

**GEF Helper Functions**
- `gef_base` - Evaluate `$_base()`
- `gef_stack` - Evaluate `$_stack()`
- `gef_heap` - Evaluate `$_heap()`
- `gef_got` - Evaluate `$_got()`
- `gef_bss` - Evaluate `$_bss()`

Note: The full list of tools (and parameters) is defined in `src/tools.rs`.

## License

MIT
