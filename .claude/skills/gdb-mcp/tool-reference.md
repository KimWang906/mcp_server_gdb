# GDB MCP Server — Full Tool Reference

67 tools across 3 tiers. All tools require `session_id` unless noted.

---

## Tier 1: Intent Decision Matrix

Pick your entry point based on your goal:

| Scenario | Entry Tool → Next Steps |
|----------|------------------------|
| **Crash triage** | `get_stack_frames` → `get_local_variables` → `get_registers` |
| **CTF exploit** | `checksec` → `vmmap` → `got` → `heap` → `pattern` |
| **Cross-arch bring-up** | `create_session(binary=<elf>)` → `get_registers` → `vmmap` |
| **Kernel/firmware remote** | `create_session(backend=qemu-system, qemu_args=[…,-S,-gdb,…])` → `execute_cli("info registers")` |
| **PTY interactive** | `create_session(create_pty=true)` → `start_debugging` → `get_inferior_output` |
| **Core dump analysis** | `create_session(core_file=./core, binary=./app)` → `get_stack_frames` → `get_registers` |
| **Process attach** | `create_session(proc_id=<pid>)` → `get_stack_frames` |
| **Format string** | `checksec` → `format-string-helper` → `got` |
| **Heap exploit** | `heap` → `heap-analysis-helper` → `vmmap` |
| **ROP chain** | `pattern` → `search-pattern` → `vmmap` → `elf-info` |

---

## Tier 2: Lifecycle Phase Map

```
create_session ──────────────────────────────────────────── [Created]
      │                                                          │
      │                                             set_breakpoint (×N)
      │                                             execute_cli ("set" cmds)
      ▼                                                          │
start_debugging ◀───────────────────────────────────────────────┘
      │
      ▼
 [Running / Stopped]
      │
      ├─── INSPECT (requires Stopped) ───────────────────────────────────────┐
      │    get_stack_frames       get_registers        read_memory            │
      │    get_local_variables    get_register_names   vmmap                  │
      │    checksec               got                  heap                   │
      │    hexdump                dereference          xinfo                  │
      │    elf-info               arch                 context                │
      │    registers              process-status       xfiles                 │
      │                                                                       │
      ├─── CONTROL (from Stopped) ────────────────────────────────────────────┤
      │    continue_execution     step_execution       next_execution         │
      │    stop_debugging         skipi                stepover               │
      │    entry-break            trace-run                                   │
      │                                                                       │
      ├─── PATCH (requires Stopped) ⚠️ destructive ──────────────────────────┤
      │    nop                    patch                stub                   │
      │    edit-flags             xor-memory                                  │
      │                                                                       │
      └─── SESSION MGMT (any state) ─────────────────────────────────────────┘
           get_all_sessions       get_session          close_session
           get_breakpoints        delete_breakpoint
```

---

## Tier 3: Full Catalog

### Session Management

| Tool | Required State | Key Params | JSON | Feature | Safe | Typical Next |
|------|---------------|-----------|------|---------|------|-------------|
| `create_session` | — | `binary`, `backend` | No | varies | ✅ | `set_breakpoint`, `start_debugging` |
| `get_session` | any | `session_id` | No | — | ✅ | — |
| `get_all_sessions` | any | — | No | — | ✅ | — |
| `close_session` | any | `session_id` | No | — | ✅ | — |
| `start_debugging` | Created/Stopped | `session_id` | No | — | ✅ | inspect tools |
| `stop_debugging` | Running | `session_id` | No | — | ✅ | inspect tools |

#### `create_session` Parameters

| Param | Type | Description |
|-------|------|-------------|
| `binary` | path | ELF to debug. Alias: `program`. Source for arch auto-detection |
| `backend` | string | `"native"` \| `"qemu-user"` \| `"qemu-system"`. Omit = auto |
| `gdb_path` | path | Custom GDB binary path |
| `gef_script` | path | GEF script path (auto-loaded if `vendor/gef/gef.py` exists) |
| `gef_rc` | path | GEF RC config path |
| `symbol_file` | path | Separate symbol file |
| `lib_dir` | path | Sysroot (`-L`) for QEMU user; solib dir for native |
| `auto_fetch_libc` | bool | Download matching Ubuntu libc6 (requires `libc-fetch` feature) |
| `core_file` | path | Core dump → native backend |
| `proc_id` | u32 | PID to attach → native backend |
| `args` | string[] | Arguments passed to the inferior |
| `create_pty` | bool | Create PTY for inferior I/O (default: true, native only) |
| `binary_args` | string[] | Args forwarded to emulated binary (QEMU user) |
| `qemu_path` | path | Explicit `qemu-<arch>` binary (QEMU user, optional) |
| `gdb_port` | u16 | GDB stub port (auto for QEMU user; required for QEMU system) |
| `qemu_args` | string[] | Full QEMU system args (must include `-S -gdb tcp::<port>`) |
| `nh` | bool | GDB `-nh` flag |
| `nx` | bool | GDB `-nx` flag |
| `quiet` | bool | GDB `-q` flag |
| `cd` | path | Working directory for GDB |
| `source_dir` | path | Source directory hint |
| `tty` | path | TTY device for inferior |

---

### Breakpoints

| Tool | Required State | Key Params | JSON | Safe | Typical Next |
|------|---------------|-----------|------|------|-------------|
| `set_breakpoint` | Created/Stopped | `session_id`, `file`, `line` | No | ✅ | `start_debugging` / `continue_execution` |
| `get_breakpoints` | Stopped | `session_id` | No | ✅ | `delete_breakpoint` |
| `delete_breakpoint` | Stopped | `session_id`, `breakpoints: [string]` | No | ✅ | — |

> `set_breakpoint` uses `file` (source file path) and `line` (line number).
> Always call `get_breakpoints` to confirm numbers before `delete_breakpoint`.

---

### Execution Control

| Tool | Required State | Key Params | JSON | Safe | Typical Next |
|------|---------------|-----------|------|------|-------------|
| `continue_execution` | Stopped | `session_id` | No | ✅ | inspect (on next stop) |
| `step_execution` | Stopped | `session_id` | No | ✅ | inspect |
| `next_execution` | Stopped | `session_id` | No | ✅ | inspect |
| `execute_cli` | any | `session_id`, `command`, `json?`, `timeout_seconds?` | Yes | ✅ | — |

---

### Inspection

| Tool | Required State | Key Params | JSON | Safe | Typical Next |
|------|---------------|-----------|------|------|-------------|
| `get_stack_frames` | Stopped | `session_id` | No | ✅ | `get_local_variables` |
| `get_local_variables` | Stopped | `session_id`, `frame_id?` | No | ✅ | `read_memory` |
| `get_registers` | Stopped | `session_id`, `reg_list?` | No | ✅ | `read_memory` |
| `get_register_names` | Stopped | `session_id` | No | ✅ | `get_registers` |
| `read_memory` | Stopped | `session_id`, `address`, `count`, `offset?` | No | ✅ | `hexdump` |

---

### Inferior I/O (Native + PTY only)

| Tool | Required State | Constraint | Safe | Notes |
|------|---------------|-----------|------|-------|
| `get_inferior_output` | Stopped | Native + `create_pty=true` | ✅ | Reads accumulated PTY output |
| `send_inferior_input` | Running/Stopped | Native + `create_pty=true` | ✅ | Writes to inferior stdin |

> **QEMU sessions**: these tools return an error. PTY is not available for
> QEMU user-mode or system-mode sessions.

---

### GEF — Security

| Tool | Required State | Args | JSON | Feature | Safe |
|------|---------------|------|------|---------|------|
| `checksec` | Stopped | `session_id`, `args?` | ✅ | GEF | ✅ |
| `canary` | Stopped | `session_id`, `args?` | ✅ | GEF | ✅ |
| `aslr` | Stopped | `session_id`, `args?` | ✅ | GEF | ✅ |
| `pie` | Stopped | `session_id`, `args?` | ✅ | GEF | ✅ |

---

### GEF — Memory

| Tool | Required State | Args | JSON | Safe | Notes |
|------|---------------|------|------|------|-------|
| `vmmap` | Stopped | `session_id`, `args?` | ✅ | ✅ | Memory mappings with permissions |
| `memory` | Stopped | `session_id`, `args?` | ✅ | ✅ | Inspect/watch memory regions |
| `hexdump` | Stopped | `session_id`, `args?` (addr + len) | ✅ | ✅ | Visual hex+ASCII dump |
| `dereference` | Stopped | `session_id`, `args?` | ✅ | ✅ | Follow pointer chains |
| `xinfo` | Stopped | `session_id`, `args?` | ✅ | ✅ | Address metadata (section, perms) |
| `xor-memory` | Stopped | `session_id`, `args?` | ✅ | ⚠️ | XOR memory in-place (destructive) |

---

### GEF — Heap

| Tool | Required State | Args | JSON | Safe | Notes |
|------|---------------|------|------|------|-------|
| `heap` | Stopped | `session_id`, `args?` | ✅ | ✅ | ptmalloc2 chunk/bin inspection |
| `heap-analysis-helper` | Stopped | `session_id`, `args?` | ✅ | ✅ | Heap use-after-free/double-free detection |

---

### GEF — ELF / Binary

| Tool | Required State | Args | JSON | Safe | Notes |
|------|---------------|------|------|------|-------|
| `elf-info` | Stopped | `session_id`, `args?` | ✅ | ✅ | ELF header, sections, segments |
| `got` | Stopped | `session_id`, `args?` | ✅ | ✅ | GOT entries with current values |
| `xfiles` | Stopped | `session_id`, `args?` | ✅ | ✅ | All loaded shared libraries |

---

### GEF — Search

| Tool | Required State | Args | JSON | Safe | Notes |
|------|---------------|------|------|------|-------|
| `search-pattern` | Stopped | `session_id`, `args` (pattern) | ✅ | ✅ | Find byte/string patterns in memory |
| `scan` | Stopped | `session_id`, `args?` | ✅ | ✅ | Scan for values in writable regions |
| `pattern` | Stopped | `session_id`, `args?` | ✅ | ✅ | De Bruijn pattern gen/search (overflow offset) |

---

### GEF — Patch (⚠️ Destructive)

> These modify the running process's memory. Changes do not persist to disk.

| Tool | Required State | Args | JSON | Notes |
|------|---------------|------|------|-------|
| `nop` | Stopped | `session_id`, `args` (addr [+count]) | No | Replace instructions with NOPs |
| `patch` | Stopped | `session_id`, `args` (addr bytes) | No | Write arbitrary bytes |
| `stub` | Stopped | `session_id`, `args` (func [retval]) | No | Stub out a function (nop + ret) |

---

### GEF — Execution Control

| Tool | Required State | Args | JSON | Safe | Notes |
|------|---------------|------|------|------|-------|
| `entry-break` | Created/Stopped | `session_id`, `args?` | No | ✅ | Break at program entry point |
| `name-break` | Created/Stopped | `session_id`, `args` (symbol) | No | ✅ | Breakpoint by symbol/function name |
| `skipi` | Stopped | `session_id`, `args?` | No | ✅ | Skip current instruction |
| `stepover` | Stopped | `session_id`, `args?` | No | ✅ | Step over (GEF variant) |
| `trace-run` | Stopped | `session_id`, `args?` | No | ✅ | Trace execution with context |

---

### GEF — Process

| Tool | Required State | Args | JSON | Safe | Notes |
|------|---------------|------|------|------|-------|
| `process-status` | Stopped | `session_id`, `args?` | ✅ | ✅ | FDs, maps, environ of inferior |
| `process-search` | any | `session_id`, `args?` | ✅ | ✅ | Search running processes by name |
| `hijack-fd` | Stopped | `session_id`, `args?` | No | ⚠️ | Redirect file descriptor |

---

### GEF — Misc

| Tool | Required State | Args | JSON | Safe | Notes |
|------|---------------|------|------|------|-------|
| `context` | Stopped | `session_id`, `args?` | No | ✅ | Full GEF context (regs+stack+code+trace) |
| `registers` | Stopped | `session_id`, `args?` | ✅ | ✅ | Visual register display |
| `arch` | any | `session_id`, `args?` | ✅ | ✅ | Detected architecture info |
| `eval` | Stopped | `session_id`, `args` (expr) | No | ✅ | Evaluate expression |
| `print-format` | Stopped | `session_id`, `args?` | No | ✅ | Display in various formats |
| `format-string-helper` | Stopped | `session_id`, `args?` | ✅ | ✅ | Format string vulnerability analysis |
| `pcustom` | Stopped | `session_id`, `args?` | No | ✅ | Custom struct printing |
| `reset-cache` | any | `session_id`, `args?` | No | ✅ | Reset GEF internal cache |
| `shellcode` | any | `session_id`, `args?` | No | ✅ | Search/display shellcode snippets |
| `edit-flags` | Stopped | `session_id`, `args?` | No | ⚠️ | Modify CPU flags register |
| `functions` | any | `session_id`, `args?` | No | ✅ | List GEF convenience functions |

---

### GEF — Helper Functions

These evaluate GEF convenience functions via `p <func>`:

| Tool | Function | Description |
|------|---------|-------------|
| `gef_base` | `$_base()` | Image base address (PIE offset) |
| `gef_stack` | `$_stack()` | Current stack pointer value |
| `gef_heap` | `$_heap()` | Heap base address |
| `gef_got` | `$_got()` | GOT base address |
| `gef_bss` | `$_bss()` | BSS section address |

All require Stopped state, accept `json?` parameter.

---

## Error Recovery Playbook

| Error | Cause | Fix |
|-------|-------|-----|
| `"backend 'qemu-user' requires --features qemu-user"` | Server not built with feature | Rebuild: `cargo build --features qemu-user` |
| `"qemu_args requires explicit backend = qemu-system"` | Missing `backend` param | Add `backend="qemu-system"` |
| `"auto_fetch_libc requires qemu-user backend"` | Native + auto_fetch | Remove `auto_fetch_libc` or use QEMU backend |
| `"Session not found"` | Stale session_id | Call `get_all_sessions` to list active sessions |
| GEF command returns empty/error | GEF not loaded | Pass `gef_script=<path/to/gef.py>` in `create_session` |
| `get_inferior_output` errors on QEMU session | PTY unavailable in QEMU | Use `execute_cli` for output inspection instead |
| `set_breakpoint` fails | Wrong file/line | Check with `execute_cli("info sources")` first |
| Timeout on `execute_cli` | Long-running command | Use `timeout_seconds=<N>` param |

---

## Supported Architectures (QEMU user-mode)

`aarch64`, `arm`, `armeb`, `mipsel`, `mips`, `ppc`, `ppc64`, `ppc64le`,
`riscv64`, `riscv32`, `s390x`, `i386`

Auto-detected from ELF machine field when `--features qemu-user` is built in.
x86_64 ELFs fall through to native GDB.
