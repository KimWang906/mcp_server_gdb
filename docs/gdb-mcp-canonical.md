# GDB MCP Server — Canonical Reference

> **Single source of truth** for GDB MCP Server integration across AI agents.
> Derivative files are generated from this document:
> - Claude Code → `.claude/skills/gdb-mcp/SKILL.md` + `tool-reference.md`
> - Cursor → `.cursor/rules/gdb-mcp.mdc`
> - Codex CLI → `AGENTS.md` (GDB section)

---

## Overview

`mcp-server-gdb` wraps GDB in the GDB/MI protocol and exposes 67 MCP tools.
One session = one GDB process. Every tool requires a `session_id` UUID.

**Architecture:**
```
MCP Client → GdbService (tools.rs) → GDBManager (gdb.rs) → GDB process (mi/)
```

---

## Feature Flags (Build-time)

| Feature | What it enables | Required for |
|---------|----------------|-------------|
| `qemu-user` | ELF arch detection, QEMU user-mode | Cross-arch ELF debugging |
| `qemu-system` | QEMU system-mode backend | Kernel/firmware debugging |
| `qemu` | Both qemu-user + qemu-system | Full QEMU support |
| `libc-fetch` | Ubuntu libc6 auto-download | QEMU user + libc-fetch (implies qemu-user) |

Build example: `cargo build --release --features qemu-user,libc-fetch`

---

## Session Lifecycle

```
create_session → [Created] → start_debugging → [Running/Stopped loop] → close_session
```

State machine:
- **Created**: `set_breakpoint`, `execute_cli` (set commands)
- **Running**: `stop_debugging`
- **Stopped**: all inspect/patch/control tools
- **Terminated**: `close_session` only

---

## Backend Selection

`determine_backend()` resolution order:
1. Explicit `backend=` parameter
2. `qemu_args` present → error (requires `backend="qemu-system"`)
3. `core_file` or `proc_id` → Native
4. ELF arch detection (if `qemu-user` feature built) → QemuUser or Native
5. Default: Native

`start_debugging` behavior:
- Native: `exec-run` (starts fresh)
- QEMU user / QEMU system / core dump / attach: `exec-continue` (already halted)

---

## PTY Constraint

`get_inferior_output` and `send_inferior_input` require:
- Native backend (`backend=native` or auto-detected x86_64)
- `create_pty=true` in `create_session`

QEMU sessions do not support PTY I/O. Use `execute_cli` instead.

---

## Tool Categories (67 total)

### Core Session Tools (20)
`create_session`, `get_session`, `get_all_sessions`, `close_session`,
`start_debugging`, `stop_debugging`, `get_breakpoints`, `set_breakpoint`,
`delete_breakpoint`, `get_stack_frames`, `get_local_variables`, `get_registers`,
`get_register_names`, `read_memory`, `continue_execution`, `step_execution`,
`next_execution`, `execute_cli`, `get_inferior_output`, `send_inferior_input`

### GEF — Security (4)
`checksec`, `canary`, `aslr`, `pie`

### GEF — Memory (6)
`vmmap`, `memory`, `hexdump`, `dereference`, `xinfo`, `xor-memory`

### GEF — Heap (2)
`heap`, `heap-analysis-helper`

### GEF — ELF/Binary (3)
`elf-info`, `got`, `xfiles`

### GEF — Search (3)
`search-pattern`, `scan`, `pattern`

### GEF — Patch ⚠️ (3)
`nop`, `patch`, `stub`

### GEF — Execution Control (5)
`entry-break`, `name-break`, `skipi`, `stepover`, `trace-run`

### GEF — Process (3)
`process-status`, `process-search`, `hijack-fd`

### GEF — Misc (11)
`context`, `registers`, `arch`, `eval`, `print-format`, `format-string-helper`,
`pcustom`, `reset-cache`, `shellcode`, `edit-flags`, `functions`

### GEF — Helper Functions (5)
`gef_base` (`$_base()`), `gef_stack` (`$_stack()`), `gef_heap` (`$_heap()`),
`gef_got` (`$_got()`), `gef_bss` (`$_bss()`)

---

## JSON Output

- `execute_cli(json=true)` → auto-prepends `gef-json` prefix
- GEF tools: `json=true` → structured JSON output
- Use `json=true` for programmatic analysis; omit for human-readable output

---

## Destructive Tools

| Tool | Effect |
|------|--------|
| `patch` | Write arbitrary bytes at address |
| `nop` | Replace instructions with NOPs |
| `stub` | Replace function body (nop + ret) |
| `xor-memory` | XOR memory region in-place |
| `edit-flags` | Modify CPU flags register |
| `hijack-fd` | Redirect file descriptor |

All destructive changes are in-memory only; binary on disk is unchanged.

---

## Supported Architectures (QEMU user-mode)

`aarch64`, `arm` (LE/BE), `mipsel`, `mips`, `ppc`, `ppc64` (BE/LE),
`riscv64`, `riscv32`, `s390x`, `i386`

---

## Common Workflows

### Minimal CTF Recon
```
create_session(binary="./chall") → start_debugging
→ checksec → vmmap → got → close_session
```

### Breakpoint + Inspect
```
create_session(binary="./app") → set_breakpoint(file="main.c", line=42)
→ start_debugging → get_registers → get_stack_frames → get_local_variables
→ continue_execution → close_session
```

### QEMU User-Mode (ARM)
```
create_session(binary="./arm_elf")  # auto-detects, requires qemu-user feature
→ start_debugging → get_registers → vmmap → close_session
```

### QEMU System-Mode (Kernel)
```
create_session(
  backend="qemu-system",
  qemu_args=["-kernel","./bzImage","-nographic","-S","-gdb","tcp::1234"],
  gdb_port=1234
) → start_debugging → execute_cli("info registers") → close_session
```

### Core Dump Analysis
```
create_session(binary="./app", core_file="./core")
→ start_debugging → get_stack_frames → get_registers → close_session
```

---

## Error Reference

| Error Message | Fix |
|--------------|-----|
| `backend 'qemu-user' requires --features qemu-user` | Rebuild with `--features qemu-user` |
| `qemu_args requires explicit backend = "qemu-system"` | Add `backend="qemu-system"` |
| `auto_fetch_libc requires qemu-user backend` | Remove param or switch to qemu-user |
| `Session not found` | Call `get_all_sessions` to verify |
| GEF commands return empty | Pass `gef_script=<path>` to `create_session` |
| PTY tools fail on QEMU | Expected; use `execute_cli` instead |
