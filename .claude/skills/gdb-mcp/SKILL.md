---
name: gdb-mcp
description: >
  Use when debugging a binary, analyzing a CTF challenge, inspecting
  memory/registers/heap, setting breakpoints, or running a cross-architecture
  ELF (ARM, MIPS, RISC-V, PPC, AARCH64). Also use for core dump analysis,
  process attach, kernel/firmware debugging via QEMU. Trigger phrases:
  "debug", "GDB", "바이너리 분석", "CTF", "QEMU 디버깅", "코어 덤프",
  "브레이크포인트", "레지스터", "메모리 검사", "힙 분석".
  Do NOT use for general code editing, build errors, or non-binary tasks.
---

# GDB MCP Server — Skill Guide

One GDB process = one session. Every tool requires a `session_id` UUID returned
by `create_session`. Full tool catalog: [tool-reference.md](tool-reference.md).

---

## Preflight Checklist

Before calling any tool, verify:

1. **Server running** — `mcp-server-gdb` process is active in MCP config
2. **Feature flags** (build-time, cannot change at runtime):
   - Cross-arch ELF (ARM/MIPS/RISC-V/…) → built with `--features qemu-user`
   - Auto libc download → built with `--features libc-fetch` (implies qemu-user)
   - QEMU system-mode → built with `--features qemu-system`
3. **GEF** — `vendor/gef/gef.py` present → loaded automatically.
   If absent, pass `gef_script=<path>` to `create_session`.
4. **Stripped binary** — GEF symbol commands (`got`, `heap`, etc.) need debug
   info or at least a non-stripped ELF. Check with `elf-info`.

---

## Session Lifecycle

```
create_session
    │
    ▼
[Created] ──── set_breakpoint (×N) ────────────────────────┐
    │                                                        │
    ▼                                                        │
start_debugging                                              │
    │                                                        │
    ▼                                                        │
[Running] ────── stop_debugging ──────────────────────────▶ │
    │                                                        │
    ▼  (hits breakpoint / signal)                           │
[Stopped] ──── inspect / patch / search ──────────────────▶ │
    │          continue / step / next                        │
    │                ▲                                       │
    └────────────────┘  (loop until done)                   │
    │                                                        │
    ▼                                                        │
[Terminated / Detached]                                     │
    │                                                        │
    └─────────────────────────────────────────────────────▶ │
close_session ◀─────────────────────────────────────────────┘
```

---

## Session State Rules

| State | Tools Available |
|-------|----------------|
| **Created** | `set_breakpoint`, `execute_cli` (GDB `set` commands) |
| **Running** | `stop_debugging`, `get_all_sessions` |
| **Stopped** | All inspect tools (`get_stack_frames`, `get_registers`, `read_memory`, all GEF commands), `continue_execution`, `step_execution`, `next_execution`, `delete_breakpoint`, `patch`/`nop`/`stub` |
| **Terminated** | `close_session` only |

> `get_registers`, `read_memory`, `get_stack_frames`, and all GEF tools require
> **Stopped** state. Calling them while Running returns an error.

---

## Backend Selection Matrix

| Situation | Parameters | `start_debugging` behavior |
|-----------|-----------|---------------------------|
| x86_64 native binary | `binary=<path>` | `exec-run` (launches from scratch) |
| ARM/MIPS/RISC-V/PPC/AArch64 ELF | `binary=<path>` (auto-detects QemuUser) | `exec-continue` (QEMU already halted) |
| Explicit QEMU user-mode | `binary=<path>`, `backend="qemu-user"` | `exec-continue` |
| QEMU system-mode (kernel/firmware) | `backend="qemu-system"`, `qemu_args=["-kernel",…,"-S","-gdb","tcp::1234"]`, `gdb_port=1234` | `exec-continue` |
| Core dump analysis | `core_file=<path>`, `binary=<path>` | `exec-continue` (already terminated) |
| Attach to process | `proc_id=<pid>` | `exec-continue` |

**PTY constraint** — `get_inferior_output` / `send_inferior_input` are
**only available for Native sessions** created with `create_pty=true`.
These tools return an error for QEMU sessions.

---

## Intent → Tool Selector

| Goal | Tool(s) |
|------|---------|
| Security properties (PIE/NX/canary/RELRO) | `checksec` |
| Memory layout / mappings | `vmmap` |
| GOT overwrite analysis | `got` |
| Heap structure inspection | `heap`, `heap-analysis-helper` |
| Registers (structured JSON) | `get_registers` |
| Registers (GEF visual output) | `registers` |
| Read raw bytes | `read_memory` |
| Memory hexdump (visual) | `hexdump` |
| ROP gadget / cyclic pattern | `pattern`, `search-pattern` |
| Arbitrary GDB/GEF command | `execute_cli` |
| Patch bytes (NOP a check) | `nop`, `patch` ⚠️ destructive |
| Crash backtrace | `get_stack_frames` + `get_local_variables` |
| Architecture info | `arch` |
| Format string vuln | `format-string-helper` |
| Shellcode lookup | `shellcode` |

---

## JSON Output Rules

- `execute_cli(json=true)` → automatically prepends `gef-json` → returns parseable JSON
- GEF command tools (`checksec`, `vmmap`, `got`, `heap`, …) accept `json=true` → structured output
- For programmatic analysis, always use `json=true`
- For human-readable output (CTF recon), omit `json` or set `json=false`

```
# Example: machine-parseable checksec
checksec(session_id=<id>, json=true)

# Example: arbitrary command with JSON
execute_cli(session_id=<id>, command="vmmap", json=true)
```

---

## Safety Notes

| Category | Tools | Risk |
|----------|-------|------|
| ⚠️ Destructive | `patch`, `nop`, `stub` | Modifies memory permanently within session |
| ⚠️ Destructive | `edit-flags` | Modifies CPU flags |
| ✅ Read-only | `get_registers`, `vmmap`, `checksec`, `read_memory`, `got`, `heap`, `elf-info`, … | No state change |
| ℹ️ Control flow | `continue_execution`, `step_execution`, `next_execution` | Advances execution |

- Run `get_breakpoints` before `delete_breakpoint` to confirm breakpoint numbers.
- `patch`/`nop` changes persist only in the running process, not the binary on disk.

---

## Quick Start (30 seconds)

```
1. create_session(binary="./challenge")
   → returns session_id: "abc-123-..."

2. start_debugging(session_id="abc-123-...")

3. checksec(session_id="abc-123-...", json=true)

4. vmmap(session_id="abc-123-...", json=true)

5. execute_cli(session_id="abc-123-...", command="info functions", json=false)

6. close_session(session_id="abc-123-...")
```

### CTF Exploit Workflow

```
1. create_session(binary="./pwn_chall")
2. start_debugging
3. checksec                         # security features
4. vmmap                            # base addresses
5. got                              # GOT entries for libc leaks
6. set_breakpoint(file="pwn_chall.c", line=42)  # or use entry-break
7. continue_execution
8. get_registers                    # check rip/rsp at break
9. heap                             # if heap challenge
10. close_session
```

### Cross-Architecture (ARM ELF)

```
1. create_session(binary="./arm_binary")
   # auto-detects ARM → QEMU user-mode (requires qemu-user feature)
2. start_debugging                  # exec-continue (QEMU already halted)
3. get_registers                    # ARM registers (r0-r15, cpsr)
4. close_session
```

---

## Full Tool Reference

See [tool-reference.md](tool-reference.md) for the complete 3-tier catalog
of all 67 tools with required state, parameters, JSON support, and safety notes.
