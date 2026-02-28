/// Integration and unit tests for the QEMU user-mode backend.
///
/// Unit tests:  validate ELF parsing via `ElfInfo::from_bytes` — no QEMU required.
/// Integration tests: spin up a real QEMU+GDB session for each supported architecture.
///
/// Run with:
///   cargo test --features qemu-user -- qemu_user
///
/// Individual architecture tests are skipped when the corresponding
/// `qemu-<arch>` binary is not found in PATH.

// ─── Minimal ELF builder ─────────────────────────────────────────────────────
//
// Generates a valid, loadable ELF file that QEMU user-mode can execute.
//
// IMPORTANT: QEMU user-mode starts executing the process immediately after
// launch (it does NOT halt at entry like `qemu-system -S`). The code bytes
// must therefore be a valid infinite loop so the process stays alive long
// enough for GDB to connect and send an interrupt.
//
// Layout:
//   ELF32: header(52) + PT_LOAD phdr(32) + code(≥4 bytes) = ≥88 bytes
//   ELF64: header(64) + PT_LOAD phdr(56) + code(≥4 bytes) = ≥124 bytes
//
// The PT_LOAD segment maps file offset 0 to vaddr_base.
// e_entry points to the first code byte.

struct MiniElf {
    e_machine: u16,
    e_flags: u32,
    /// 1 = ELF32, 2 = ELF64
    ei_class: u8,
    big_endian: bool,
    /// Virtual address for the PT_LOAD segment base (e.g. 0x10000).
    vaddr_base: u64,
}

impl MiniElf {
    fn w16(&self, v: u16) -> [u8; 2] {
        if self.big_endian { v.to_be_bytes() } else { v.to_le_bytes() }
    }
    fn w32(&self, v: u32) -> [u8; 4] {
        if self.big_endian { v.to_be_bytes() } else { v.to_le_bytes() }
    }
    fn w64(&self, v: u64) -> [u8; 8] {
        if self.big_endian { v.to_be_bytes() } else { v.to_le_bytes() }
    }

    /// Build ELF bytes using `code` at the entry point.
    ///
    /// For unit tests use `&[0u8; 16]` (never executed — only parsed).
    /// For integration tests use architecture-specific infinite-loop bytes.
    fn build_with_code(&self, code: &[u8]) -> Vec<u8> {
        if self.ei_class == 2 {
            self.build64(code)
        } else {
            self.build32(code)
        }
    }

    /// Convenience wrapper: all-zero code (for ELF-parsing unit tests only).
    fn build(&self) -> Vec<u8> {
        self.build_with_code(&[0u8; 16])
    }

    fn build32(&self, code: &[u8]) -> Vec<u8> {
        assert!(!code.is_empty(), "code must be non-empty");
        const HDR: u32 = 52;
        const PHD: u32 = 32;
        let code_len = code.len() as u32;
        let total = HDR + PHD + code_len;
        let vbase = self.vaddr_base as u32;
        let entry = vbase + HDR + PHD;

        let mut b: Vec<u8> = Vec::with_capacity(total as usize);

        // ── ELF Ident (16 bytes) ────────────────────────────────────────────
        b.extend_from_slice(b"\x7fELF");
        b.push(1); // ELFCLASS32
        b.push(if self.big_endian { 2 } else { 1 }); // EI_DATA
        b.push(1); // EI_VERSION
        b.push(0); // ELFOSABI_NONE
        b.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + padding

        // ── ELF Header fields ───────────────────────────────────────────────
        b.extend_from_slice(&self.w16(2)); // e_type = ET_EXEC
        b.extend_from_slice(&self.w16(self.e_machine));
        b.extend_from_slice(&self.w32(1)); // e_version
        b.extend_from_slice(&self.w32(entry)); // e_entry
        b.extend_from_slice(&self.w32(HDR)); // e_phoff
        b.extend_from_slice(&self.w32(0)); // e_shoff
        b.extend_from_slice(&self.w32(self.e_flags));
        b.extend_from_slice(&self.w16(52)); // e_ehsize
        b.extend_from_slice(&self.w16(32)); // e_phentsize
        b.extend_from_slice(&self.w16(1)); // e_phnum
        b.extend_from_slice(&self.w16(40)); // e_shentsize
        b.extend_from_slice(&self.w16(0)); // e_shnum
        b.extend_from_slice(&self.w16(0)); // e_shstrndx

        assert_eq!(b.len(), 52);

        // ── PT_LOAD phdr (ELF32: 32 bytes) ─────────────────────────────────
        b.extend_from_slice(&self.w32(1)); // p_type = PT_LOAD
        b.extend_from_slice(&self.w32(0)); // p_offset
        b.extend_from_slice(&self.w32(vbase)); // p_vaddr
        b.extend_from_slice(&self.w32(vbase)); // p_paddr
        b.extend_from_slice(&self.w32(total)); // p_filesz
        b.extend_from_slice(&self.w32(total)); // p_memsz
        b.extend_from_slice(&self.w32(5)); // p_flags = PF_R | PF_X
        b.extend_from_slice(&self.w32(0x1000)); // p_align

        assert_eq!(b.len(), 84);

        // ── Executable code ─────────────────────────────────────────────────
        b.extend_from_slice(code);

        assert_eq!(b.len(), total as usize);
        b
    }

    fn build64(&self, code: &[u8]) -> Vec<u8> {
        assert!(!code.is_empty(), "code must be non-empty");
        const HDR: u64 = 64;
        const PHD: u64 = 56;
        let code_len = code.len() as u64;
        let total = HDR + PHD + code_len;
        let vbase = self.vaddr_base;
        let entry = vbase + HDR + PHD;

        let mut b: Vec<u8> = Vec::with_capacity(total as usize);

        // ── ELF Ident (16 bytes) ────────────────────────────────────────────
        b.extend_from_slice(b"\x7fELF");
        b.push(2); // ELFCLASS64
        b.push(if self.big_endian { 2 } else { 1 }); // EI_DATA
        b.push(1); // EI_VERSION
        b.push(0); // ELFOSABI_NONE
        b.extend_from_slice(&[0u8; 8]); // padding

        // ── ELF Header fields ───────────────────────────────────────────────
        b.extend_from_slice(&self.w16(2)); // e_type = ET_EXEC
        b.extend_from_slice(&self.w16(self.e_machine));
        b.extend_from_slice(&self.w32(1)); // e_version
        b.extend_from_slice(&self.w64(entry)); // e_entry
        b.extend_from_slice(&self.w64(HDR)); // e_phoff
        b.extend_from_slice(&self.w64(0)); // e_shoff
        b.extend_from_slice(&self.w32(self.e_flags));
        b.extend_from_slice(&self.w16(64)); // e_ehsize
        b.extend_from_slice(&self.w16(56)); // e_phentsize
        b.extend_from_slice(&self.w16(1)); // e_phnum
        b.extend_from_slice(&self.w16(64)); // e_shentsize
        b.extend_from_slice(&self.w16(0)); // e_shnum
        b.extend_from_slice(&self.w16(0)); // e_shstrndx

        assert_eq!(b.len(), 64);

        // ── PT_LOAD phdr (ELF64: 56 bytes) — note: p_flags BEFORE p_offset ─
        b.extend_from_slice(&self.w32(1)); // p_type = PT_LOAD
        b.extend_from_slice(&self.w32(5)); // p_flags = PF_R | PF_X  (ELF64 layout)
        b.extend_from_slice(&self.w64(0)); // p_offset
        b.extend_from_slice(&self.w64(vbase)); // p_vaddr
        b.extend_from_slice(&self.w64(vbase)); // p_paddr
        b.extend_from_slice(&self.w64(total)); // p_filesz
        b.extend_from_slice(&self.w64(total)); // p_memsz
        b.extend_from_slice(&self.w64(0x1000)); // p_align

        assert_eq!(b.len(), 120);

        // ── Executable code ─────────────────────────────────────────────────
        b.extend_from_slice(code);

        assert_eq!(b.len(), total as usize);
        b
    }
}

// ─── PATH helpers ─────────────────────────────────────────────────────────────

/// Search `$PATH` for `binary_name`. Returns the full path if found.
fn find_in_path(binary_name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(binary_name);
            if candidate.is_file() { Some(candidate) } else { None }
        })
    })
}

/// Returns `true` if `binary_name` is found in PATH.
fn qemu_available(binary_name: &str) -> bool {
    find_in_path(binary_name).is_some()
}

// ─── Architecture table ───────────────────────────────────────────────────────
//
// (label, e_machine, ei_class, big_endian, e_flags, expected_qemu_binary,
//  vaddr_base, loop_code)
//
// loop_code: valid machine code that busy-loops forever so QEMU stays alive
// long enough for GDB to connect and send an interrupt signal.
//
// Encoding notes:
//   AArch64 LE:  B . → 0x14000000 → [00 00 00 14]
//   ARM LE:      B . → 0xEAFFFFFE → [FE FF FF EA]
//   ARM BE:      B . → 0xEAFFFFFE → [EA FF FF FE]
//   MIPS[el] LE: BEQ $0,$0,-1 (→ PC) + NOP (delay slot) → [FF FF 00 10][00 00 00 00]
//   MIPS BE:     same value big-endian → [10 00 FF FF][00 00 00 00]
//   PPC32 BE:    B . → 0x48000000 → [48 00 00 00]
//   PPC64 BE:    B . → 0x48000000 → [48 00 00 00]
//   PPC64 LE:    B . → 0x48000000 LE → [00 00 00 48]
//   RISC-V LE:   JAL x0, 0 → 0x0000006F → [6F 00 00 00]
//   S390x BE:    BRC 15, 0 (always→self) → [A7 F4 00 00]
//   i386 LE:     JMP . → [EB FE 90 90] (+ 2 NOPs for 4-byte pad)

#[allow(dead_code)]
struct ArchCase {
    label: &'static str,
    e_machine: u16,
    ei_class: u8,
    big_endian: bool,
    e_flags: u32,
    qemu_bin: &'static str,
    vaddr_base: u64,
    /// Architecture-specific machine code that loops forever.
    loop_code: &'static [u8],
}

static ARCH_CASES: &[ArchCase] = &[
    // AArch64 little-endian — B . = 0x14000000
    ArchCase {
        label: "aarch64",
        e_machine: 183,
        ei_class: 2,
        big_endian: false,
        e_flags: 0,
        qemu_bin: "qemu-aarch64",
        vaddr_base: 0x0040_0000,
        loop_code: &[0x00, 0x00, 0x00, 0x14], // B . (LE)
    },
    // ARM little-endian EABI — B . = 0xEAFFFFFE
    ArchCase {
        label: "arm",
        e_machine: 40,
        ei_class: 1,
        big_endian: false,
        e_flags: 0x0500_0000, // EF_ARM_EABI_VER5
        qemu_bin: "qemu-arm",
        vaddr_base: 0x0001_0000,
        loop_code: &[0xFE, 0xFF, 0xFF, 0xEA], // B . (LE)
    },
    // ARM big-endian EABI — B . = 0xEAFFFFFE
    ArchCase {
        label: "armeb",
        e_machine: 40,
        ei_class: 1,
        big_endian: true,
        e_flags: 0x0500_0000, // EF_ARM_EABI_VER5
        qemu_bin: "qemu-armeb",
        vaddr_base: 0x0001_0000,
        loop_code: &[0xEA, 0xFF, 0xFF, 0xFE], // B . (BE)
    },
    // MIPS little-endian — BEQ $0,$0,-1 (target=PC) + NOP delay slot
    ArchCase {
        label: "mipsel",
        e_machine: 8,
        ei_class: 1,
        big_endian: false,
        e_flags: 0,
        qemu_bin: "qemu-mipsel",
        vaddr_base: 0x0040_0000,
        loop_code: &[
            0xFF, 0xFF, 0x00, 0x10, // BEQ $0,$0,-1 (LE: 0x1000FFFF)
            0x00, 0x00, 0x00, 0x00, // NOP (delay slot)
        ],
    },
    // MIPS big-endian — BEQ $0,$0,-1 + NOP delay slot
    ArchCase {
        label: "mips",
        e_machine: 8,
        ei_class: 1,
        big_endian: true,
        e_flags: 0,
        qemu_bin: "qemu-mips",
        vaddr_base: 0x0040_0000,
        loop_code: &[
            0x10, 0x00, 0xFF, 0xFF, // BEQ $0,$0,-1 (BE)
            0x00, 0x00, 0x00, 0x00, // NOP (delay slot)
        ],
    },
    // PowerPC 32-bit big-endian — B . = 0x48000000
    ArchCase {
        label: "ppc",
        e_machine: 20,
        ei_class: 1,
        big_endian: true,
        e_flags: 0,
        qemu_bin: "qemu-ppc",
        vaddr_base: 0x0001_0000,
        loop_code: &[0x48, 0x00, 0x00, 0x00], // B . (BE)
    },
    // PowerPC 64-bit big-endian (ELFv2 ABI, e_flags=2) — B . = 0x48000000
    //
    // PPC64 BE normally uses ELFv1 where e_entry is an OPD function descriptor,
    // not a direct code pointer.  By setting EF_PPC64_ABI=2 (ELFv2), e_entry
    // points directly to the first instruction, which our minimal ELF requires.
    ArchCase {
        label: "ppc64",
        e_machine: 21,
        ei_class: 2,
        big_endian: true,
        e_flags: 2, // EF_PPC64_ABI_VER2 — ELFv2: e_entry is a direct code pointer
        qemu_bin: "qemu-ppc64",
        vaddr_base: 0x0001_0000,
        loop_code: &[0x48, 0x00, 0x00, 0x00], // B . (BE)
    },
    // PowerPC 64-bit little-endian (ELFv2 ABI, e_flags=2) — B . stored LE = [00 00 00 48]
    ArchCase {
        label: "ppc64le",
        e_machine: 21,
        ei_class: 2,
        big_endian: false,
        e_flags: 2, // EF_PPC64_ABI_VER2 — standard for PPC64 LE
        qemu_bin: "qemu-ppc64le",
        vaddr_base: 0x0001_0000,
        loop_code: &[0x00, 0x00, 0x00, 0x48], // B . (LE)
    },
    // RISC-V 64-bit — JAL x0, 0 = 0x0000006F (branch to self)
    ArchCase {
        label: "riscv64",
        e_machine: 243,
        ei_class: 2,
        big_endian: false,
        e_flags: 0,
        qemu_bin: "qemu-riscv64",
        vaddr_base: 0x0001_0000,
        loop_code: &[0x6F, 0x00, 0x00, 0x00], // JAL x0, 0 (LE)
    },
    // RISC-V 32-bit — JAL x0, 0 = 0x0000006F (branch to self)
    ArchCase {
        label: "riscv32",
        e_machine: 243,
        ei_class: 1,
        big_endian: false,
        e_flags: 0,
        qemu_bin: "qemu-riscv32",
        vaddr_base: 0x0001_0000,
        loop_code: &[0x6F, 0x00, 0x00, 0x00], // JAL x0, 0 (LE)
    },
    // IBM S/390x 64-bit big-endian — BRC 15, 0 (always branch to self)
    ArchCase {
        label: "s390x",
        e_machine: 22,
        ei_class: 2,
        big_endian: true,
        e_flags: 0,
        qemu_bin: "qemu-s390x",
        vaddr_base: 0x0001_0000,
        loop_code: &[0xA7, 0xF4, 0x00, 0x00], // BRC 15, 0 (BE): always branch to self
    },
    // x86 32-bit — JMP . = EB FE (+ 2 NOP padding for 4-byte alignment)
    ArchCase {
        label: "i386",
        e_machine: 3,
        ei_class: 1,
        big_endian: false,
        e_flags: 0,
        qemu_bin: "qemu-i386",
        vaddr_base: 0x0804_8000,
        loop_code: &[0xEB, 0xFE, 0x90, 0x90], // JMP . + 2× NOP
    },
];

// ─── Unit tests: ElfInfo parsing ─────────────────────────────────────────────

#[cfg(all(unix, feature = "qemu-user"))]
mod elf_info_unit {
    use super::{ArchCase, ARCH_CASES, MiniElf};
    use mcp_server_gdb::qemu::ElfInfo;

    fn build_and_parse(arch: &ArchCase) -> ElfInfo {
        // Use all-zero code: we're testing ELF header parsing, not execution.
        let elf =
            MiniElf { e_machine: arch.e_machine, ei_class: arch.ei_class, big_endian: arch.big_endian, e_flags: arch.e_flags, vaddr_base: arch.vaddr_base };
        ElfInfo::from_bytes(&elf.build())
            .unwrap_or_else(|e| panic!("[{}] ElfInfo::from_bytes failed: {}", arch.label, e))
    }

    /// All architecture ELFs parse without error and fields match the expected
    /// values.
    #[test]
    fn all_arches_parse_correctly() {
        for arch in ARCH_CASES {
            let info = build_and_parse(arch);
            assert_eq!(info.e_machine, arch.e_machine, "[{}] e_machine", arch.label);
            assert_eq!(info.ei_class, arch.ei_class, "[{}] ei_class", arch.label);
            assert_eq!(info.big_endian, arch.big_endian, "[{}] big_endian", arch.label);
            assert_eq!(info.e_flags, arch.e_flags, "[{}] e_flags", arch.label);
            // Static ELF — no .interp section, so not dynamic.
            assert!(!info.is_dynamic, "[{}] should not be dynamic", arch.label);
            assert!(info.interp_path.is_none(), "[{}] interp_path should be None", arch.label);
        }
    }

    /// `qemu_user_binary()` maps each architecture to the expected QEMU binary.
    #[test]
    fn qemu_binary_mapping() {
        for arch in ARCH_CASES {
            let info = build_and_parse(arch);
            let binary = info
                .qemu_user_binary()
                .unwrap_or_else(|e| panic!("[{}] qemu_user_binary() error: {}", arch.label, e));
            assert_eq!(
                binary.as_deref(),
                Some(arch.qemu_bin),
                "[{}] expected qemu binary '{}'",
                arch.label,
                arch.qemu_bin
            );
        }
    }

    /// x86_64 returns `None` (host arch — prefer Native backend).
    #[test]
    fn x86_64_returns_none() {
        let elf = MiniElf { e_machine: 62, ei_class: 2, big_endian: false, e_flags: 0, vaddr_base: 0x0040_0000 };
        let info = ElfInfo::from_bytes(&elf.build()).expect("parse x86_64 ELF");
        let binary = info.qemu_user_binary().expect("qemu_user_binary x86_64");
        assert_eq!(binary, None, "x86_64 should return None");
    }

    /// ELF smaller than 64 bytes must be rejected.
    #[test]
    fn too_small_is_rejected() {
        let err = ElfInfo::from_bytes(&[0u8; 32])
            .err()
            .expect("should return Err for too-small input");
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("small") || msg.contains("elf"), "unexpected error: {err}");
    }

    /// Non-ELF data (bad magic) must be rejected.
    #[test]
    fn bad_magic_is_rejected() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"NELF"); // wrong magic
        let err = ElfInfo::from_bytes(&data)
            .err()
            .expect("should return Err for bad magic");
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("magic") || msg.contains("elf"), "unexpected error: {err}");
    }

    /// An unsupported e_machine value must return an error from
    /// `qemu_user_binary()`, not a panic.
    #[test]
    fn unsupported_machine_returns_error() {
        let elf = MiniElf { e_machine: 0xBEEF, ei_class: 2, big_endian: false, e_flags: 0, vaddr_base: 0x1000 };
        let info = ElfInfo::from_bytes(&elf.build()).expect("parse unknown ELF");
        let err = info.qemu_user_binary()
            .err()
            .expect("should return Err for unsupported machine");
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("unsupported"), "expected 'unsupported' in: {err}");
    }
}

// ─── Integration tests: full QEMU user session lifecycle ─────────────────────

#[cfg(all(unix, feature = "qemu-user"))]
mod qemu_session {
    use std::sync::Arc;

    use mcp_server_gdb::GDBManager;

    use super::{ArchCase, ARCH_CASES, MiniElf, find_in_path, qemu_available};

    /// Write `bytes` to a temporary file with execute permissions.
    fn write_exec_tempfile(bytes: &[u8]) -> tempfile::NamedTempFile {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        std::fs::write(tmp.path(), bytes).expect("write ELF bytes");
        let mut perms = std::fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(tmp.path(), perms).unwrap();
        tmp
    }

    /// Run a single QEMU user-mode session lifecycle test for `arch`.
    ///
    /// Steps:
    ///   1. Build a minimal ELF with an infinite-loop entry point.
    ///   2. Skip (Ok) if the QEMU binary is not in PATH.
    ///   3. Create a QEMU user-mode session (spawns QEMU + GDB).
    ///   4. Send GDB interrupt so the looping process stops.
    ///   5. Verify that `info registers` returns non-empty output.
    ///   6. Close the session (kills GDB + QEMU).
    ///
    /// Returns `Ok(())` on success or skip, `Err(message)` on failure.
    async fn run_arch_test(manager: &GDBManager, arch: &ArchCase) -> Result<(), String> {
        if !qemu_available(arch.qemu_bin) {
            eprintln!("[SKIP] {}: {} not in PATH", arch.label, arch.qemu_bin);
            return Ok(());
        }

        let elf_bytes = MiniElf {
            e_machine: arch.e_machine,
            ei_class: arch.ei_class,
            big_endian: arch.big_endian,
            e_flags: arch.e_flags,
            vaddr_base: arch.vaddr_base,
        }
        .build_with_code(arch.loop_code);

        let tmp = write_exec_tempfile(&elf_bytes);
        let binary = tmp.path().to_path_buf();

        // Use the explicit binary path to avoid PATH-search races in tests.
        let qemu_path = find_in_path(arch.qemu_bin);

        let session_id = match manager
            .create_qemu_user_session(
                binary,
                None,      // binary_args
                qemu_path, // explicit QEMU binary path
                None,      // sysroot (static binary — not needed)
                false,     // auto_fetch_libc
                None,      // gdb_port (auto-allocate)
                None,      // gdb_path (use "gdb" from PATH)
                None,      // gef_script
                None,      // gef_rc
                None,      // symbol_file
            )
            .await
        {
            Ok(id) => id,
            Err(e) => {
                return Err(format!("{}: create_qemu_user_session: {}", arch.label, e));
            }
        };

        eprintln!("[OK] {}: session_id = {session_id}", arch.label);

        // The process is running the infinite loop. Send GDB Ctrl+C to stop it,
        // then read registers to confirm GDB is fully operational.
        let _ = manager.execute_cli(&session_id, "interrupt").await;

        // Give the interrupt a moment to take effect.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let regs = match manager.execute_cli(&session_id, "info registers").await {
            Ok(r) => r,
            Err(e) => {
                let _ = manager.close_session(&session_id).await;
                return Err(format!("{}: info registers: {}", arch.label, e));
            }
        };

        let result = if regs.trim().is_empty() {
            Err(format!("{}: 'info registers' returned empty output", arch.label))
        } else {
            eprintln!("[OK] {}: registers read ({} chars)", arch.label, regs.len());
            Ok(())
        };

        // Always close the session even if an assertion failed.
        if let Err(e) = manager.close_session(&session_id).await {
            eprintln!("[WARN] {}: close_session: {}", arch.label, e);
        }
        eprintln!("[DONE] {}", arch.label);
        result
    }

    /// Test all supported architectures sequentially.
    ///
    /// Architectures whose `qemu-<arch>` binary is absent from PATH are
    /// skipped with a `[SKIP]` log line; they do not cause test failure.
    /// All other architectures are tested and failures are collected; the
    /// test fails at the end if any architecture had an error.
    #[tokio::test]
    async fn all_architectures() {
        let manager = Arc::new(GDBManager::default());
        let mut failures: Vec<String> = Vec::new();

        for arch in ARCH_CASES {
            match run_arch_test(&manager, arch).await {
                Ok(()) => {}
                Err(msg) => {
                    eprintln!("[FAIL] {}", msg);
                    failures.push(msg);
                }
            }
        }

        if !failures.is_empty() {
            panic!(
                "{} architecture(s) failed:\n{}",
                failures.len(),
                failures.join("\n")
            );
        }
    }
}
