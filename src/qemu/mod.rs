/// QEMU backend support for cross-architecture debugging.
///
/// Provides user-mode and system-mode QEMU process management,
/// ELF architecture detection, port allocation, and TCP readiness checks.

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::warn;

use crate::error::{AppError, AppResult};

// ─── Port allocation ─────────────────────────────────────────────────────────

/// Bind to port 0 (OS picks a free ephemeral port) then immediately close.
/// The port is almost certainly free for the brief window until QEMU binds it.
pub fn allocate_free_port() -> AppResult<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

// ─── TCP readiness ───────────────────────────────────────────────────────────

/// Poll until the QEMU GDB stub TCP port is listening, or the deadline passes.
///
/// Checks for early child exit on every iteration so callers get a meaningful
/// error rather than a timeout when QEMU fails to start.
pub async fn wait_for_tcp_ready(
    child: &mut tokio::process::Child,
    port: u16,
    timeout: Duration,
) -> AppResult<()> {
    let deadline = Instant::now() + timeout;
    loop {
        // Detect premature QEMU exit.
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(AppError::backend(
                    "qemu.wait_ready",
                    format!("QEMU exited early with status: {:?}", status),
                ));
            }
            Ok(None) => {}
            Err(e) => {
                return Err(AppError::backend(
                    "qemu.wait_ready",
                    format!("QEMU wait error: {}", e),
                ));
            }
        }

        // Try connecting to the stub port.
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(AppError::timeout(
                "qemu.wait_ready",
                format!("QEMU GDB stub port {} not ready within {:?}", port, timeout),
            ));
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ─── QemuProcess ─────────────────────────────────────────────────────────────

/// Shared handle to a running QEMU child process.
///
/// Both the background monitor task and `close_session` hold a clone of
/// `child` via `Arc<Mutex<>>`, so neither needs to transfer ownership.
#[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
pub struct QemuProcess {
    /// Shared child process — accessed by the monitor task and close_session.
    pub child: Arc<Mutex<tokio::process::Child>>,
    /// GDB remote stub port QEMU is listening on.
    pub port: u16,
    /// Rolling buffer of the last 50 QEMU stderr lines (for diagnostics).
    pub stderr_lines: Arc<Mutex<Vec<String>>>,
}

// ─── ELF info (qemu-user only) ───────────────────────────────────────────────

/// Parsed ELF header fields needed for QEMU user-mode setup.
#[cfg(feature = "qemu-user")]
pub struct ElfInfo {
    pub e_machine: u16,
    pub e_flags: u32,
    /// EI_CLASS: 1 = 32-bit, 2 = 64-bit
    pub ei_class: u8,
    pub big_endian: bool,
    /// True when the ELF has a PT_INTERP segment (dynamically linked).
    pub is_dynamic: bool,
    /// Contents of the .interp section (dynamic linker path).
    pub interp_path: Option<String>,
}

#[cfg(feature = "qemu-user")]
impl ElfInfo {
    /// Parse the ELF header of `path` and return the fields we need.
    pub fn from_path(path: &Path) -> AppResult<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    pub fn from_bytes(data: &[u8]) -> AppResult<Self> {
        // Validate ELF magic.
        if data.len() < 64 {
            return Err(AppError::invalid_argument("qemu.elf_info", "File too small to be ELF"));
        }
        if &data[..4] != b"\x7fELF" {
            return Err(AppError::invalid_argument("qemu.elf_info", "Not a valid ELF file (bad magic)"));
        }

        let ei_class = data[4]; // ELFCLASS32=1, ELFCLASS64=2
        let ei_data = data[5]; // ELFDATA2LSB=1, ELFDATA2MSB=2
        let big_endian = ei_data == 2;

        // e_machine is at offset 18 for both ELF32 and ELF64.
        let e_machine = read_u16(data, 18, big_endian).ok_or_else(|| {
            AppError::invalid_argument("qemu.elf_info", "ELF header truncated (e_machine)")
        })?;

        // e_flags offset differs between ELF32 and ELF64.
        let e_flags_offset = if ei_class == 1 { 36usize } else { 48usize };
        let e_flags = read_u32(data, e_flags_offset, big_endian).unwrap_or(0);

        // Use the `object` crate to find the .interp section (presence → dynamic).
        use object::{Object, ObjectSection};
        let obj = object::read::File::parse(data as &[u8])
            .map_err(|e| AppError::invalid_argument("qemu.elf_info", format!("ELF parse error: {}", e)))?;

        let interp_path = obj
            .section_by_name(".interp")
            .and_then(|sec| sec.data().ok().map(|d| d.to_vec()))
            .and_then(|bytes| {
                let s = if bytes.last() == Some(&0) { &bytes[..bytes.len() - 1] } else { &bytes[..] };
                std::str::from_utf8(s).ok().map(|s| s.to_string())
            });

        let is_dynamic = interp_path.is_some();

        Ok(ElfInfo { e_machine, e_flags, ei_class, big_endian, is_dynamic, interp_path })
    }

    /// Map `e_machine` + `e_flags` to the appropriate `qemu-<arch>` binary name.
    ///
    /// Returns the binary name only (no path). The caller resolves it via PATH.
    /// Returns `None` for x86_64 to signal that the Native backend is preferred.
    pub fn qemu_user_binary(&self) -> AppResult<Option<String>> {
        let name = match self.e_machine {
            // EM_386
            3 => "qemu-i386",
            // EM_MIPS
            8 => {
                if self.big_endian {
                    "qemu-mips"
                } else {
                    "qemu-mipsel"
                }
            }
            // EM_PPC
            20 => "qemu-ppc",
            // EM_PPC64
            21 => {
                if self.big_endian {
                    "qemu-ppc64"
                } else {
                    "qemu-ppc64le"
                }
            }
            // EM_S390
            22 => "qemu-s390x",
            // EM_ARM
            40 => {
                if self.big_endian {
                    "qemu-armeb"
                } else {
                    "qemu-arm"
                }
            }
            // EM_X86_64 — host architecture, Native backend is preferred
            62 => return Ok(None),
            // EM_AARCH64
            183 => "qemu-aarch64",
            // EM_RISCV
            243 => {
                if self.ei_class == 2 {
                    "qemu-riscv64"
                } else {
                    "qemu-riscv32"
                }
            }
            other => {
                return Err(AppError::invalid_argument(
                    "qemu.elf_info",
                    format!(
                        "Unsupported e_machine 0x{:04x}; specify qemu_path explicitly",
                        other
                    ),
                ));
            }
        };
        Ok(Some(name.to_string()))
    }

}

// ─── Byte reading helpers ─────────────────────────────────────────────────────

#[cfg(feature = "qemu-user")]
fn read_u16(data: &[u8], offset: usize, big_endian: bool) -> Option<u16> {
    let b = data.get(offset..offset + 2)?;
    if big_endian {
        Some(u16::from_be_bytes([b[0], b[1]]))
    } else {
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
}

#[cfg(feature = "qemu-user")]
fn read_u32(data: &[u8], offset: usize, big_endian: bool) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    if big_endian {
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    } else {
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

// ─── Spawn helpers ────────────────────────────────────────────────────────────

/// Spawn `qemu-<arch>` in user mode with a GDB stub on `port`.
///
/// `sysroot` is passed as `-L <path>` to redirect dynamic library lookups.
/// Returns the raw `Child` before it is wrapped in `Arc<Mutex<>>` so that
/// `wait_for_tcp_ready` can monitor it without holding a lock.
#[cfg(feature = "qemu-user")]
pub async fn spawn_qemu_user(
    qemu_bin: &Path,
    port: u16,
    binary: &Path,
    binary_args: &[OsString],
    sysroot: Option<&Path>,
) -> AppResult<tokio::process::Child> {
    let mut cmd = tokio::process::Command::new(qemu_bin);

    if let Some(root) = sysroot {
        cmd.arg("-L").arg(root);
    }

    cmd.arg("-g").arg(port.to_string());
    cmd.arg(binary);
    cmd.args(binary_args);
    cmd.stderr(std::process::Stdio::piped());

    cmd.spawn().map_err(|e| {
        AppError::backend(
            "qemu.spawn_user",
            format!("Failed to spawn '{}': {}", qemu_bin.display(), e),
        )
    })
}

/// Spawn a QEMU system-mode VM.
///
/// The caller is responsible for passing `-S -gdb tcp::<port>` in `qemu_args`.
/// Returns the raw `Child`.
#[cfg(feature = "qemu-system")]
pub async fn spawn_qemu_system(
    qemu_path: &Path,
    qemu_args: &[OsString],
) -> AppResult<tokio::process::Child> {
    let mut cmd = tokio::process::Command::new(qemu_path);
    cmd.args(qemu_args);
    cmd.stderr(std::process::Stdio::piped());

    cmd.spawn().map_err(|e| {
        AppError::backend(
            "qemu.spawn_system",
            format!("Failed to spawn '{}': {}", qemu_path.display(), e),
        )
    })
}

/// Spawn a background task that polls the QEMU child every 500 ms
/// and logs when it exits.  The task holds its own `Arc` clone of the
/// child so it never blocks `close_session`.
#[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
pub fn spawn_qemu_monitor(
    child_arc: Arc<Mutex<tokio::process::Child>>,
    stderr_lines: Arc<Mutex<Vec<String>>>,
    session_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let exit_status = {
                let mut child = child_arc.lock().await;
                child.try_wait().ok().flatten()
            };
            if let Some(status) = exit_status {
                let lines = stderr_lines.lock().await;
                warn!(
                    session_id = %session_id,
                    exit_status = ?status,
                    last_stderr = ?lines.last(),
                    "QEMU process exited"
                );
                break;
            }
        }
    })
}
