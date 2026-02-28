use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use portable_pty::{PtyPair, PtySize, native_pty_system};
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader as TokioBufReader;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult, ErrorKind, ResultContextExt};
use crate::mi::commands::{BreakPointLocation, BreakPointNumber, MiCommand, RegisterFormat};
use crate::mi::output::{OutOfBandRecord, ResultClass, ResultRecord, StreamKind};
use crate::mi::{GDB, GDBBuilder};
use crate::models::{
    BreakPoint, DebugBackendKind, GDBSession, GDBSessionStatus, LaunchMode, Memory, Register,
    StackFrame, Variable,
};

fn normalize_mi_list(value: serde_json::Value, inner_key: &str) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    serde_json::Value::Object(mut map) => {
                        if let Some(inner) = map.remove(inner_key) {
                            out.push(inner);
                        } else {
                            out.push(serde_json::Value::Object(map));
                        }
                    }
                    other => out.push(other),
                }
            }
            serde_json::Value::Array(out)
        }
        serde_json::Value::Object(mut map) => {
            if let Some(inner) = map.remove(inner_key) {
                match inner {
                    serde_json::Value::Array(_) => inner,
                    serde_json::Value::Null => serde_json::Value::Array(vec![]),
                    other => serde_json::Value::Array(vec![other]),
                }
            } else if map.is_empty() {
                serde_json::Value::Array(vec![])
            } else {
                serde_json::Value::Array(vec![serde_json::Value::Object(map)])
            }
        }
        serde_json::Value::Null => serde_json::Value::Array(vec![]),
        other => serde_json::Value::Array(vec![other]),
    }
}

/// GDB Session Manager
#[derive(Default)]
pub struct GDBManager {
    /// Configuration
    config: Config,
    /// Session mapping table
    sessions: Mutex<HashMap<String, GDBSessionHandle>>,
}

/// GDB Session Handle
struct GDBSessionHandle {
    /// Session information
    info: GDBSession,
    /// GDB instance
    gdb: GDB,
    /// OOB handle
    oob_handle: JoinHandle<()>,
    /// Stderr reader handle
    stderr_handle: Option<JoinHandle<()>>,
    /// Buffered console output from GDB/GEF commands
    stream_buffer: Arc<Mutex<Vec<String>>>,
    /// PTY master/slave pair for inferior I/O
    #[allow(dead_code)]
    pty_pair: Option<PtyPair>,
    /// PTY reader task handle
    pty_read_handle: Option<JoinHandle<()>>,
    /// PTY writer for inferior stdin
    pty_writer: Option<Box<dyn Write + Send>>,
    /// Buffered inferior output from PTY master
    inferior_output: Option<Arc<Mutex<Vec<u8>>>>,
    /// QEMU child process (User or System mode).
    #[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
    qemu: Option<crate::qemu::QemuProcess>,
    /// Background task that polls QEMU for unexpected exit.
    #[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
    qemu_monitor: Option<JoinHandle<()>>,
    /// Keeps the libc TempDir alive until the session is closed.
    /// Stored as `Box<dyn Any + Send>` to avoid exposing `tempfile` types here.
    #[cfg(feature = "libc-fetch")]
    _libc_work_dir: Option<Box<dyn std::any::Any + Send>>,
}

impl GDBManager {
    /// Create a new GDB session
    pub async fn create_session(
        &self,
        program: Option<PathBuf>,
        nh: Option<bool>,
        nx: Option<bool>,
        quiet: Option<bool>,
        cd: Option<PathBuf>,
        bps: Option<u32>,
        symbol_file: Option<PathBuf>,
        core_file: Option<PathBuf>,
        proc_id: Option<u32>,
        command: Option<PathBuf>,
        source_dir: Option<PathBuf>,
        args: Option<Vec<OsString>>,
        tty: Option<PathBuf>,
        gdb_path: Option<PathBuf>,
        gef_script: Option<PathBuf>,
        gef_rc: Option<PathBuf>,
        create_pty: Option<bool>,
        lib_dir: Option<PathBuf>,
    ) -> AppResult<String> {
        // Generate unique session ID
        let session_id = Uuid::new_v4().to_string();

        let mut pty_pair: Option<PtyPair> = None;
        let mut pty_writer: Option<Box<dyn Write + Send>> = None;
        let mut pty_read_handle: Option<JoinHandle<()>> = None;
        let mut inferior_output: Option<Arc<Mutex<Vec<u8>>>> = None;
        let create_pty = create_pty.unwrap_or(true);
        let mut tty_path = tty;
        let mut gef_script = gef_script;
        let gef_rc = gef_rc.or_else(|| self.config.gef_rc.clone());

        if gef_script.is_none() {
            let default_gef = PathBuf::from("vendor/gef/gef.py");
            if default_gef.exists() {
                gef_script = Some(default_gef);
            }
        }

        if create_pty {
            if tty_path.is_some() {
                return Err(AppError::invalid_argument(
                    "gdb.create_session",
                    "Cannot combine create_pty with an explicit tty path",
                ));
            }
            let pty_system = native_pty_system();
            let pair = pty_system
                .openpty(PtySize {
                    rows: 24,
                    cols: 80,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .context("gdb.create_session", "open PTY")?;

            let slave_name = {
                #[cfg(unix)]
                {
                    pair.master.tty_name().ok_or_else(|| {
                        AppError::backend(
                            "gdb.create_session",
                            "Failed to resolve PTY slave name",
                        )
                    })?
                }
                #[cfg(windows)]
                {
                    return Err(AppError::invalid_argument(
                        "gdb.create_session",
                        "PTY auto-creation is not supported on Windows yet",
                    ));
                }
            };
            tty_path = Some(slave_name);

            let reader = pair
                .master
                .try_clone_reader()
                .context("gdb.create_session", "clone PTY reader")?;
            let writer = pair
                .master
                .take_writer()
                .context("gdb.create_session", "take PTY writer")?;

            let output_buffer = Arc::new(Mutex::new(Vec::new()));
            let output_clone = output_buffer.clone();

            let reader_handle = tokio::task::spawn_blocking(move || {
                let mut reader = reader;
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut output = output_clone.blocking_lock();
                            output.extend_from_slice(&buf[..n]);
                        }
                        Err(err) => {
                            warn!("PTY read error: {}", err);
                            break;
                        }
                    }
                }
            });

            pty_pair = Some(pair);
            pty_writer = Some(writer);
            pty_read_handle = Some(reader_handle);
            inferior_output = Some(output_buffer);
        }

        // Capture before values are moved into the builder (used for lib_dir logic).
        let is_exec_run = proc_id.is_none() && core_file.is_none();

        let gdb_builder = GDBBuilder {
            gdb_path: gdb_path.unwrap_or_else(|| PathBuf::from("gdb")),
            opt_nh: nh.unwrap_or(false),
            opt_nx: nx.unwrap_or(false),
            opt_quiet: quiet.unwrap_or(false),
            opt_cd: cd,
            opt_bps: bps,
            opt_symbol_file: symbol_file,
            opt_core_file: core_file,
            opt_proc_id: proc_id,
            opt_command: command,
            opt_source_dir: source_dir,
            opt_args: args.unwrap_or(vec![]),
            opt_program: program,
            opt_tty: tty_path,
            opt_gef_script: gef_script,
            opt_gef_rc: gef_rc,
            opt_create_pty: create_pty,
        };

        let (oob_src, mut oob_sink) = mpsc::channel(100);
        let gdb = gdb_builder
            .try_spawn(oob_src)
            .context("gdb.create_session", "spawn GDB process")?;

        let stream_buffer = Arc::new(Mutex::new(Vec::new()));
        let stream_buffer_clone = stream_buffer.clone();
        let oob_handle = tokio::spawn(async move {
            loop {
                match oob_sink.recv().await {
                    Some(record) => match record {
                        OutOfBandRecord::AsyncRecord { results, .. } => {
                            debug!("AsyncRecord: {:?}", results);
                        }
                        OutOfBandRecord::StreamRecord { kind, data } => {
                            if matches!(kind, StreamKind::Console | StreamKind::Log | StreamKind::Target)
                            {
                                let mut buffer = stream_buffer_clone.lock().await;
                                buffer.push(data.clone());
                            }
                            debug!("StreamRecord: {:?}", data);
                        }
                    },
                    None => {
                        debug!("Source Channel closed");
                        break;
                    }
                }
            }
        });

        let stderr_handle = {
            let mut process = gdb.process.lock().await;
            let stderr = process.stderr.take();
            drop(process);
            stderr.map(|stderr| {
                let stream_buffer_clone = stream_buffer.clone();
                tokio::spawn(async move {
                    let mut reader = TokioBufReader::new(stderr);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) => break,
                            Ok(_) => {
                                let mut buffer = stream_buffer_clone.lock().await;
                                buffer.push(line.clone());
                            }
                            Err(err) => {
                                warn!("GDB stderr read error: {}", err);
                                break;
                            }
                        }
                    }
                })
            })
        };

        // Create session information
        let session = GDBSession {
            id: session_id.clone(),
            status: GDBSessionStatus::Created,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            backend: DebugBackendKind::Native,
            launch_mode: LaunchMode::ExecRun,
            qemu_port: None,
        };

        // Store session
        let handle = GDBSessionHandle {
            info: session,
            gdb,
            oob_handle,
            stderr_handle,
            stream_buffer,
            pty_pair,
            pty_read_handle,
            pty_writer,
            inferior_output,
            #[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
            qemu: None,
            #[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
            qemu_monitor: None,
            #[cfg(feature = "libc-fetch")]
            _libc_work_dir: None,
        };

        self.sessions.lock().await.insert(session_id.clone(), handle);

        // Send empty command to GDB to flush the welcome messages
        let _ = self.send_command(&session_id, &MiCommand::empty()).await?;

        // lib_dir: configure shared-library search path and LD_LIBRARY_PATH
        if let Some(ref lib_dir) = lib_dir {
            let solib_cmd = MiCommand::cli_exec(
                &format!("set solib-search-path \"{}\"", lib_dir.display()),
            );
            self.send_command(&session_id, &solib_cmd)
                .await
                .context("gdb.create_session", "set solib-search-path")?;

            // LD_LIBRARY_PATH only makes sense for fresh exec (not attach/core)
            if is_exec_run {
                let env_cmd = MiCommand::cli_exec(
                    &format!("set environment LD_LIBRARY_PATH \"{}\"", lib_dir.display()),
                );
                // Failure is non-fatal; older GDB versions may not support this
                let _ = self.send_command(&session_id, &env_cmd).await;
            }
        }

        Ok(session_id)
    }

    /// Get all sessions
    pub async fn get_all_sessions(&self) -> AppResult<Vec<GDBSession>> {
        let sessions = self.sessions.lock().await;
        let result = sessions.values().map(|handle| handle.info.clone()).collect();
        Ok(result)
    }

    /// Get specific session
    pub async fn get_session(&self, session_id: &str) -> AppResult<GDBSession> {
        let sessions = self.sessions.lock().await;
        let handle = sessions.get(session_id).ok_or_else(|| {
            AppError::not_found(
                "gdb.get_session",
                format!("Session {} does not exist", session_id),
            )
        })?;
        Ok(handle.info.clone())
    }

    /// Close session
    pub async fn close_session(&self, session_id: &str) -> AppResult<()> {
        let _ = match self.send_command_with_timeout(session_id, &MiCommand::exit()).await {
            Ok(result) => Some(result),
            Err(e) => {
                warn!("GDB exit command timed out, forcing process termination: {}", e.to_string());
                // Ignore timeout error, continue to force terminate the process
                None
            }
        };

        let mut sessions = self.sessions.lock().await;
        let handle = sessions.remove(session_id);

        if let Some(handle) = handle {
            handle.oob_handle.abort();
            if let Some(stderr_handle) = handle.stderr_handle {
                stderr_handle.abort();
            }
            if let Some(pty_handle) = handle.pty_read_handle {
                pty_handle.abort();
            }
            // Terminate GDB process
            let mut process = handle.gdb.process.lock().await;
            let _ = process.kill().await; // Ignore possible errors, process may have already terminated
            drop(process);

            // Terminate QEMU process (if any).
            #[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
            if let Some(qemu) = handle.qemu {
                // Stop the monitor task first so it doesn't race with our kill().
                if let Some(monitor) = handle.qemu_monitor {
                    monitor.abort();
                }
                let mut child = qemu.child.lock().await;
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
            // _libc_work_dir drops here, removing the TempDir.
        }

        Ok(())
    }

    // ─── QEMU User-mode session ───────────────────────────────────────────────

    /// Create a GDB session targeting a foreign-architecture ELF via QEMU user-mode.
    ///
    /// Steps:
    /// 1. Parse ELF to determine architecture.
    /// 2. Resolve QEMU binary (from `qemu_path` or PATH lookup by arch).
    /// 3. Decide sysroot: explicit / auto-fetch libc / static (no sysroot needed).
    /// 4. Spawn QEMU with `-g <port>`.
    /// 5. Wait for the GDB stub TCP port to open.
    /// 6. Spawn GDB and connect with `target remote localhost:<port>`.
    #[cfg(feature = "qemu-user")]
    pub async fn create_qemu_user_session(
        &self,
        binary: PathBuf,
        binary_args: Option<Vec<std::ffi::OsString>>,
        qemu_path: Option<PathBuf>,
        sysroot: Option<PathBuf>,
        auto_fetch_libc: bool,
        gdb_port: Option<u16>,
        gdb_path: Option<PathBuf>,
        gef_script: Option<PathBuf>,
        gef_rc: Option<PathBuf>,
        symbol_file: Option<PathBuf>,
    ) -> AppResult<String> {
        use crate::qemu::{
            ElfInfo, QemuProcess, allocate_free_port, spawn_qemu_monitor, spawn_qemu_user,
            wait_for_tcp_ready,
        };

        let session_id = Uuid::new_v4().to_string();

        // ── 1. Parse ELF ──────────────────────────────────────────────────────
        let elf_info = ElfInfo::from_path(&binary)?;

        // ── 2. Resolve QEMU binary ────────────────────────────────────────────
        let qemu_bin = if let Some(p) = qemu_path {
            p
        } else {
            match elf_info.qemu_user_binary()? {
                Some(name) => PathBuf::from(name),
                None => {
                    return Err(AppError::invalid_argument(
                        "qemu.create_user_session",
                        "x86_64 binary detected; use the native backend (create_session) instead, \
                         or pass qemu_path explicitly to force QEMU",
                    ));
                }
            }
        };

        // ── 3. Determine port ─────────────────────────────────────────────────
        let port = match gdb_port {
            Some(p) => p,
            None => allocate_free_port()?,
        };

        // ── 4. Resolve sysroot ────────────────────────────────────────────────
        // We use a type-erased box to keep TempDir alive without leaking
        // tempfile types into GDBSessionHandle.
        #[cfg(feature = "libc-fetch")]
        let mut _libc_work_dir_holder: Option<Box<dyn std::any::Any + Send>> = None;

        let resolved_sysroot: Option<PathBuf> = if let Some(s) = sysroot {
            Some(s)
        } else if elf_info.is_dynamic {
            if auto_fetch_libc {
                #[cfg(feature = "libc-fetch")]
                {
                    let result =
                        crate::libc_fetch::extract_sysroot(&binary, &elf_info).await?;
                    let sysroot_path = result.sysroot.clone();
                    _libc_work_dir_holder = Some(Box::new(result._work_dir));
                    Some(sysroot_path)
                }
                #[cfg(not(feature = "libc-fetch"))]
                {
                    return Err(AppError::invalid_argument(
                        "qemu.create_user_session",
                        "auto_fetch_libc=true requires the server to be built with \
                         the libc-fetch feature (cargo build --features libc-fetch)",
                    ));
                }
            } else {
                return Err(AppError::invalid_argument(
                    "qemu.create_user_session",
                    "Dynamic binary requires either sysroot or auto_fetch_libc=true. \
                     For a static binary, this check is skipped automatically.",
                ));
            }
        } else {
            // Static binary — QEMU can run it without a sysroot.
            None
        };

        // ── 5. Spawn QEMU ─────────────────────────────────────────────────────
        let binary_args = binary_args.unwrap_or_default();
        let mut raw_child =
            spawn_qemu_user(&qemu_bin, port, &binary, &binary_args, resolved_sysroot.as_deref())
                .await?;

        // Drain QEMU stderr into a rolling buffer for diagnostics.
        let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));
        if let Some(stderr) = raw_child.stderr.take() {
            let lines_clone = stderr_lines.clone();
            tokio::spawn(async move {
                let mut reader = TokioBufReader::new(stderr);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let mut buf = lines_clone.lock().await;
                            if buf.len() >= 50 {
                                buf.remove(0);
                            }
                            buf.push(line.trim_end().to_string());
                        }
                    }
                }
            });
        }

        // Wait for the GDB stub to open its port (timeout: 3 s).
        wait_for_tcp_ready(&mut raw_child, port, Duration::from_secs(3)).await?;

        // Wrap in Arc so the monitor task and close_session can share ownership.
        let child_arc = Arc::new(Mutex::new(raw_child));

        let qemu_process = QemuProcess {
            child: child_arc.clone(),
            port,
            stderr_lines: stderr_lines.clone(),
        };

        // ── 6. Spawn GDB ──────────────────────────────────────────────────────
        let mut gef_script = gef_script;
        let gef_rc = gef_rc.or_else(|| self.config.gef_rc.clone());
        if gef_script.is_none() {
            let default_gef = PathBuf::from("vendor/gef/gef.py");
            if default_gef.exists() {
                gef_script = Some(default_gef);
            }
        }

        // Default symbol file to the binary itself.
        let symbol_file = symbol_file.or_else(|| Some(binary.clone()));

        let gdb_builder = GDBBuilder {
            gdb_path: gdb_path.unwrap_or_else(|| PathBuf::from("gdb")),
            opt_nh: false,
            opt_nx: true,
            opt_quiet: true,
            opt_cd: None,
            opt_bps: None,
            opt_symbol_file: symbol_file,
            opt_core_file: None,
            opt_proc_id: None,
            opt_command: None,
            opt_source_dir: None,
            opt_args: vec![],
            opt_program: None,
            opt_tty: None,
            opt_gef_script: gef_script,
            opt_gef_rc: gef_rc,
            opt_create_pty: false,
        };

        let (oob_src, mut oob_sink) = mpsc::channel(100);
        let gdb = gdb_builder
            .try_spawn(oob_src)
            .context("qemu.create_user_session", "spawn GDB process")?;

        let stream_buffer = Arc::new(Mutex::new(Vec::new()));
        let stream_buffer_clone = stream_buffer.clone();
        let oob_handle = tokio::spawn(async move {
            loop {
                match oob_sink.recv().await {
                    Some(record) => match record {
                        OutOfBandRecord::AsyncRecord { results, .. } => {
                            debug!("AsyncRecord: {:?}", results);
                        }
                        OutOfBandRecord::StreamRecord { kind, data } => {
                            if matches!(
                                kind,
                                StreamKind::Console | StreamKind::Log | StreamKind::Target
                            ) {
                                stream_buffer_clone.lock().await.push(data.clone());
                            }
                            debug!("StreamRecord: {:?}", data);
                        }
                    },
                    None => {
                        debug!("OOB source channel closed");
                        break;
                    }
                }
            }
        });

        // Capture GDB's own stderr.
        let stderr_handle = {
            let mut process = gdb.process.lock().await;
            let stderr = process.stderr.take();
            drop(process);
            stderr.map(|stderr| {
                let buf_clone = stream_buffer.clone();
                tokio::spawn(async move {
                    let mut reader = TokioBufReader::new(stderr);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                buf_clone.lock().await.push(line.clone());
                            }
                        }
                    }
                })
            })
        };

        // Build the session.
        let session = GDBSession {
            id: session_id.clone(),
            status: GDBSessionStatus::Created,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            backend: DebugBackendKind::QemuUser,
            launch_mode: LaunchMode::ExecContinue,
            qemu_port: Some(port),
        };

        let handle = GDBSessionHandle {
            info: session,
            gdb,
            oob_handle,
            stderr_handle,
            stream_buffer,
            pty_pair: None,
            pty_read_handle: None,
            pty_writer: None,
            inferior_output: None,
            qemu: Some(qemu_process),
            qemu_monitor: None, // filled in below after insert
            #[cfg(feature = "libc-fetch")]
            _libc_work_dir: _libc_work_dir_holder,
        };

        self.sessions.lock().await.insert(session_id.clone(), handle);

        // Flush GDB welcome messages.
        let _ = self.send_command(&session_id, &MiCommand::empty()).await?;

        // Connect GDB to the QEMU stub with retries.
        let target_cmd =
            MiCommand::cli_exec(&format!("target remote localhost:{}", port));
        let mut connect_err: Option<crate::error::AppError> = None;
        for attempt in 0..5u32 {
            // Check for premature QEMU exit before each attempt.
            // Collect owned data so we can drop the sessions lock before returning.
            let early_exit: Option<(std::process::ExitStatus, Option<String>)> = {
                let sessions = self.sessions.lock().await;
                if let Some(h) = sessions.get(&session_id) {
                    if let Some(ref qemu) = h.qemu {
                        let child_status = qemu.child.lock().await.try_wait().ok().flatten();
                        if let Some(status) = child_status {
                            let last_line = qemu.stderr_lines.lock().await.last().cloned();
                            Some((status, last_line))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }; // sessions lock released here
            if let Some((status, last_line)) = early_exit {
                let _ = self.close_session(&session_id).await;
                return Err(AppError::backend(
                    "qemu.create_user_session",
                    format!(
                        "QEMU exited (status {:?}) before GDB could connect; last stderr: {:?}",
                        status, last_line
                    ),
                ));
            }

            match self.send_command(&session_id, &target_cmd).await {
                Ok(_) => {
                    connect_err = None;
                    break;
                }
                Err(e) if attempt < 4 => {
                    connect_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => {
                    connect_err = Some(e);
                }
            }
        }

        if let Some(err) = connect_err {
            let _ = self.close_session(&session_id).await;
            return Err(err.with_context(
                "qemu.create_user_session",
                "target remote failed after 5 attempts",
            ));
        }

        // Start the QEMU monitor task.
        let monitor = {
            let sessions = self.sessions.lock().await;
            sessions.get(&session_id).map(|h| {
                h.qemu.as_ref().map(|q| {
                    spawn_qemu_monitor(q.child.clone(), q.stderr_lines.clone(), session_id.clone())
                })
            })
        };
        if let Some(Some(monitor_handle)) = monitor {
            let mut sessions = self.sessions.lock().await;
            if let Some(h) = sessions.get_mut(&session_id) {
                h.qemu_monitor = Some(monitor_handle);
            }
        }

        Ok(session_id)
    }

    // ─── QEMU System-mode session ─────────────────────────────────────────────

    /// Create a GDB session attached to a QEMU system-mode VM.
    ///
    /// The caller must include `-S -gdb tcp::<gdb_port>` in `qemu_args`.
    #[cfg(feature = "qemu-system")]
    pub async fn create_qemu_system_session(
        &self,
        qemu_path: PathBuf,
        qemu_args: Vec<std::ffi::OsString>,
        gdb_port: u16,
        gdb_path: Option<PathBuf>,
        gef_script: Option<PathBuf>,
        gef_rc: Option<PathBuf>,
        symbol_file: Option<PathBuf>,
    ) -> AppResult<String> {
        use crate::qemu::{QemuProcess, spawn_qemu_monitor, spawn_qemu_system, wait_for_tcp_ready};

        let session_id = Uuid::new_v4().to_string();

        // ── Spawn QEMU system VM ──────────────────────────────────────────────
        let mut raw_child = spawn_qemu_system(&qemu_path, &qemu_args).await?;

        // Drain QEMU stderr.
        let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));
        if let Some(stderr) = raw_child.stderr.take() {
            let lines_clone = stderr_lines.clone();
            tokio::spawn(async move {
                let mut reader = TokioBufReader::new(stderr);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let mut buf = lines_clone.lock().await;
                            if buf.len() >= 50 {
                                buf.remove(0);
                            }
                            buf.push(line.trim_end().to_string());
                        }
                    }
                }
            });
        }

        // System mode can take longer to start; allow 10 s.
        wait_for_tcp_ready(&mut raw_child, gdb_port, Duration::from_secs(10)).await?;

        let child_arc = Arc::new(Mutex::new(raw_child));
        let qemu_process = QemuProcess {
            child: child_arc.clone(),
            port: gdb_port,
            stderr_lines: stderr_lines.clone(),
        };

        // ── Spawn GDB ─────────────────────────────────────────────────────────
        let mut gef_script = gef_script;
        let gef_rc = gef_rc.or_else(|| self.config.gef_rc.clone());
        if gef_script.is_none() {
            let default_gef = PathBuf::from("vendor/gef/gef.py");
            if default_gef.exists() {
                gef_script = Some(default_gef);
            }
        }

        let gdb_builder = GDBBuilder {
            gdb_path: gdb_path.unwrap_or_else(|| PathBuf::from("gdb")),
            opt_nh: false,
            opt_nx: true,
            opt_quiet: true,
            opt_cd: None,
            opt_bps: None,
            opt_symbol_file: symbol_file,
            opt_core_file: None,
            opt_proc_id: None,
            opt_command: None,
            opt_source_dir: None,
            opt_args: vec![],
            opt_program: None,
            opt_tty: None,
            opt_gef_script: gef_script,
            opt_gef_rc: gef_rc,
            opt_create_pty: false,
        };

        let (oob_src, mut oob_sink) = mpsc::channel(100);
        let gdb = gdb_builder
            .try_spawn(oob_src)
            .context("qemu.create_system_session", "spawn GDB process")?;

        let stream_buffer = Arc::new(Mutex::new(Vec::new()));
        let stream_buffer_clone = stream_buffer.clone();
        let oob_handle = tokio::spawn(async move {
            loop {
                match oob_sink.recv().await {
                    Some(record) => match record {
                        OutOfBandRecord::AsyncRecord { results, .. } => {
                            debug!("AsyncRecord: {:?}", results);
                        }
                        OutOfBandRecord::StreamRecord { kind, data } => {
                            if matches!(
                                kind,
                                StreamKind::Console | StreamKind::Log | StreamKind::Target
                            ) {
                                stream_buffer_clone.lock().await.push(data.clone());
                            }
                        }
                    },
                    None => break,
                }
            }
        });

        let stderr_handle = {
            let mut process = gdb.process.lock().await;
            let stderr = process.stderr.take();
            drop(process);
            stderr.map(|stderr| {
                let buf_clone = stream_buffer.clone();
                tokio::spawn(async move {
                    let mut reader = TokioBufReader::new(stderr);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => buf_clone.lock().await.push(line.clone()),
                        }
                    }
                })
            })
        };

        let session = GDBSession {
            id: session_id.clone(),
            status: GDBSessionStatus::Created,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            backend: DebugBackendKind::QemuSystem,
            launch_mode: LaunchMode::ExecContinue,
            qemu_port: Some(gdb_port),
        };

        let handle = GDBSessionHandle {
            info: session,
            gdb,
            oob_handle,
            stderr_handle,
            stream_buffer,
            pty_pair: None,
            pty_read_handle: None,
            pty_writer: None,
            inferior_output: None,
            qemu: Some(qemu_process),
            qemu_monitor: None,
            #[cfg(feature = "libc-fetch")]
            _libc_work_dir: None,
        };

        self.sessions.lock().await.insert(session_id.clone(), handle);

        // Flush GDB welcome.
        let _ = self.send_command(&session_id, &MiCommand::empty()).await?;

        // Connect to QEMU stub with retries.
        let target_cmd =
            MiCommand::cli_exec(&format!("target remote localhost:{}", gdb_port));
        let mut connect_err: Option<crate::error::AppError> = None;
        for attempt in 0..5u32 {
            match self.send_command(&session_id, &target_cmd).await {
                Ok(_) => {
                    connect_err = None;
                    break;
                }
                Err(e) if attempt < 4 => {
                    connect_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => {
                    connect_err = Some(e);
                }
            }
        }

        if let Some(err) = connect_err {
            let _ = self.close_session(&session_id).await;
            return Err(err.with_context(
                "qemu.create_system_session",
                "target remote failed after 5 attempts",
            ));
        }

        // Start monitor task.
        let monitor = {
            let sessions = self.sessions.lock().await;
            sessions.get(&session_id).map(|h| {
                h.qemu.as_ref().map(|q| {
                    spawn_qemu_monitor(q.child.clone(), q.stderr_lines.clone(), session_id.clone())
                })
            })
        };
        if let Some(Some(monitor_handle)) = monitor {
            let mut sessions = self.sessions.lock().await;
            if let Some(h) = sessions.get_mut(&session_id) {
                h.qemu_monitor = Some(monitor_handle);
            }
        }

        Ok(session_id)
    }

    /// Send GDB command
    pub async fn send_command(
        &self,
        session_id: &str,
        command: &MiCommand,
    ) -> AppResult<ResultRecord> {
        let mut sessions = self.sessions.lock().await;
        let handle = sessions.get_mut(session_id).ok_or_else(|| {
            AppError::not_found(
                "gdb.send_command",
                format!("Session {} does not exist", session_id),
            )
        })?;

        let record = handle.gdb.execute(command).await?;
        let output = record.results.to_string();

        debug!("GDB output: {}", output);
        Ok(record)
    }

    /// Send GDB command with timeout
    async fn send_command_with_timeout(
        &self,
        session_id: &str,
        command: &MiCommand,
    ) -> AppResult<ResultRecord> {
        let command_timeout = self.config.command_timeout;
        match tokio::time::timeout(
            Duration::from_secs(command_timeout),
            self.send_command(session_id, command),
        )
        .await
        {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(AppError::timeout("gdb.send_command", "GDB command timeout")),
        }
    }

    async fn ensure_stopped(&self, session_id: &str, timeout: Duration) -> AppResult<()> {
        let is_running = {
            let sessions = self.sessions.lock().await;
            let handle = sessions.get(session_id).ok_or_else(|| {
                AppError::not_found(
                    "gdb.ensure_stopped",
                    format!("Session {} does not exist", session_id),
                )
            })?;
            handle.gdb.is_running()
        };

        if !is_running {
            return Ok(());
        }

        {
            let sessions = self.sessions.lock().await;
            let handle = sessions.get(session_id).ok_or_else(|| {
                AppError::not_found(
                    "gdb.ensure_stopped",
                    format!("Session {} does not exist", session_id),
                )
            })?;
            handle.gdb.interrupt_execution().await.map_err(|e| {
                AppError::backend("gdb.ensure_stopped", format!("interrupt failed: {}", e))
            })?;
        }

        let start = Instant::now();
        loop {
            let is_running = {
                let sessions = self.sessions.lock().await;
                let handle = sessions.get(session_id).ok_or_else(|| {
                    AppError::not_found(
                        "gdb.ensure_stopped",
                        format!("Session {} does not exist", session_id),
                    )
                })?;
                handle.gdb.is_running()
            };
            if !is_running {
                let mut sessions = self.sessions.lock().await;
                if let Some(handle) = sessions.get_mut(session_id) {
                    handle.info.status = GDBSessionStatus::Stopped;
                }
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(AppError::timeout(
                    "gdb.ensure_stopped",
                    "Timeout waiting for GDB to stop",
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Start debugging
    pub async fn start_debugging(&self, session_id: &str) -> AppResult<String> {
        // Determine the correct MI command based on how the session was created.
        let launch_mode = {
            let sessions = self.sessions.lock().await;
            let handle = sessions.get(session_id).ok_or_else(|| {
                AppError::not_found(
                    "gdb.start_debugging",
                    format!("Session {} does not exist", session_id),
                )
            })?;
            handle.info.launch_mode.clone()
        };

        let cmd = match launch_mode {
            // Native sessions start the inferior from scratch.
            LaunchMode::ExecRun => MiCommand::exec_run(),
            // QEMU/remote sessions: the inferior is already at the entry breakpoint.
            LaunchMode::ExecContinue => MiCommand::exec_continue(),
        };

        let response = self.send_command_with_timeout(session_id, &cmd).await?;

        // Update session status
        let mut sessions = self.sessions.lock().await;
        if let Some(handle) = sessions.get_mut(session_id) {
            handle.info.status = GDBSessionStatus::Running;
        }

        Ok(response.results.to_string())
    }

    /// Stop debugging
    pub async fn stop_debugging(&self, session_id: &str) -> AppResult<String> {
        let timeout = Duration::from_secs(self.config.command_timeout);
        self.ensure_stopped(session_id, timeout).await?;
        Ok("stopped".to_string())
    }

    /// Get breakpoint list
    pub async fn get_breakpoints(&self, session_id: &str) -> AppResult<Vec<BreakPoint>> {
        let timeout = Duration::from_secs(self.config.command_timeout);
        self.ensure_stopped(session_id, timeout).await?;
        let response =
            self.send_command_with_timeout(session_id, &MiCommand::breakpoints_list()).await?;

        let table = response.results.get("BreakpointTable").ok_or_else(|| {
            AppError::not_found("gdb.get_breakpoints", "BreakpointTable not found")
        })?;
        let body = table
            .get("body")
            .ok_or_else(|| AppError::not_found("gdb.get_breakpoints", "body not found"))?;
        let body = normalize_mi_list(body.to_owned(), "bkpt");
        Ok(serde_json::from_value(body)
            .context("gdb.get_breakpoints", "parse breakpoint table")?)
    }

    /// Set breakpoint
    pub async fn set_breakpoint(
        &self,
        session_id: &str,
        file: &Path,
        line: usize,
    ) -> AppResult<BreakPoint> {
        let command = MiCommand::insert_breakpoint(BreakPointLocation::Line(file, line));
        let response = self.send_command_with_timeout(session_id, &command).await?;

        Ok(serde_json::from_value(
            response
                .results
                .get("bkpt")
                .ok_or_else(|| {
                    AppError::not_found("gdb.set_breakpoint", "bkpt not found in the result")
                })?
                .to_owned(),
        )
        .context("gdb.set_breakpoint", "parse breakpoint result")?)
    }

    /// Delete breakpoint
    pub async fn delete_breakpoint(
        &self,
        session_id: &str,
        breakpoints: Vec<String>,
    ) -> AppResult<()> {
        let command = MiCommand::delete_breakpoints(
            breakpoints
                .iter()
                .map(|num| serde_json::from_str::<BreakPointNumber>(num))
                .collect::<Result<Vec<_>, _>>()
                .context("gdb.delete_breakpoint", "parse breakpoint numbers")?,
        );
        let response = self.send_command_with_timeout(session_id, &command).await?;
        if response.class != ResultClass::Done {
            return Err(AppError::backend(
                "gdb.delete_breakpoint",
                response.results.to_string(),
            ));
        }

        Ok(())
    }

    /// Get stack frames
    pub async fn get_stack_frames(&self, session_id: &str) -> AppResult<Vec<StackFrame>> {
        let timeout = Duration::from_secs(self.config.command_timeout);
        self.ensure_stopped(session_id, timeout).await?;
        let command = MiCommand::stack_list_frames(None, None);
        let response = self.send_command_with_timeout(session_id, &command).await?;

        let Some(stack) = response.results.get("stack") else {
            return Ok(Vec::new());
        };
        let stack = normalize_mi_list(stack.to_owned(), "frame");
        Ok(serde_json::from_value(stack)
            .context("gdb.get_stack_frames", "parse stack frames")?)
    }

    /// Get local variables
    pub async fn get_local_variables(
        &self,
        session_id: &str,
        frame_id: Option<usize>,
    ) -> AppResult<Vec<Variable>> {
        let command = MiCommand::stack_list_variables(None, frame_id, None);
        let response = self.send_command_with_timeout(session_id, &command).await?;

        Ok(serde_json::from_value(
            response
                .results
                .get("variables")
                .ok_or_else(|| {
                    AppError::not_found("gdb.get_local_variables", "expect variables in result")
                })?
                .to_owned(),
        )
        .context("gdb.get_local_variables", "parse variables")?)
    }

    /// Get registers
    pub async fn get_registers(
        &self,
        session_id: &str,
        reg_list: Option<Vec<String>>,
    ) -> AppResult<Vec<Register>> {
        let timeout = Duration::from_secs(self.config.command_timeout);
        self.ensure_stopped(session_id, timeout).await?;
        let reg_list = reg_list
            .map(|s| s.iter().map(|num| num.parse::<usize>()).collect::<Result<Vec<_>, _>>())
            .transpose()
            .context("gdb.get_registers", "parse register list")?;
        let command = MiCommand::data_list_register_names(reg_list.clone());
        let response = self.send_command_with_timeout(session_id, &command).await?;
        let names: Vec<String> = serde_json::from_value(
            response
                .results
                .get("register-names")
                .ok_or_else(|| {
                    AppError::not_found("gdb.get_registers", "register-names not found")
                })?
                .to_owned(),
        )
        .context("gdb.get_registers", "parse register names")?;

        let command = MiCommand::data_list_register_values(RegisterFormat::Hex, reg_list);
        let response = self.send_command_with_timeout(session_id, &command).await?;

        let registers: Vec<Register> = serde_json::from_value(
            response
                .results
                .get("register-values")
                .ok_or_else(|| {
                    AppError::not_found("gdb.get_registers", "expect register-values")
                })?
                .to_owned(),
        )
        .context("gdb.get_registers", "parse register values")?;
        Ok(registers
            .into_iter()
            .map(|mut r| {
                r.name = names.get(r.number).cloned();
                r
            })
            .collect::<_>())
    }

    /// Evaluate expression via MI
    pub async fn evaluate_expression(&self, session_id: &str, expr: &str) -> AppResult<String> {
        let timeout = Duration::from_secs(self.config.command_timeout);
        self.ensure_stopped(session_id, timeout).await?;
        let command = MiCommand::data_evaluate_expression(expr.to_string());
        let response = self.send_command_with_timeout(session_id, &command).await?;
        if let Some(value) = response.results.get("value").and_then(|v| v.as_str()) {
            return Ok(value.to_string());
        }
        Ok(response.results.to_string())
    }

    /// Get register names
    pub async fn get_register_names(
        &self,
        session_id: &str,
        reg_list: Option<Vec<String>>,
    ) -> AppResult<Vec<Register>> {
        let timeout = Duration::from_secs(self.config.command_timeout);
        self.ensure_stopped(session_id, timeout).await?;
        let reg_list = reg_list
            .map(|s| s.iter().map(|num| num.parse::<usize>()).collect::<Result<Vec<_>, _>>())
            .transpose()
            .context("gdb.get_register_names", "parse register list")?;
        let command = MiCommand::data_list_register_names(reg_list);
        let response = self.send_command_with_timeout(session_id, &command).await?;

        Ok(serde_json::from_value(
            response
                .results
                .get("register-values")
                .ok_or_else(|| {
                    AppError::not_found("gdb.get_register_names", "expect register-values")
                })?
                .to_owned(),
        )
        .context("gdb.get_register_names", "parse register names")?)
    }

    /// Read memory contents
    pub async fn read_memory(
        &self,
        session_id: &str,
        offset: Option<isize>,
        address: String,
        count: usize,
    ) -> AppResult<Vec<Memory>> {
        let command = MiCommand::data_read_memory_bytes(offset, address, count);
        let response = self.send_command_with_timeout(session_id, &command).await?;

        Ok(serde_json::from_value(
            response
                .results
                .get("memory")
                .ok_or_else(|| AppError::not_found("gdb.read_memory", "expect memory"))?
                .to_owned(),
        )
        .context("gdb.read_memory", "parse memory result")?)
    }

    /// Continue execution
    pub async fn continue_execution(&self, session_id: &str) -> AppResult<String> {
        let response =
            self.send_command_with_timeout(session_id, &MiCommand::exec_continue()).await?;

        // Update session status
        let mut sessions = self.sessions.lock().await;
        if let Some(handle) = sessions.get_mut(session_id) {
            handle.info.status = GDBSessionStatus::Running;
        }

        Ok(response.results.to_string())
    }

    /// Step execution
    pub async fn step_execution(&self, session_id: &str) -> AppResult<String> {
        let response = self.send_command_with_timeout(session_id, &MiCommand::exec_step()).await?;

        Ok(response.results.to_string())
    }

    /// Next execution
    pub async fn next_execution(&self, session_id: &str) -> AppResult<String> {
        let response = self.send_command_with_timeout(session_id, &MiCommand::exec_next()).await?;

        Ok(response.results.to_string())
    }

    /// Execute a CLI command via GDB/GEF and return console output.
    pub async fn execute_cli(&self, session_id: &str, command: &str) -> AppResult<String> {
        self.execute_cli_with_timeout(session_id, command, None).await
    }

    /// Execute a CLI command via GDB/GEF with an optional timeout override.
    pub async fn execute_cli_with_timeout(
        &self,
        session_id: &str,
        command: &str,
        timeout: Option<Duration>,
    ) -> AppResult<String> {
        let timeout = timeout.unwrap_or_else(|| Duration::from_secs(self.config.command_timeout));
        self.ensure_stopped(session_id, timeout).await?;

        let commands: Vec<&str> = command
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();

        let mut output = String::new();
        for cmd in commands {
            output.push_str(&self.execute_cli_single(session_id, cmd, timeout).await?);
        }
        Ok(output)
    }

    async fn execute_cli_single(
        &self,
        session_id: &str,
        command: &str,
        timeout: Duration,
    ) -> AppResult<String> {
        {
            let mut sessions = self.sessions.lock().await;
            let handle = sessions.get_mut(session_id).ok_or_else(|| {
                AppError::not_found(
                    "gdb.execute_cli",
                    format!("Session {} does not exist", session_id),
                )
            })?;
            handle.stream_buffer.lock().await.clear();
        }

        let mi_command = MiCommand::cli_exec(command);
        let mut attempt = 0;
        loop {
            match self.send_command_with_timeout(session_id, &mi_command).await {
                Ok(_) => break,
                Err(err)
                    if attempt == 0
                        && matches!(err.kind, ErrorKind::Busy | ErrorKind::Timeout) =>
                {
                    self.ensure_stopped(session_id, timeout).await?;
                    attempt += 1;
                    continue;
                }
                Err(err) => return Err(err),
            }
        }

        let output_wait = std::cmp::min(timeout, Duration::from_secs(1));
        let start = Instant::now();
        loop {
            let has_output = {
                let sessions = self.sessions.lock().await;
                let handle = sessions.get(session_id).ok_or_else(|| {
                    AppError::not_found(
                        "gdb.execute_cli",
                        format!("Session {} does not exist", session_id),
                    )
                })?;
                let buffer = handle.stream_buffer.lock().await;
                !buffer.is_empty()
            };
            if has_output || start.elapsed() >= output_wait {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let mut sessions = self.sessions.lock().await;
        let handle = sessions.get_mut(session_id).ok_or_else(|| {
            AppError::not_found(
                "gdb.execute_cli",
                format!("Session {} does not exist", session_id),
            )
        })?;
        let mut buffer = handle.stream_buffer.lock().await;
        let output = buffer.join("");
        buffer.clear();
        Ok(output)
    }

    /// Read buffered inferior output from the PTY master.
    pub async fn get_inferior_output(&self, session_id: &str) -> AppResult<String> {
        let mut sessions = self.sessions.lock().await;
        let handle = sessions
            .get_mut(session_id)
            .ok_or_else(|| {
                AppError::not_found(
                    "gdb.get_inferior_output",
                    format!("Session {} does not exist", session_id),
                )
            })?;
        // QEMU sessions do not use PTY for inferior I/O.
        #[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
        if handle.qemu.is_some() {
            return Err(AppError::invalid_argument(
                "gdb.get_inferior_output",
                "QEMU sessions do not support PTY-based inferior I/O",
            ));
        }
        let output = handle.inferior_output.as_ref().ok_or_else(|| {
            AppError::invalid_argument("gdb.get_inferior_output", "PTY is not enabled for this session")
        })?;
        let mut buffer = output.lock().await;
        if buffer.is_empty() {
            return Ok(String::new());
        }
        let data = std::mem::take(&mut *buffer);
        Ok(String::from_utf8_lossy(&data).to_string())
    }

    /// Send input to the inferior process via PTY.
    pub async fn send_inferior_input(&self, session_id: &str, input: &str) -> AppResult<()> {
        let mut sessions = self.sessions.lock().await;
        let handle = sessions
            .get_mut(session_id)
            .ok_or_else(|| {
                AppError::not_found(
                    "gdb.send_inferior_input",
                    format!("Session {} does not exist", session_id),
                )
            })?;
        // QEMU sessions do not use PTY for inferior I/O.
        #[cfg(any(feature = "qemu-user", feature = "qemu-system"))]
        if handle.qemu.is_some() {
            return Err(AppError::invalid_argument(
                "gdb.send_inferior_input",
                "QEMU sessions do not support PTY-based inferior I/O",
            ));
        }
        let writer = handle.pty_writer.as_mut().ok_or_else(|| {
            AppError::invalid_argument("gdb.send_inferior_input", "PTY is not enabled for this session")
        })?;
        writer
            .write_all(input.as_bytes())
            .context("gdb.send_inferior_input", "write PTY input")?;
        writer.flush().context("gdb.send_inferior_input", "flush PTY input")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_creation() {
        let pty_system = native_pty_system();
        let pair = match pty_system.openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        }) {
            Ok(pair) => pair,
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("Permission denied") {
                    eprintln!("Skipping PTY test: {}", msg);
                    return;
                }
                panic!("openpty failed: {}", err);
            }
        };
        assert!(pair.master.try_clone_reader().is_ok());
    }
}
