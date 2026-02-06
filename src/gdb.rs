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
    BreakPoint, GDBSession, GDBSessionStatus, Memory, Register, StackFrame, Variable,
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
        };

        self.sessions.lock().await.insert(session_id.clone(), handle);

        // Send empty command to GDB to flush the welcome messages
        let _ = self.send_command(&session_id, &MiCommand::empty()).await?;

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
            // Terminate process
            let mut process = handle.gdb.process.lock().await;
            let _ = process.kill().await; // Ignore possible errors, process may have already terminated
        }

        Ok(())
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
        let response = self.send_command_with_timeout(session_id, &MiCommand::exec_run()).await?;

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
