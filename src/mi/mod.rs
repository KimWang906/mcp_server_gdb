pub mod commands;
pub mod output;

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::Result;
use output::process_output;
use tokio::io::BufReader;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, Sender};
use tracing::debug;

use crate::error::{AppError, AppResult, ResultContextExt};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
#[allow(dead_code)]
pub struct GDB {
    pub process: Arc<Mutex<Child>>,
    is_running: Arc<AtomicBool>,
    result_output: mpsc::Receiver<output::ResultRecord>,
    pending_results: VecDeque<output::ResultRecord>,
    pending_result_stash_count: u64,
    pending_result_drop_count: u64,
    current_command_token: AtomicU64,
    binary_path: PathBuf,
    init_options: Vec<OsString>,
}

#[derive(Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub enum ExecuteError {
    Busy,
    Quit,
}

/// A builder struct for configuring and launching GDB with various command line
/// options. This struct provides a fluent interface for setting up GDB with
/// different parameters before spawning the debugger process.
pub struct GDBBuilder {
    /// Path to the GDB executable
    pub gdb_path: PathBuf,
    /// Do not read ~/.gdbinit file (--nh)
    pub opt_nh: bool,
    /// Do not read any .gdbinit files in any directory (--nx)
    pub opt_nx: bool,
    /// Do not print version number on startup (--quiet)
    pub opt_quiet: bool,
    /// Change current directory to DIR (--cd=DIR)
    pub opt_cd: Option<PathBuf>,
    /// Set serial port baud rate used for remote debugging (-b BAUDRATE)
    pub opt_bps: Option<u32>,
    /// Read symbols from SYMFILE (--symbols=SYMFILE)
    pub opt_symbol_file: Option<PathBuf>,
    /// Analyze the core dump COREFILE (--core=COREFILE)
    pub opt_core_file: Option<PathBuf>,
    /// Attach to running process PID (--pid=PID)
    pub opt_proc_id: Option<u32>,
    /// Execute GDB commands from FILE (--command=FILE)
    pub opt_command: Option<PathBuf>,
    /// Search for source files in DIR (--directory=DIR)
    pub opt_source_dir: Option<PathBuf>,
    /// Arguments to be passed to the inferior program (--args)
    pub opt_args: Vec<OsString>,
    /// The executable file to debug
    pub opt_program: Option<PathBuf>,
    /// Use TTY for input/output by the program being debugged (--tty=TTY)
    pub opt_tty: Option<PathBuf>,
    /// Load GEF script via -x option (e.g. vendor/gef/gef.py)
    pub opt_gef_script: Option<PathBuf>,
    /// Load GEF rc file via GEF_RC environment variable
    pub opt_gef_rc: Option<PathBuf>,
    /// Automatically create a PTY for inferior I/O separation
    pub opt_create_pty: bool,
}

impl GDBBuilder {
    #[allow(dead_code)]
    pub fn new(gdb: PathBuf) -> Self {
        GDBBuilder {
            gdb_path: gdb,
            opt_nh: false,
            opt_nx: false,
            opt_quiet: false,
            opt_cd: None,
            opt_bps: None,
            opt_symbol_file: None,
            opt_core_file: None,
            opt_proc_id: None,
            opt_command: None,
            opt_source_dir: None,
            opt_args: Vec::new(),
            opt_program: None,
            opt_tty: None,
            opt_gef_script: None,
            opt_gef_rc: None,
            opt_create_pty: false,
        }
    }

    pub fn try_spawn(self, oob_sink: Sender<output::OutOfBandRecord>) -> AppResult<GDB> {
        let mut gdb_args = Vec::<OsString>::new();
        let mut init_options = Vec::<OsString>::new();
        if self.opt_nh {
            gdb_args.push("--nh".into());
            init_options.push("--nh".into());
        }
        if self.opt_nx {
            gdb_args.push("--nx".into());
            init_options.push("--nx".into());
        }
        if self.opt_quiet {
            gdb_args.push("--quiet".into());
        }
        if let Some(cd) = self.opt_cd {
            gdb_args.push("--cd=".into());
            gdb_args.last_mut().unwrap().push(&cd);
        }
        if let Some(bps) = self.opt_bps {
            gdb_args.push("-b".into());
            gdb_args.push(bps.to_string().into());
        }
        if let Some(symbol_file) = self.opt_symbol_file {
            gdb_args.push("--symbols=".into());
            gdb_args.last_mut().unwrap().push(&symbol_file);
        }
        if let Some(core_file) = self.opt_core_file {
            gdb_args.push("--core=".into());
            gdb_args.last_mut().unwrap().push(&core_file);
        }
        if let Some(proc_id) = self.opt_proc_id {
            gdb_args.push("--pid=".into());
            gdb_args.last_mut().unwrap().push(proc_id.to_string());
        }
        if let Some(command) = self.opt_command {
            gdb_args.push("--command=".into());
            gdb_args.last_mut().unwrap().push(&command);
        }
        if let Some(source_dir) = self.opt_source_dir {
            gdb_args.push("--directory=".into());
            gdb_args.last_mut().unwrap().push(&source_dir);
        }
        if let Some(tty) = self.opt_tty {
            gdb_args.push("--tty=".into());
            gdb_args.last_mut().unwrap().push(&tty);
        } else if self.opt_create_pty {
            return Err(AppError::invalid_argument(
                "mi.spawn",
                "PTY creation requested but no TTY path was configured",
            ));
        }
        if let Some(gef_script) = self.opt_gef_script {
            gdb_args.push("-x".into());
            gdb_args.push(gef_script.into_os_string());
        }
        if !self.opt_args.is_empty() {
            gdb_args.push("--args".into());
            gdb_args.push(
                self.opt_program
                    .ok_or_else(|| {
                        AppError::invalid_argument(
                            "mi.spawn",
                            "Program path is required if --args is provided",
                        )
                    })?
                    .into_os_string(),
            );
            for arg in self.opt_args {
                gdb_args.push(arg);
            }
        } else if let Some(program) = self.opt_program {
            gdb_args.push(program.into());
        }

        let mut command = Command::new(self.gdb_path.clone());
        if let Some(gef_rc) = &self.opt_gef_rc {
            command.env("GEF_RC", gef_rc);
        }
        command.arg("--interpreter=mi").args(gdb_args);

        debug!("Starting GDB process with command: {:?}", command);

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                AppError::backend("mi.spawn", format!("Failed to start GDB process: {}", e))
            })?;

        let stdout = BufReader::new(child.stdout.take().unwrap());
        let is_running = Arc::new(AtomicBool::new(false));
        let is_running_clone = is_running.clone();
        let (result_input, result_output) = mpsc::channel(100);
        tokio::spawn(process_output(stdout, result_input, oob_sink, is_running_clone));

        let gdb = GDB {
            process: Arc::new(Mutex::new(child)),
            is_running,
            current_command_token: AtomicU64::new(0),
            binary_path: self.gdb_path,
            init_options,
            result_output,
            pending_results: VecDeque::new(),
            pending_result_stash_count: 0,
            pending_result_drop_count: 0,
        };
        Ok(gdb)
    }
}

impl GDB {
    #[cfg(unix)]
    #[allow(dead_code)]
    pub async fn interrupt_execution(&self) -> Result<(), nix::Error> {
        use nix::sys::signal;
        use nix::unistd::Pid;
        signal::kill(Pid::from_raw(self.process.lock().await.id().unwrap() as i32), signal::SIGINT)
    }

    #[cfg(windows)]
    #[allow(dead_code)]
    pub async fn interrupt_execution(&self) -> Result<()> {
        Ok(())
    }

    #[allow(dead_code)]
    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    #[allow(dead_code)]
    pub fn init_options(&self) -> &[OsString] {
        &self.init_options
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    pub fn new_token(&mut self) -> u64 {
        self.current_command_token.fetch_add(1, Ordering::SeqCst)
    }

    pub async fn execute<C: std::borrow::Borrow<commands::MiCommand>>(
        &mut self,
        command: C,
    ) -> AppResult<output::ResultRecord> {
        if self.is_running() {
            return Err(AppError::busy("mi.execute", "GDB is busy"));
        }

        let command_token = self.new_token();
        let expects_token = !command.borrow().operation.is_empty();

        if let Some(record) = self
            .pending_results
            .iter()
            .position(|record| record.token == Some(command_token))
            .and_then(|pos| self.pending_results.remove(pos))
        {
            return Ok(record);
        }

        command
            .borrow()
            .write_interpreter_string(
                &mut self
                    .process
                    .lock()
                    .await
                    .stdin
                    .as_mut()
                    .ok_or_else(|| AppError::backend("mi.execute", "Failed to get stdin"))?,
                command_token,
            )
            .await
            .context("mi.execute", "write interpreter command")?;

        loop {
            match self.result_output.recv().await {
                Some(record) => match record.token {
                    Some(token) if token == command_token => {
                        return Ok(record);
                    }
                    Some(token) if token < command_token => {
                        self.pending_result_drop_count += 1;
                        debug!(
                            "mi.execute: dropping stale result token {} (expecting {}), drops={}",
                            token, command_token, self.pending_result_drop_count
                        );
                    }
                    Some(token) => {
                        if self.pending_results.len() >= 32 {
                            let _ = self.pending_results.pop_front();
                        }
                        self.pending_result_stash_count += 1;
                        if self.pending_result_stash_count == 1
                            || self.pending_result_stash_count % 10 == 0
                            || self.pending_results.len() > 8
                        {
                            debug!(
                                "mi.execute: stashing out-of-order result token {} (expecting {}), stash_count={}, pending_len={}",
                                token,
                                command_token,
                                self.pending_result_stash_count,
                                self.pending_results.len()
                            );
                        }
                        self.pending_results.push_back(record);
                    }
                    None if !expects_token => return Ok(record),
                    None => {
                        debug!(
                            "mi.execute: dropping tokenless result (expecting {})",
                            command_token
                        );
                    }
                },
                None => return Err(AppError::backend("mi.execute", "no result, expecting response")),
            }
        }
    }

    #[allow(dead_code)]
    pub async fn execute_later<C: std::borrow::Borrow<commands::MiCommand>>(
        &mut self,
        command: C,
    ) -> AppResult<()> {
        let command_token = self.new_token();
        command
            .borrow()
            .write_interpreter_string(
                &mut self
                    .process
                    .lock()
                    .await
                    .stdin
                    .as_mut()
                    .ok_or_else(|| AppError::backend("mi.execute_later", "Failed to get stdin"))?,
                command_token,
            )
            .await
            .context("mi.execute_later", "write interpreter command")?;
        let _ = self.result_output.recv().await;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn is_session_active(&mut self) -> AppResult<bool> {
        let res = self.execute(commands::MiCommand::thread_info(None)).await?;
        if let Some(threads) = res.results.get("threads") {
            if let Some(threads) = threads.as_array() {
                Ok(!threads.is_empty())
            } else {
                Err(AppError::protocol("mi.is_session_active", "threads is not an array"))
            }
        } else {
            Err(AppError::protocol("mi.is_session_active", "threads is not found"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_create_pty_requires_tty() {
        let mut builder = GDBBuilder::new(PathBuf::from("gdb"));
        builder.opt_create_pty = true;

        let (oob_tx, _oob_rx) = mpsc::channel(1);
        let err = builder.try_spawn(oob_tx).expect_err("expected error");

        assert_eq!(err.kind, crate::error::ErrorKind::InvalidArgument);
    }
}
