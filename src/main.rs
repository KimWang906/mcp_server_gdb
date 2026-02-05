mod ui;

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use axum::Router;
use axum::routing::any_service;
use clap::{Parser, ValueEnum};
use crossterm::event::EventStream;
use futures::StreamExt;
use mcp_server_gdb::GDBManager;
use mcp_server_gdb::config::Config;
use mcp_server_gdb::error::{AppError, AppResult};
use mcp_server_gdb::models::{
    ASM, BT, Memory, MemoryMapping, MemoryType, ResolveSymbol, TrackedRegister,
};
use mcp_server_gdb::tools::{self, GDB_MANAGER};
use ratatui::Terminal;
use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::event::{DisableMouseCapture, Event, KeyCode};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::Backend;
use ratatui::widgets::ScrollbarState;
use rmcp::ServiceExt;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService, stdio};
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, error, info, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use ui::hexdump::HEXDUMP_WIDTH;

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum TransportType {
    Stdio,
    Sse,
}

impl FromStr for TransportType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stdio" => Ok(TransportType::Stdio),
            "sse" => Ok(TransportType::Sse),
            _ => Err(format!("Invalid transport type: {}", s)),
        }
    }
}

#[allow(dead_code)]
fn resolve_home(path: &str) -> Option<PathBuf> {
    if path.starts_with("~/") {
        if let Ok(home) = env::var("HOME") {
            return Some(Path::new(&home).join(&path[2..]));
        }
        None
    } else {
        Some(PathBuf::from(path))
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Transport type to use
    #[arg(
        value_enum,
        default_value_t = TransportType::Stdio,
        required_if_eq("enable_tui", "true"),
        value_parser = clap::builder::ValueParser::new(|s: &str| -> Result<TransportType, String> {
            let t = s.parse::<TransportType>()?;
            if t == TransportType::Stdio && std::env::args().any(|arg| arg == "--enable-tui") {
                Err("When TUI is enabled, transport must be SSE".to_string())
            } else {
                Ok(t)
            }
        }),
        help = "Transport type to use, can only use SSE when TUI is enabled, otherwise key events can be lost"
    )]
    transport: TransportType,

    /// Enable TUI
    #[arg(long)]
    enable_tui: bool,
}

#[derive(Copy, Clone, Default, PartialEq)]
enum Mode {
    #[default]
    All,
    OnlyRegister,
    OnlyStack,
    OnlyInstructions,
    OnlyOutput,
    OnlyMapping,
    OnlyHexdump,
}

impl Mode {
    pub fn next(&self) -> Self {
        match self {
            Mode::All => Mode::OnlyRegister,
            Mode::OnlyRegister => Mode::OnlyStack,
            Mode::OnlyStack => Mode::OnlyInstructions,
            Mode::OnlyInstructions => Mode::OnlyOutput,
            Mode::OnlyOutput => Mode::OnlyMapping,
            Mode::OnlyMapping => Mode::OnlyHexdump,
            Mode::OnlyHexdump => Mode::All,
        }
    }
}

/// An endian
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Endian {
    /// Little endian
    Little,
    /// Big endian
    Big,
}

#[derive(Default)]
pub struct MyScrollState {
    pub scroll: usize,
    pub state: ScrollbarState,
}

#[derive(Default)]
#[allow(dead_code)]
struct App {
    gdb: GDBManager,
    /// -32 bit mode
    bit32: bool,
    /// Current filepath of .text
    filepath: Option<PathBuf>,
    /// Current endian
    endian: Option<Endian>,
    /// Current display mode
    mode: Mode,
    /// Memory map TUI
    memory_map: Option<Vec<MemoryMapping>>,
    memory_map_scroll: MyScrollState,
    /// Current $pc
    current_pc: AtomicU64,
    /// All output from gdb
    output: Vec<String>,
    output_scroll: MyScrollState,
    /// Saved output such as (gdb) or > from gdb
    stream_output_prompt: String,
    /// Register TUI
    register_changed: Vec<u8>,
    registers: Vec<TrackedRegister>,
    register_name_width_cache: usize,
    register_name_width_cache_len: usize,
    /// Saved Stack
    stack: BTreeMap<u64, ResolveSymbol>,
    /// Saved ASM
    asm: Vec<ASM>,
    asm_cache: AsmCache,
    /// Hexdump
    hexdump: Option<(u64, Vec<u8>)>,
    hexdump_scroll: MyScrollState,
    /// Right side of status in TUI
    async_result: String,
    /// Left side of status in TUI
    status: String,
    bt: Vec<BT>,
    /// Exit the app
    _exit: bool,
}

#[derive(Default)]
struct AsmCache {
    pc: u64,
    len: usize,
    pc_index: Option<usize>,
    function_name: Option<String>,
    tallest_function_len: usize,
}

impl App {
    // Parse a "file filepath" command and save
    #[allow(dead_code)]
    fn save_filepath(&mut self, val: &str) {
        let filepath: Vec<&str> = val.split_whitespace().collect();
        let filepath = resolve_home(filepath[1]).expect("Failed to resolve home directory");
        // debug!("filepath: {filepath:?}");
        self.filepath = Some(filepath);
    }

    pub async fn find_first_heap(&self) -> Option<MemoryMapping> {
        self.memory_map.as_ref()?.iter().find(|a| a.is_heap()).cloned()
    }

    pub async fn find_first_stack(&self) -> Option<MemoryMapping> {
        self.memory_map.as_ref()?.iter().find(|a| a.is_stack()).cloned()
    }

    pub fn classify_val(&self, val: u64, filepath: &Path) -> MemoryType {
        if val != 0 {
            // look through, add see if the value is part of the stack
            // trace!("{:02x?}", memory_map);
            if let Some(memory_map) = self.memory_map.as_ref() {
                let mut exec_paths: HashSet<&Path> = HashSet::new();
                for r in memory_map {
                    if r.is_exec() {
                        if let Some(path) = r.path.as_ref() {
                            exec_paths.insert(path.as_path());
                        }
                    }
                }
                for r in memory_map {
                    if r.contains(val) {
                        if r.is_stack() {
                            return MemoryType::Stack;
                        }
                        if r.is_heap() {
                            return MemoryType::Heap;
                        }
                        if r.is_path(filepath)
                            || r.is_exec()
                            || r.path.as_ref().map_or(false, |p| exec_paths.contains(p.as_path()))
                        {
                            return MemoryType::Exec;
                        }
                    }
                }
            }
        }
        MemoryType::Unknown
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenv::dotenv().ok();

    let args = Args::parse();

    let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "mcp-gdb.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Initialize logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("info"))
        }))
        // needs to go to file due to stdio transport
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
        .init();

    // Get configuration
    let config = Config::default();
    debug!("config: {:?}", config);

    info!("Starting MCP GDB Server on port {}", config.server_port);

    let app = Arc::new(Mutex::new(Default::default()));

    // Initialize terminal
    let ui_handle = if args.enable_tui {
        let default_hook = std::panic::take_hook();
        let restored = Arc::new(AtomicBool::new(false));
        let restored_hook = restored.clone();
        std::panic::set_hook(Box::new(move |info| {
            if !restored_hook.swap(true, Ordering::SeqCst) {
                let _ = restore_terminal_stdout();
            }
            default_hook(info);
        }));
        enable_raw_mode()?;
        execute!(std::io::stdout(), EnterAlternateScreen)?;
        match ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout())) {
            Ok(terminal) => {
                let terminal = Arc::new(Mutex::new(terminal));
                let (quit_sender, quit_receiver) = oneshot::channel();
                let app_clone = app.clone();
                let terminal_for_tui = terminal.clone();
                let tui_handle = tokio::spawn(async move {
                    if let Err(e) = run_app(terminal_for_tui, app_clone).await {
                        error!("failed to run app: {}", e);
                    } else {
                        quit_sender.send(()).unwrap();
                    }
                });
                Some((terminal, tui_handle, quit_receiver))
            }
            Err(e) => {
                warn!("Failed to initialize terminal: {}", e);
                None
            }
        }
    } else {
        debug!("TUI disabled by command line argument");
        None
    };

    tools::init_gdb_manager();

    match args.transport {
        TransportType::Stdio => {
            let service = tools::GdbService::new();
            let mut running = service.serve(stdio()).await?;

            if let Some((terminal, tui_handle, quit_receiver)) = ui_handle {
                if let Err(e) = quit_receiver.await {
                    error!("failed to receive quit signal: {}", e);
                }

                tui_handle.abort();

                // Restore terminal if it was initialized
                disable_raw_mode()?;
                let mut terminal = terminal.lock().await;
                execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                terminal.show_cursor()?;
                debug!("TUI closed");

                if let Err(e) = running.close().await {
                    error!("failed to close stdio service: {}", e);
                }
            } else {
                debug!("waiting for stdio service to complete");
                if let Err(e) = running.waiting().await {
                    error!("stdio service task error: {}", e);
                }
                return Ok(());
            }
        }
        TransportType::Sse => {
            let addr = format!("{}:{}", config.server_ip, config.server_port);
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            let session_manager = Arc::new(LocalSessionManager::default());
            let http_service = StreamableHttpService::new(
                || Ok(tools::GdbService::new()),
                session_manager,
                StreamableHttpServerConfig::default(),
            );
            let app = Router::new().route("/mcp", any_service(http_service));

            if let Some((terminal, tui_handle, quit_receiver)) = ui_handle {
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let server_handle = tokio::spawn(async move {
                    let server = axum::serve(listener, app).with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    });
                    if let Err(e) = server.await {
                        error!("streamable HTTP server error: {}", e);
                    }
                });

                if let Err(e) = quit_receiver.await {
                    error!("failed to receive quit signal: {}", e);
                }

                tui_handle.abort();

                // Restore terminal if it was initialized
                disable_raw_mode()?;
                let mut terminal = terminal.lock().await;
                execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                terminal.show_cursor()?;
                debug!("TUI closed");

                let _ = shutdown_tx.send(());
                if let Err(e) = server_handle.await {
                    error!("streamable HTTP server task error: {}", e);
                }
            } else {
                debug!("waiting for streamable HTTP server to complete");
                axum::serve(listener, app).await?;
                return Ok(());
            }
        }
    }

    // Close all GDB sessions
    let sessions = tools::GDB_MANAGER.get_all_sessions().await?;
    for session in sessions {
        if let Err(e) = tools::GDB_MANAGER.close_session(&session.id).await {
            error!("failed to close session {}: {}", session.id, e);
        }
    }
    std::process::exit(0);
}

fn scroll_down(n: usize, scroll: &mut MyScrollState, len: usize) {
    if scroll.scroll < len.saturating_sub(1) {
        scroll.scroll += n;
        scroll.state = scroll.state.position(scroll.scroll);
    }
}

fn scroll_up(n: usize, scroll: &mut MyScrollState) {
    if scroll.scroll > n {
        scroll.scroll -= n;
    } else {
        scroll.scroll = 0;
    }
    scroll.state = scroll.state.position(scroll.scroll);
}

fn restore_terminal_stdout() -> std::io::Result<()> {
    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture, Show)?;
    Ok(())
}

fn parse_hex_u64(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(trimmed, 16).map_err(|_| format!("invalid hex address: {}", value))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_value(bytes[i])?;
        let lo = hex_value(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", byte as char)),
    }
}

fn decode_memory(memory: &[Memory]) -> Result<(u64, Vec<u8>), String> {
    let first = memory.first().ok_or_else(|| "empty memory result".to_string())?;
    let address = parse_hex_u64(&first.begin)?;
    let bytes = hex_to_bytes(&first.contents)?;
    Ok((address, bytes))
}

async fn run_app<B: Backend + Send + 'static>(
    terminal: Arc<Mutex<Terminal<B>>>,
    app: Arc<Mutex<App>>,
) -> AppResult<()> {
    let app_clone1 = app.clone();
    let app_clone2 = app.clone();
    let mut reader = EventStream::new();
    let (tx, mut rx) = mpsc::channel(100);

    let event_loop = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Event::Key(key) = event {
                debug!("key >>> {:?}", key);
                let mut app = app_clone1.lock().await;
                match key.code {
                    KeyCode::Tab => {
                        app.mode = app.mode.next();
                    }
                    KeyCode::F(1) => {
                        app.mode = Mode::All;
                    }
                    KeyCode::F(2) => {
                        app.mode = Mode::OnlyRegister;
                    }
                    KeyCode::F(3) => {
                        app.mode = Mode::OnlyStack;
                    }
                    KeyCode::F(4) => {
                        app.mode = Mode::OnlyInstructions;
                    }
                    KeyCode::F(5) => {
                        app.mode = Mode::OnlyOutput;
                    }
                    KeyCode::F(6) => {
                        app.mode = Mode::OnlyMapping;
                    }
                    KeyCode::F(7) => {
                        app.mode = Mode::OnlyHexdump;
                    }
                    // output
                    KeyCode::Char('g') if app.mode == Mode::OnlyOutput => {
                        app.output_scroll.scroll = 0;
                        app.output_scroll.state = app.output_scroll.state.position(0);
                    }
                    KeyCode::Char('G') if app.mode == Mode::OnlyOutput => {
                        let len = app.output.len();
                        app.output_scroll.scroll = len;
                        app.output_scroll.state.last();
                    }
                    KeyCode::Char('j') if app.mode == Mode::OnlyOutput => {
                        let len = app.output.len();
                        scroll_down(1, &mut app.output_scroll, len);
                    }
                    KeyCode::Char('k') if app.mode == Mode::OnlyOutput => {
                        scroll_up(1, &mut app.output_scroll);
                    }
                    KeyCode::Char('J') if app.mode == Mode::OnlyOutput => {
                        let len = app.output.len();
                        scroll_down(50, &mut app.output_scroll, len);
                    }
                    KeyCode::Char('K') if app.mode == Mode::OnlyOutput => {
                        scroll_up(50, &mut app.output_scroll);
                    }
                    // memory mapping
                    KeyCode::Char('g') if app.mode == Mode::OnlyMapping => {
                        app.memory_map_scroll.scroll = 0;
                        app.memory_map_scroll.state = app.memory_map_scroll.state.position(0);
                    }
                    KeyCode::Char('G') if app.mode == Mode::OnlyMapping => {
                        if let Some(memory) = app.memory_map.as_ref() {
                            let len = memory.len();
                            let memory_map_scroll = &mut app.memory_map_scroll;
                            memory_map_scroll.scroll = len;
                            memory_map_scroll.state.last();
                        }
                    }
                    KeyCode::Char('j') if app.mode == Mode::OnlyMapping => {
                        if let Some(memory) = app.memory_map.as_ref() {
                            let len = memory.len() / HEXDUMP_WIDTH;
                            scroll_down(1, &mut app.memory_map_scroll, len);
                        }
                    }
                    KeyCode::Char('k') if app.mode == Mode::OnlyMapping => {
                        scroll_up(1, &mut app.memory_map_scroll);
                    }
                    KeyCode::Char('J') if app.mode == Mode::OnlyMapping => {
                        if let Some(memory) = app.memory_map.as_ref() {
                            let len = memory.len() / HEXDUMP_WIDTH;
                            scroll_down(50, &mut app.memory_map_scroll, len);
                        }
                    }
                    KeyCode::Char('K') if app.mode == Mode::OnlyMapping => {
                        scroll_up(50, &mut app.memory_map_scroll);
                    }
                    // hexdump
                    KeyCode::Char('g') if app.mode == Mode::OnlyHexdump => {
                        app.hexdump_scroll.scroll = 0;
                        app.hexdump_scroll.state = app.hexdump_scroll.state.position(0);
                    }
                    KeyCode::Char('G') if app.mode == Mode::OnlyHexdump => {
                        if let Some(hexdump) = app.hexdump.as_ref() {
                            let len = hexdump.1.len() / HEXDUMP_WIDTH;
                            let hexdump_scroll = &mut app.hexdump_scroll;
                            hexdump_scroll.scroll = len;
                            hexdump_scroll.state.last();
                        }
                    }
                    KeyCode::Char('H') if app.mode == Mode::OnlyHexdump => {
                        if let Some(find_heap) = app.find_first_heap().await {
                            let memory = GDB_MANAGER
                                .read_memory(
                                    "",
                                    Some(find_heap.start_address as isize),
                                    "0".to_string(),
                                    find_heap.size as usize,
                                )
                                .await?;
                            match decode_memory(&memory) {
                                Ok((address, bytes)) => {
                                    app.hexdump = Some((address, bytes));
                                }
                                Err(err) => {
                                    app.status = format!("hexdump: {}", err);
                                }
                            }

                            // reset position
                            app.hexdump_scroll.scroll = 0;
                            app.hexdump_scroll.state = app.hexdump_scroll.state.position(0);
                        }
                    }
                    KeyCode::Char('T') if app.mode == Mode::OnlyHexdump => {
                        if let Some(find_stack) = app.find_first_stack().await {
                            let memory = GDB_MANAGER
                                .read_memory(
                                    "",
                                    Some(find_stack.start_address as isize),
                                    "0".to_string(),
                                    find_stack.size as usize,
                                )
                                .await?;
                            match decode_memory(&memory) {
                                Ok((address, bytes)) => {
                                    app.hexdump = Some((address, bytes));
                                }
                                Err(err) => {
                                    app.status = format!("hexdump: {}", err);
                                }
                            }

                            // reset position
                            app.hexdump_scroll.scroll = 0;
                            app.hexdump_scroll.state = app.hexdump_scroll.state.position(0);
                        }
                    }
                    KeyCode::Char('j') if app.mode == Mode::OnlyHexdump => {
                        if let Some(hexdump) = app.hexdump.as_ref() {
                            let len = hexdump.1.len() / HEXDUMP_WIDTH;
                            scroll_down(1, &mut app.hexdump_scroll, len);
                        }
                    }
                    KeyCode::Char('k') if app.mode == Mode::OnlyHexdump => {
                        scroll_up(1, &mut app.hexdump_scroll);
                    }
                    KeyCode::Char('J') if app.mode == Mode::OnlyHexdump => {
                        if let Some(hexdump) = app.hexdump.as_ref() {
                            let len = hexdump.1.len() / HEXDUMP_WIDTH;
                            scroll_down(50, &mut app.hexdump_scroll, len);
                        }
                    }
                    KeyCode::Char('K') if app.mode == Mode::OnlyHexdump => {
                        scroll_up(1, &mut app.hexdump_scroll);
                    }
                    _ => {
                        // app.input.handle_event(&Event::Key(key));
                    }
                }
            }
        }
        let mut app = app.lock().await;
        app._exit = true;
        Ok::<(), AppError>(())
    });

    let draw_loop = tokio::task::spawn_blocking(move || {
        loop {
            {
                let mut terminal = terminal.blocking_lock();
                let mut app = app_clone2.blocking_lock();
                if app._exit {
                    break;
                }
                if let Err(e) = terminal.draw(|f| {
                    ui::ui(f, &mut app);
                }) {
                    error!("failed to draw: {}", e);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    // Event collection task
    while let Some(Ok(event)) = reader.next().await {
        debug!("event <<< {:?}", event);
        if let Event::Key(key) = event {
            if key.code == KeyCode::Char('q') {
                drop(tx);
                break;
            }
            if let Err(e) = tx.send(event).await {
                error!("failed to send event: {}", e);
                break;
            }
        }
    }

    // Wait for processor to finish
    if let Err(e) = event_loop.await {
        error!("event processor error: {}", e);
    }

    // Wait for draw task to finish
    if let Err(e) = draw_loop.await {
        error!("failed to wait for draw task to finish: {}", e);
    }

    Ok(())
}
