use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::router::tool::CallToolHandlerExt;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo, ToolsCapability};
use rmcp::{ErrorData, ServerHandler, tool, tool_handler};
use mcp_server_gdb_macros::tool_router_with_gef;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ResultContextExt;
use crate::gdb::GDBManager;

pub static GDB_MANAGER: LazyLock<Arc<GDBManager>> =
    LazyLock::new(|| Arc::new(GDBManager::default()));

/// Initialize the global GDB manager.
pub fn init_gdb_manager() {
    LazyLock::force(&GDB_MANAGER);
}

/// RMCP service implementation for the GDB MCP server.
#[derive(Clone)]
pub struct GdbService {
    tool_router: ToolRouter<Self>,
}

impl GdbService {
    /// Create a new GDB RMCP service.
    pub fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }
}

impl Default for GdbService {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CreateSessionParams {
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
    args: Option<Vec<String>>,
    tty: Option<PathBuf>,
    gdb_path: Option<PathBuf>,
    gef_script: Option<PathBuf>,
    gef_rc: Option<PathBuf>,
    #[schemars(description = "Automatically create a PTY for inferior I/O separation. Default: true.")]
    create_pty: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SessionIdParams {
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct BreakpointParams {
    session_id: String,
    file: String,
    line: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteBreakpointParams {
    session_id: String,
    breakpoints: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FrameParams {
    session_id: String,
    frame_id: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RegistersParams {
    session_id: String,
    reg_list: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReadMemoryParams {
    session_id: String,
    address: String,
    count: usize,
    offset: Option<isize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ExecuteCliParams {
    session_id: String,
    command: String,
    json: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct InferiorInputParams {
    session_id: String,
    input: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[allow(dead_code)]
struct GefCommandParams {
    session_id: String,
    args: Option<String>,
    json: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GefFunctionParams {
    session_id: String,
    json: Option<bool>,
}

fn json_text<T: Serialize>(value: &T) -> Result<String, ErrorData> {
    serde_json::to_string(value)
        .map_err(|error| ErrorData::internal_error(error.to_string(), None))
}

fn format_gef_json_cli(tool: &str, args: Option<&str>) -> String {
    let args = args.map(str::trim).filter(|value| !value.is_empty());
    match args {
        Some(value) => format!("gef-json {} {}", tool, value),
        None => format!("gef-json {}", tool),
    }
}

fn normalize_gef_json_command(command: &str, json: bool) -> String {
    let command = command.trim();
    if json && !command.starts_with("gef-json") {
        if command.is_empty() {
            "gef-json".to_string()
        } else {
            format!("gef-json {}", command)
        }
    } else {
        command.to_string()
    }
}

macro_rules! gef_command_tool {
    ($fn_name:ident, $tool_name:expr, $command:expr, $description:expr) => {
        #[tool(name = $tool_name, description = $description)]
        async fn $fn_name(
            &self,
            Parameters(params): Parameters<GefCommandParams>,
        ) -> Result<String, ErrorData> {
            let use_json = params.json.unwrap_or(false);
            let command = if use_json {
                format_gef_json_cli($tool_name, params.args.as_deref())
            } else if let Some(args) = params.args.as_ref() {
                format!("{} {}", $command, args)
            } else {
                $command.to_string()
            };
            let output = GDB_MANAGER
                .execute_cli(&params.session_id, &command)
                .await
                .field("session_id", params.session_id.clone())
                .field("command", command.clone())
                .map_err(ErrorData::from)?;
            Ok(output)
        }
    };
}

macro_rules! gef_function_tool {
    ($fn_name:ident, $tool_name:expr, $expression:expr, $description:expr) => {
        #[tool(name = $tool_name, description = $description)]
        async fn $fn_name(
            &self,
            Parameters(params): Parameters<GefFunctionParams>,
        ) -> Result<String, ErrorData> {
            let use_json = params.json.unwrap_or(false);
            let command = if use_json {
                format_gef_json_cli($tool_name, None)
            } else {
                format!("p {}", $expression)
            };
            let output = GDB_MANAGER
                .execute_cli(&params.session_id, &command)
                .await
                .field("session_id", params.session_id.clone())
                .field("command", command.clone())
                .map_err(ErrorData::from)?;
            Ok(output)
        }
    };
}

#[allow(dead_code)]
#[tool_router_with_gef]
impl GdbService {
    #[tool(
        name = "create_session",
        description = "Create a new GDB debugging session with optional parameters, returns a session ID (UUID) if successful"
    )]
    async fn create_session(
        &self,
        Parameters(params): Parameters<CreateSessionParams>,
    ) -> Result<String, ErrorData> {
        let args = params
            .args
            .map(|args| args.into_iter().map(OsString::from).collect());
        let program_field = params
            .program
            .as_ref()
            .map(|path| path.display().to_string());
        let gdb_path_field = params
            .gdb_path
            .as_ref()
            .map(|path| path.display().to_string());
        let create_pty_field = params.create_pty;
        let result = GDB_MANAGER
            .create_session(
                params.program,
                params.nh,
                params.nx,
                params.quiet,
                params.cd,
                params.bps,
                params.symbol_file,
                params.core_file,
                params.proc_id,
                params.command,
                params.source_dir,
                args,
                params.tty,
                params.gdb_path,
                params.gef_script,
                params.gef_rc,
                params.create_pty,
            )
            .await;
        let result = if let Some(program_field) = program_field {
            result.field("program", program_field)
        } else {
            result
        };
        let result = if let Some(gdb_path_field) = gdb_path_field {
            result.field("gdb_path", gdb_path_field)
        } else {
            result
        };
        let result = if let Some(create_pty_field) = create_pty_field {
            result.field("create_pty", create_pty_field.to_string())
        } else {
            result
        };
        let session = result.map_err(ErrorData::from)?;
        Ok(format!("Created GDB session: {}", session))
    }

    #[tool(name = "get_session", description = "Get a GDB debugging session by ID")]
    async fn get_session(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let session = GDB_MANAGER
            .get_session(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(format!("Session: {}", json_text(&session)?))
    }

    #[tool(name = "get_all_sessions", description = "Get all GDB debugging sessions")]
    async fn get_all_sessions(&self) -> Result<String, ErrorData> {
        let sessions = GDB_MANAGER.get_all_sessions().await.map_err(ErrorData::from)?;
        Ok(format!("Sessions: {}", json_text(&sessions)?))
    }

    #[tool(name = "close_session", description = "Close a GDB debugging session")]
    async fn close_session(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        GDB_MANAGER
            .close_session(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok("Closed GDB session".to_string())
    }

    #[tool(name = "start_debugging", description = "Start debugging in a session")]
    async fn start_debugging(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let ret = GDB_MANAGER
            .start_debugging(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(format!("Started debugging: {}", ret))
    }

    #[tool(name = "stop_debugging", description = "Stop debugging in a session")]
    async fn stop_debugging(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let ret = GDB_MANAGER
            .stop_debugging(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(format!("Stopped debugging: {}", ret))
    }

    #[tool(name = "get_breakpoints", description = "Get all breakpoints in the current GDB session")]
    async fn get_breakpoints(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let breakpoints = GDB_MANAGER
            .get_breakpoints(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(format!("Breakpoints: {}", json_text(&breakpoints)?))
    }

    #[tool(name = "set_breakpoint", description = "Set a breakpoint in the code")]
    async fn set_breakpoint(
        &self,
        Parameters(params): Parameters<BreakpointParams>,
    ) -> Result<String, ErrorData> {
        let file_field = params.file.clone();
        let line_field = params.line;
        let breakpoint = GDB_MANAGER
            .set_breakpoint(&params.session_id, &PathBuf::from(params.file), params.line)
            .await
            .field("session_id", params.session_id.clone())
            .field("file", file_field)
            .field("line", line_field.to_string())
            .map_err(ErrorData::from)?;
        Ok(format!("Set breakpoint: {}", json_text(&breakpoint)?))
    }

    #[tool(name = "delete_breakpoint", description = "Delete one or more breakpoints in the code")]
    async fn delete_breakpoint(
        &self,
        Parameters(params): Parameters<DeleteBreakpointParams>,
    ) -> Result<String, ErrorData> {
        let count_field = params.breakpoints.len();
        GDB_MANAGER
            .delete_breakpoint(&params.session_id, params.breakpoints)
            .await
            .field("session_id", params.session_id.clone())
            .field("breakpoint_count", count_field.to_string())
            .map_err(ErrorData::from)?;
        Ok("Breakpoints deleted".to_string())
    }

    #[tool(name = "get_stack_frames", description = "Get stack frames in the current GDB session")]
    async fn get_stack_frames(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let frames = GDB_MANAGER
            .get_stack_frames(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(format!("Stack frames: {}", json_text(&frames)?))
    }

    #[tool(name = "get_local_variables", description = "Get local variables in the current stack frame")]
    async fn get_local_variables(
        &self,
        Parameters(params): Parameters<FrameParams>,
    ) -> Result<String, ErrorData> {
        let frame_field = params.frame_id.map(|value| value.to_string());
        let result = GDB_MANAGER
            .get_local_variables(&params.session_id, params.frame_id)
            .await
            .field("session_id", params.session_id.clone());
        let result = if let Some(frame_field) = frame_field {
            result.field("frame_id", frame_field)
        } else {
            result
        };
        let variables = result.map_err(ErrorData::from)?;
        Ok(format!("Local variables: {}", json_text(&variables)?))
    }

    #[tool(name = "get_registers", description = "Get registers in the current GDB session")]
    async fn get_registers(
        &self,
        Parameters(params): Parameters<RegistersParams>,
    ) -> Result<String, ErrorData> {
        let reg_count_field = params.reg_list.as_ref().map(|list| list.len());
        let result = GDB_MANAGER
            .get_registers(&params.session_id, params.reg_list)
            .await
            .field("session_id", params.session_id.clone());
        let result = if let Some(reg_count_field) = reg_count_field {
            result.field("register_count", reg_count_field.to_string())
        } else {
            result
        };
        let registers = result.map_err(ErrorData::from)?;
        Ok(format!("Registers: {}", json_text(&registers)?))
    }

    #[tool(name = "get_register_names", description = "Get register names in the current GDB session")]
    async fn get_register_names(
        &self,
        Parameters(params): Parameters<RegistersParams>,
    ) -> Result<String, ErrorData> {
        let reg_count_field = params.reg_list.as_ref().map(|list| list.len());
        let result = GDB_MANAGER
            .get_register_names(&params.session_id, params.reg_list)
            .await
            .field("session_id", params.session_id.clone());
        let result = if let Some(reg_count_field) = reg_count_field {
            result.field("register_count", reg_count_field.to_string())
        } else {
            result
        };
        let registers = result.map_err(ErrorData::from)?;
        Ok(format!("Registers: {}", json_text(&registers)?))
    }

    #[tool(
        name = "read_memory",
        description = "Read the memory in the current GDB session. This command attempts to read all accessible memory regions in the specified range."
    )]
    async fn read_memory(
        &self,
        Parameters(params): Parameters<ReadMemoryParams>,
    ) -> Result<String, ErrorData> {
        let address_field = params.address.clone();
        let count_field = params.count;
        let result = GDB_MANAGER
            .read_memory(&params.session_id, params.offset, params.address, params.count)
            .await
            .field("session_id", params.session_id.clone())
            .field("address", address_field)
            .field("count", count_field.to_string());
        let memory = result.map_err(ErrorData::from)?;
        Ok(format!("Memory: {}", json_text(&memory)?))
    }

    #[tool(name = "continue_execution", description = "Continue program execution")]
    async fn continue_execution(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let ret = GDB_MANAGER
            .continue_execution(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(format!("Continued execution: {}", ret))
    }

    #[tool(name = "step_execution", description = "Step into next line")]
    async fn step_execution(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let ret = GDB_MANAGER
            .step_execution(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(format!("Stepped into next line: {}", ret))
    }

    #[tool(name = "next_execution", description = "Step over next line")]
    async fn next_execution(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let ret = GDB_MANAGER
            .next_execution(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(format!("Stepped over next line: {}", ret))
    }

    #[tool(
        name = "execute_cli",
        description = "Execute a GDB/GEF CLI command in the current session"
    )]
    async fn execute_cli(
        &self,
        Parameters(params): Parameters<ExecuteCliParams>,
    ) -> Result<String, ErrorData> {
        let command = normalize_gef_json_command(&params.command, params.json.unwrap_or(false));
        let command_field = command.clone();
        let output = GDB_MANAGER
            .execute_cli(&params.session_id, &command)
            .await
            .field("session_id", params.session_id.clone())
            .field("command", command_field)
            .map_err(ErrorData::from)?;
        Ok(output)
    }

    #[tool(
        name = "get_inferior_output",
        description = "Read buffered inferior output from the PTY master"
    )]
    async fn get_inferior_output(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<String, ErrorData> {
        let output = GDB_MANAGER
            .get_inferior_output(&session_id)
            .await
            .field("session_id", session_id.clone())
            .map_err(ErrorData::from)?;
        Ok(output)
    }

    #[tool(
        name = "send_inferior_input",
        description = "Send input to the inferior process via PTY"
    )]
    async fn send_inferior_input(
        &self,
        Parameters(params): Parameters<InferiorInputParams>,
    ) -> Result<String, ErrorData> {
        let input_len = params.input.len();
        GDB_MANAGER
            .send_inferior_input(&params.session_id, &params.input)
            .await
            .field("session_id", params.session_id.clone())
            .field("input_len", input_len.to_string())
            .map_err(ErrorData::from)?;
        Ok("Sent inferior input".to_string())
    }

    // Security
    gef_command_tool!(checksec_tool, "checksec", "checksec", "Inspect binary security features");
    gef_command_tool!(canary_tool, "canary", "canary", "Display stack canary value");
    gef_command_tool!(aslr_tool, "aslr", "aslr", "Show ASLR status");
    gef_command_tool!(pie_tool, "pie", "pie", "Display PIE information");

    // Memory
    gef_command_tool!(vmmap_tool, "vmmap", "vmmap", "Show memory mappings");
    gef_command_tool!(memory_tool, "memory", "memory", "Inspect or modify memory");
    gef_command_tool!(hexdump_tool, "hexdump", "hexdump", "Hexdump memory");
    gef_command_tool!(dereference_tool, "dereference", "dereference", "Dereference pointers");
    gef_command_tool!(xinfo_tool, "xinfo", "xinfo", "Display address information");
    gef_command_tool!(xor_memory_tool, "xor-memory", "xor-memory", "XOR memory contents");

    // Heap
    gef_command_tool!(heap_tool, "heap", "heap", "Inspect heap structures");
    gef_command_tool!(
        heap_analysis_helper_tool,
        "heap-analysis-helper",
        "heap-analysis-helper",
        "Heap analysis helper"
    );

    // ELF / Binary
    gef_command_tool!(elf_info_tool, "elf-info", "elf-info", "Show ELF information");
    gef_command_tool!(got_tool, "got", "got", "Display GOT entries");
    gef_command_tool!(xfiles_tool, "xfiles", "xfiles", "List loaded files");

    // Search
    gef_command_tool!(
        search_pattern_tool,
        "search-pattern",
        "search-pattern",
        "Search for patterns in memory"
    );
    gef_command_tool!(scan_tool, "scan", "scan", "Scan memory for values");
    gef_command_tool!(pattern_tool, "pattern", "pattern", "Generate or search patterns");

    // Patch
    gef_command_tool!(nop_tool, "nop", "nop", "Patch memory with NOPs");
    gef_command_tool!(patch_tool, "patch", "patch", "Patch memory");
    gef_command_tool!(stub_tool, "stub", "stub", "Stub functions");

    // Execution control
    gef_command_tool!(entry_break_tool, "entry-break", "entry-break", "Break at program entry");
    gef_command_tool!(name_break_tool, "name-break", "name-break", "Set breakpoint by name");
    gef_command_tool!(skipi_tool, "skipi", "skipi", "Skip instructions");
    gef_command_tool!(stepover_tool, "stepover", "stepover", "Step over instructions");
    gef_command_tool!(trace_run_tool, "trace-run", "trace-run", "Trace execution");

    // Process
    gef_command_tool!(process_status_tool, "process-status", "process-status", "Show process status");
    gef_command_tool!(process_search_tool, "process-search", "process-search", "Search processes");
    gef_command_tool!(hijack_fd_tool, "hijack-fd", "hijack-fd", "Hijack file descriptor");

    // Misc
    gef_command_tool!(context_tool, "context", "context", "Show context");
    gef_command_tool!(registers_tool, "registers", "registers", "Show registers");
    gef_command_tool!(arch_tool, "arch", "arch", "Show architecture info");
    gef_command_tool!(eval_tool, "eval", "eval", "Evaluate expression");
    gef_command_tool!(print_format_tool, "print-format", "print-format", "Display format options");
    gef_command_tool!(
        format_string_helper_tool,
        "format-string-helper",
        "format-string-helper",
        "Format string helper"
    );
    gef_command_tool!(pcustom_tool, "pcustom", "pcustom", "Custom structure printing");
    gef_command_tool!(reset_cache_tool, "reset-cache", "reset-cache", "Reset GEF cache");
    gef_command_tool!(shellcode_tool, "shellcode", "shellcode", "Generate shellcode");
    gef_command_tool!(edit_flags_tool, "edit-flags", "edit-flags", "Edit flags");
    gef_command_tool!(functions_tool, "functions", "functions", "List GEF functions");

    // GEF helper functions
    gef_function_tool!(gef_base_tool, "gef_base", "$_base()", "Evaluate $_base()");
    gef_function_tool!(gef_stack_tool, "gef_stack", "$_stack()", "Evaluate $_stack()");
    gef_function_tool!(gef_heap_tool, "gef_heap", "$_heap()", "Evaluate $_heap()");
    gef_function_tool!(gef_got_tool, "gef_got", "$_got()", "Evaluate $_got()");
    gef_function_tool!(gef_bss_tool, "gef_bss", "$_bss()", "Evaluate $_bss()");
}

#[tool_handler]
impl ServerHandler for GdbService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: Some(false) }),
                ..Default::default()
            },
            server_info: Implementation::from_build_env(),
            instructions: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{format_gef_json_cli, normalize_gef_json_command};

    const TOOLS: &[&str] = &[
        "checksec",
        "canary",
        "aslr",
        "pie",
        "vmmap",
        "memory",
        "hexdump",
        "dereference",
        "xinfo",
        "xor-memory",
        "heap",
        "heap-analysis-helper",
        "elf-info",
        "got",
        "xfiles",
        "search-pattern",
        "scan",
        "pattern",
        "nop",
        "patch",
        "stub",
        "entry-break",
        "name-break",
        "skipi",
        "stepover",
        "trace-run",
        "process-status",
        "process-search",
        "hijack-fd",
        "context",
        "registers",
        "arch",
        "eval",
        "print-format",
        "format-string-helper",
        "pcustom",
        "reset-cache",
        "shellcode",
        "edit-flags",
        "functions",
        "gef_base",
        "gef_stack",
        "gef_heap",
        "gef_got",
        "gef_bss",
    ];

    #[test]
    fn build_json_command_includes_tool() {
        for tool in TOOLS {
            let cmd = format_gef_json_cli(tool, Some("arg1 arg2"));
            assert!(cmd.starts_with("gef-json "));
            assert!(cmd.contains(tool));
        }
    }

    #[test]
    fn build_json_command_handles_quotes() {
        let cmd = format_gef_json_cli("checksec", Some("arg \"with quotes\""));
        assert!(cmd.contains("arg \"with quotes\""));
    }

    #[test]
    fn build_json_command_allows_null_args() {
        let cmd = format_gef_json_cli("checksec", None);
        assert_eq!(cmd, "gef-json checksec");
    }

    #[test]
    fn build_json_command_trims_args() {
        let cmd = format_gef_json_cli("checksec", Some("   "));
        assert_eq!(cmd, "gef-json checksec");
    }

    #[test]
    fn normalize_cli_no_json_trims_only() {
        let cmd = normalize_gef_json_command("  checksec  ", false);
        assert_eq!(cmd, "checksec");
    }

    #[test]
    fn normalize_cli_json_prefixes() {
        let cmd = normalize_gef_json_command("checksec", true);
        assert_eq!(cmd, "gef-json checksec");
    }

    #[test]
    fn normalize_cli_json_keeps_existing() {
        let cmd = normalize_gef_json_command("gef-json checksec", true);
        assert_eq!(cmd, "gef-json checksec");
    }

    #[test]
    fn normalize_cli_json_empty() {
        let cmd = normalize_gef_json_command("   ", true);
        assert_eq!(cmd, "gef-json");
    }
}
