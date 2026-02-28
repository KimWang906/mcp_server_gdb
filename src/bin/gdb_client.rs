use anyhow::Result;
use clap::{Parser, ValueEnum};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientInfo, Content, Implementation, ProtocolVersion};
use rmcp::transport::{ConfigureCommandExt, StreamableHttpClientTransport, TokioChildProcess};
use serde_json::{Value, json};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum TransportType {
    Stdio,
    Sse,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Transport type
    #[arg(value_enum, default_value_t = TransportType::Stdio)]
    transport: TransportType,

    /// Server address (only for SSE transport)
    #[arg(long, default_value = "127.0.0.1")]
    server_host: String,

    /// Server port (only for SSE transport)
    #[arg(long, default_value = "7071")]
    server_port: u16,

    /// Executable file path
    #[arg(short, long)]
    executable: Option<String>,
}

async fn call_tool(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>,
    tool_name: &str,
    params: Option<Value>,
) -> Result<Vec<Content>> {
    info!("Calling tool: {}", tool_name);
    debug!("Params: {:?}", params);
    let arguments = params.map(rmcp::model::object);
    let request = CallToolRequestParams {
        meta: None,
        name: tool_name.to_string().into(),
        arguments,
        task: None,
    };
    let response = client.peer().call_tool(request).await?;
    Ok(response.content)
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("info"))
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting GDB client");

    let client_info = ClientInfo {
        meta: None,
        protocol_version: ProtocolVersion::V_2024_11_05,
        capabilities: ClientCapabilities::default(),
        client_info: Implementation {
            name: "gdb-client".to_string(),
            title: None,
            description: None,
            version: "1.0".to_string(),
            icons: None,
            website_url: None,
        },
    };

    let client = match args.transport {
        TransportType::Stdio => {
            let transport = TokioChildProcess::new(
                tokio::process::Command::new("./target/debug/mcp-server-gdb").configure(|cmd| {
                    cmd.arg("--log-level").arg("debug");
                }),
            )?;
            client_info.clone().serve(transport).await?
        }
        TransportType::Sse => {
            let url = format!("http://{}:{}/mcp", args.server_host, args.server_port);
            let transport = StreamableHttpClientTransport::from_uri(url);
            client_info.clone().serve(transport).await?
        }
    };

    info!("Client created");

    // Create GDB session
    let session_response = call_tool(
        &client,
        "create_session",
        args.executable.map(|path| json!({ "program": path })),
    )
    .await?;

    info!("Session creation response: {:?}", session_response);

    // Extract session ID from response
    let content = session_response.first().ok_or_else(|| anyhow::anyhow!("No session response"))?;
    let text = content
        .as_text()
        .map(|text| text.text.as_str())
        .ok_or_else(|| anyhow::anyhow!("Unable to parse session response"))?;
    let session_id = text
        .split_once(": ")
        .and_then(|(_, rest)| rest.split('"').next())
        .ok_or_else(|| anyhow::anyhow!("Unable to parse session ID"))?;

    info!("Session ID: {}", session_id);

    // Set breakpoint
    let breakpoint_response = call_tool(
        &client,
        "set_breakpoint",
        Some(json!({
            "session_id": session_id,
            "file": "test_app.rs",
            "line": 5
        })),
    )
    .await?;
    info!("Breakpoint response: {:?}", breakpoint_response);

    // Start debugging
    let start_response = call_tool(
        &client,
        "start_debugging",
        Some(json!({
            "session_id": session_id
        })),
    )
    .await?;
    info!("Start debugging response: {:?}", start_response);

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Get stack frames
    let frames_response = call_tool(
        &client,
        "get_stack_frames",
        Some(json!({
            "session_id": session_id
        })),
    )
    .await?;
    info!("Stack frames response: {:?}", frames_response);

    // Get local variables
    let frames_response = call_tool(
        &client,
        "get_local_variables",
        Some(json!({
            "session_id": session_id
        })),
    )
    .await?;
    info!("Stack variables response: {:?}", frames_response);

    // Get registers
    let frames_response = call_tool(
        &client,
        "get_registers",
        Some(json!({
            "session_id": session_id
        })),
    )
    .await?;
    info!("Registers response: {:?}", frames_response);

    // Close session
    let close_response = call_tool(
        &client,
        "close_session",
        Some(json!({
            "session_id": session_id
        })),
    )
    .await?;
    info!("Close session response: {:?}", close_response);

    Ok(())
}
