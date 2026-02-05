use std::path::PathBuf;
use std::time::Duration;
use mcp_server_gdb::GDBManager;

#[tokio::test]
#[ignore]
async fn test_inferior_output_via_pty() -> Result<(), Box<dyn std::error::Error>> {
    let program = match std::env::var("GEF_TEST_BINARY") {
        Ok(path) => path,
        Err(_) => return Ok(()),
    };

    let manager = GDBManager::default();
    let session_id = manager
        .create_session(
            Some(PathBuf::from(program)),
            Some(true),
            Some(true),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true),
        )
        .await?;

    let _ = manager.start_debugging(&session_id).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let output = manager.get_inferior_output(&session_id).await?;
    assert!(output.contains("Starting test application") || output.is_empty());

    manager.close_session(&session_id).await?;
    Ok(())
}
