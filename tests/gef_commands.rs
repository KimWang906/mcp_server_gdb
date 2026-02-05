use std::path::{Path, PathBuf};
use mcp_server_gdb::GDBManager;

#[tokio::test]
#[ignore]
async fn test_gef_command_vmmap() -> Result<(), Box<dyn std::error::Error>> {
    let program = match std::env::var("GEF_TEST_BINARY") {
        Ok(path) => path,
        Err(_) => return Ok(()),
    };

    if !Path::new("vendor/gef/gef.py").exists() || !Path::new("configs/gef.rc").exists() {
        return Ok(());
    }

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
            Some(PathBuf::from("vendor/gef/gef.py")),
            Some(PathBuf::from("configs/gef.rc")),
            Some(true),
        )
        .await?;

    let output = manager.execute_cli(&session_id, "vmmap").await?;
    assert!(!output.is_empty());

    manager.close_session(&session_id).await?;
    Ok(())
}
