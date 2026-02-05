use std::path::{Path, PathBuf};
use mcp_server_gdb::GDBManager;

#[tokio::test]
#[ignore]
async fn test_create_gef_session() -> Result<(), Box<dyn std::error::Error>> {
    let program = match std::env::var("GEF_TEST_BINARY") {
        Ok(path) => path,
        Err(_) => return Ok(()),
    };

    if !Path::new("vendor/gef/gef.py").exists() || !Path::new("configs/gef.rc").exists() {
        return Ok(());
    }

    let gdb_path = std::env::var("GDB_PATH").ok().map(PathBuf::from);
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
            gdb_path,
            Some(PathBuf::from("vendor/gef/gef.py")),
            Some(PathBuf::from("configs/gef.rc")),
            Some(true),
        )
        .await?;

    let output = manager.execute_cli(&session_id, "checksec").await?;
    assert!(!output.is_empty());

    manager.close_session(&session_id).await?;
    Ok(())
}
