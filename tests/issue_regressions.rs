#[cfg(unix)]
mod issue_regressions {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use mcp_server_gdb::GDBManager;
    use tokio::time::sleep;

    fn tetris_path() -> PathBuf {
        let mut path = std::env::current_dir().expect("cwd");
        path.push("examples");
        path.push("tetris");
        path
    }

    struct SessionCleanup {
        manager: Arc<GDBManager>,
        session_id: String,
    }

    impl Drop for SessionCleanup {
        fn drop(&mut self) {
            let manager = self.manager.clone();
            let session_id = self.session_id.clone();
            tokio::spawn(async move {
                let _ = manager.close_session(&session_id).await;
            });
        }
    }

    async fn create_session(manager: &GDBManager) -> String {
        manager
            .create_session(
                Some(tetris_path()),
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
                None,
                Some(PathBuf::from("configs/gef.rc")),
                Some(false),
                None, // lib_dir
            )
            .await
            .expect("create_session")
    }

    #[tokio::test]
    async fn test_issue_regressions() {
        let manager = Arc::new(GDBManager::default());
        let session_id = create_session(&manager).await;
        let _cleanup = SessionCleanup { manager: manager.clone(), session_id: session_id.clone() };

        let gef_disable_color = manager
            .execute_cli(&session_id, "gef config gef.disable_color")
            .await
            .expect("gef.disable_color");
        println!("gef.disable_color output:\n{gef_disable_color}");

        let checksec = manager.execute_cli(&session_id, "checksec").await.expect("checksec");
        println!("checksec output:\n{checksec}");
        assert!(!checksec.trim().is_empty(), "checksec output empty");

        manager.start_debugging(&session_id).await.expect("start_debugging");
        sleep(Duration::from_millis(200)).await;

        let process_status =
            manager.execute_cli(&session_id, "process-status").await.expect("process-status");
        println!("process-status output:\n{process_status}");
        assert!(!process_status.trim().is_empty(), "process-status output empty");

        let registers = manager.execute_cli(&session_id, "registers").await.expect("registers");
        println!("registers output:\n{registers}");
        assert!(!registers.trim().is_empty(), "registers output empty");

        let context = manager.execute_cli(&session_id, "context").await.expect("context");
        assert!(!context.to_lowercase().contains("gdb is busy"), "context still reported busy");

        let eval = manager.evaluate_expression(&session_id, "$rsp").await.expect("eval");
        assert!(
            !eval.to_lowercase().contains("bad format string"),
            "eval returned format-string error"
        );
        assert!(!eval.trim().is_empty(), "eval returned empty output");

        manager
            .execute_cli(
                &session_id,
                "break tetris::menu::Menu::select\nbreak tetris::app::App::update",
            )
            .await
            .expect("multiline breakpoints");
        manager.execute_cli(&session_id, "info breakpoints").await.expect("follow-up command");

        let _breakpoints = manager.get_breakpoints(&session_id).await.expect("get_breakpoints");
        let _frames = manager.get_stack_frames(&session_id).await.expect("get_stack_frames");
    }

    #[tokio::test]
    async fn test_execute_cli_while_running_info_program() {
        let manager = Arc::new(GDBManager::default());
        let session_id = create_session(&manager).await;
        let _cleanup = SessionCleanup { manager: manager.clone(), session_id: session_id.clone() };

        manager.start_debugging(&session_id).await.expect("start_debugging");
        sleep(Duration::from_millis(200)).await;

        for i in 0..20 {
            let output = manager
                .execute_cli(&session_id, "info program")
                .await
                .unwrap_or_else(|err| panic!("info program failed on iteration {i}: {err}"));
            assert!(
                !output.to_lowercase().contains("program not being run"),
                "iteration {i} desynced: {output}"
            );

            manager
                .continue_execution(&session_id)
                .await
                .unwrap_or_else(|err| panic!("continue_execution failed on iteration {i}: {err}"));
            sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn test_execute_cli_while_running_info_reg() {
        let manager = Arc::new(GDBManager::default());
        let session_id = create_session(&manager).await;
        let _cleanup = SessionCleanup { manager: manager.clone(), session_id: session_id.clone() };

        manager.start_debugging(&session_id).await.expect("start_debugging");
        sleep(Duration::from_millis(200)).await;

        for i in 0..15 {
            let output = manager
                .execute_cli(&session_id, "info reg")
                .await
                .unwrap_or_else(|err| panic!("info reg failed on iteration {i}: {err}"));
            assert!(
                !output.to_lowercase().contains("program not being run"),
                "iteration {i} desynced: {output}"
            );

            manager
                .continue_execution(&session_id)
                .await
                .unwrap_or_else(|err| panic!("continue_execution failed on iteration {i}: {err}"));
            sleep(Duration::from_millis(50)).await;
        }
    }
}
