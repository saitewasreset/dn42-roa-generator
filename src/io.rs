use crate::model::record::RecordFile;
use crate::task::dns::GenerateDNSAuthoritativeZonesTask;
use crate::task::roa::GenerateRoaTask;
use crate::task::Task;
use crate::AppState;
use anyhow::Context;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::io::AsyncBufReadExt;
use tracing::{error, info};

fn discover_record(route_directories: impl Iterator<Item=impl AsRef<Path> + Debug>) -> anyhow::Result<Vec<PathBuf>> {
    let mut record_files = Vec::new();

    for dir in route_directories {
        for entry in fs::read_dir(&dir).with_context(|| format!("Failed to read directory {:?}", dir))? {
            let entry = entry.with_context(|| format!("Failed to read directory entry {:?}", dir))?;
            let path = entry.path();

            if path.is_file() {
                record_files.push(path);
            }
        }
    }

    Ok(record_files)
}

fn parse_record(file_path: &Path) -> anyhow::Result<RecordFile> {
    let record_file = RecordFile::new(file_path.to_path_buf()).with_context(|| format!("Failed to parse record file {:?}", file_path))?;

    Ok(record_file)
}

pub fn get_records_from_dirs(record_type: &str, directories: impl Iterator<Item=impl AsRef<Path> + Debug>) -> anyhow::Result<Vec<RecordFile>> {
    let record_paths = discover_record(directories)?;

    info!("[{}] Discovered {} record files.", record_type, record_paths.len());

    let mut records = Vec::with_capacity(record_paths.len());

    for path in record_paths {
        let record = parse_record(&path)?;
        records.push(record);
    }

    info!("[{}] Found {} valid record files", record_type, records.len());

    Ok(records)
}

pub async fn background_updater(state: AppState) {
    let do_git_pull = state.config.do_git_pull;
    let repo_url = state.config.git_repo_url.clone();
    let repo_local_path = Path::new(&state.config.git_repo_local_path);
    let update_interval = std::time::Duration::from_secs(state.config.update_interval_seconds);

    let tasks: Vec<Box<dyn Task>> = vec![
        Box::new(GenerateRoaTask::new(state.clone())),
        Box::new(GenerateDNSAuthoritativeZonesTask::new(state.clone()))
    ];

    loop {
        info!("Starting background update of git repository.");

        if let Err(e) = sync_git_repository(&repo_url, repo_local_path, do_git_pull).await {
            error!("Error updating git repository: {:?}", e);
        } else {
            info!("Successfully updated git repository.");
        }

        for task in &tasks {
            info!("Running task: {}", task.name());

            if let Err(e) = task.run() {
                error!("Error running task '{}': {:?}", task.name(), e);
            } else {
                info!("Successfully completed task: {}", task.name());
            }
        }

        info!("Waiting for {:?} before next update.", update_interval);

        tokio::time::sleep(update_interval).await;
    }
}

pub async fn run_command_echo_output(command: &mut tokio::process::Command) -> anyhow::Result<()> {
    info!("Running command '{:?}'", command);

    let mut child = command
        .stdout(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn command {:?}", command))?;

    let child_output = child.stdout.take();

    if let Some(mut child_output) = child_output {
        use tokio::io::BufReader;
        let reader = BufReader::new(&mut child_output);

        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            info!("[command output] {}", line);
        }
    } else {
        info!("Child process has no stdout.");
    }

    child.wait().await
        .with_context(|| format!("Failed to wait for command {:?}", command))?;

    Ok(())
}

pub async fn sync_git_repository(repo_url: &str, repo_local_path: &Path, do_git_pull: bool) -> anyhow::Result<()> {
    if !repo_local_path.exists() {
        info!("Syncing git repository {} to {:?}", repo_url, repo_local_path);

        run_command_echo_output(tokio::process::Command::new("git").args(["clone", repo_url, repo_local_path.to_str().unwrap()]))
            .await
            .with_context(|| format!("Failed to clone git repository from {}", repo_url))?;
    } else {
        if do_git_pull {
            info!("Updating git repository at {:?}", repo_local_path);

            run_command_echo_output(tokio::process::Command::new("git").args(["-C", repo_local_path.to_str().unwrap(), "pull", "--rebase"]))
                .await
                .with_context(|| format!("Failed to update git repository at {:?}", repo_local_path))?;
        } else {
            info!("Git pull is disabled. Skipping update for repository at {:?}", repo_local_path);
        }
    }

    Ok(())
}