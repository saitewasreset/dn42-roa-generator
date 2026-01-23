use crate::io::get_records_from_dirs;
use crate::model::output::RpkiClientOutput;
use crate::parser::get_parsed_roa_routes;
use crate::task::Task;
use crate::AppState;
use std::path::Path;
use tracing::warn;

pub struct GenerateRoaTask {
    app_state: AppState,
}

impl GenerateRoaTask {
    pub fn new(app_state: AppState) -> Self {
        Self { app_state }
    }
}

impl Task for GenerateRoaTask {
    fn name(&self) -> &str {
        "Generate ROA"
    }

    fn run(&self) -> anyhow::Result<()> {
        let state = &self.app_state;

        let git_repo_local_path = Path::new(&state.config.git_repo_local_path);

        let output = if git_repo_local_path.exists() {
            let route_directories = [
                git_repo_local_path.join(&state.config.git_repo_ipv4_route_relative_path),
                git_repo_local_path.join(&state.config.git_repo_ipv6_route_relative_path)
            ];

            let route_records = get_records_from_dirs("ROA", route_directories.iter())?;

            get_parsed_roa_routes(&route_records)
        } else {
            warn!("Git repository path {:?} does not exist. Skipping JSON ROA generation.", git_repo_local_path);

            RpkiClientOutput::default()
        };

        let mut data_lock = state.roa_data.write().unwrap();

        data_lock.last_updated = std::time::SystemTime::now();
        data_lock.json_content = serde_json::to_string_pretty(&output)?;

        Ok(())
    }
}

