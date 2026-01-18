pub mod model;
pub mod io;
pub mod parser;

use std::path::Path;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use crate::io::discover_route_record;
use crate::model::output::RpkiClientOutput;
use crate::parser::get_parsed_roa_routes;

#[derive(Clone, Default)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub data: Arc<RwLock<ROACache>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub listen_address: String,
    pub roa_endpoint: String,
    pub git_repo_url: String,
    pub git_repo_local_path: String,
    pub git_repo_ipv4_route_relative_path: String,
    pub git_repo_ipv6_route_relative_path: String,
    pub update_interval_seconds: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            listen_address: "0.0.0.0:8080".to_string(),
            roa_endpoint: "/roa.json".to_string(),
            git_repo_url: "git@git.dn42.dev:dn42/registry.git".to_string(),
            git_repo_local_path: "./registry".to_string(),
            git_repo_ipv4_route_relative_path: "data/route".to_string(),
            git_repo_ipv6_route_relative_path: "data/route6".to_string(),
            update_interval_seconds: 300,
        }
    }
}

pub struct ROACache {
    pub json_content: String,
    pub last_updated: std::time::SystemTime,
}

impl Default for ROACache {
    fn default() -> Self {
        ROACache {
            json_content: String::new(),
            last_updated: std::time::SystemTime::now(),
        }
    }
}

pub fn generate_json_roa(state: AppState) -> anyhow::Result<()> {
    let git_repo_local_path = Path::new(&state.config.git_repo_local_path);

    let output = if git_repo_local_path.exists() {
        let route_directories = vec![
            git_repo_local_path.join(&state.config.git_repo_ipv4_route_relative_path),
            git_repo_local_path.join(&state.config.git_repo_ipv6_route_relative_path)
        ];

        let route_records_path = discover_route_record(route_directories.iter())?;

        let count = route_records_path.len();

        info!("Discovered {} route record files.", count);

        let mut route_records = Vec::with_capacity(count);

        for path in route_records_path {
            let record = io::parse_route_record(&path)?;
            route_records.push(record);
        }

        info!("Found {} route record files.", route_records.len());

        get_parsed_roa_routes(&route_records)
    } else {
        warn!("Git repository path {:?} does not exist. Skipping JSON ROA generation.", git_repo_local_path);

        RpkiClientOutput::default()
    };

    let mut data_lock = state.data.write().unwrap();

    data_lock.last_updated = std::time::SystemTime::now();
    data_lock.json_content = serde_json::to_string_pretty(&output)?;

    Ok(())
}