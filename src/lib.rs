pub mod model;
pub mod io;
pub mod parser;
pub mod task;

pub mod formatter;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Default)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub roa_data: Arc<RwLock<ROACache>>,
    pub dns_data: Arc<RwLock<DNSCache>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct AppConfig {
    pub listen_address: String,
    pub roa_endpoint: String,
    pub dns_config_endpoint: String,
    pub dns_content_endpoint_directory: String,

    pub do_git_pull: bool,

    pub git_repo_url: String,
    pub git_repo_local_path: String,
    pub git_repo_ipv4_route_relative_path: String,
    pub git_repo_ipv6_route_relative_path: String,

    pub git_repo_dns_relative_path: String,
    pub git_repo_inetnum_relative_path: String,
    pub git_repo_inet6num_relative_path: String,

    pub update_interval_seconds: u64,

    pub dns_primary_master: String,
    pub dns_responsible_party: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            listen_address: "0.0.0.0:8080".to_string(),
            roa_endpoint: "/roa.json".to_string(),
            dns_config_endpoint: "/dns/config.json".to_string(),
            dns_content_endpoint_directory: "/dns/content".to_string(),
            do_git_pull: true,
            git_repo_url: "git@git.dn42.dev:dn42/registry.git".to_string(),
            git_repo_local_path: "./registry".to_string(),
            git_repo_ipv4_route_relative_path: "data/route".to_string(),
            git_repo_ipv6_route_relative_path: "data/route6".to_string(),

            git_repo_dns_relative_path: "data/dns".to_string(),
            git_repo_inetnum_relative_path: "data/inetnum".to_string(),
            git_repo_inet6num_relative_path: "data/inet6num".to_string(),

            update_interval_seconds: 300,

            dns_primary_master: "default-not-set".to_string(),
            dns_responsible_party: "default-not-set".to_string(),
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

pub struct DNSCache {
    // zone -> zone content
    pub content: HashMap<String, String>,
    pub last_updated: std::time::SystemTime,
}

impl Default for DNSCache {
    fn default() -> Self {
        DNSCache {
            content: HashMap::new(),
            last_updated: std::time::SystemTime::now(),
        }
    }
}