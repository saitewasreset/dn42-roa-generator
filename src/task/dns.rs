use crate::formatter::dns_zone::format_dns_zone;
use crate::io::get_records_from_dirs;
use crate::parser::dns::{generate_reverse_zones, get_parsed_ns_records};
use crate::task::Task;
use crate::AppState;
use std::path::Path;
use tracing::warn;

pub struct GenerateDNSAuthoritativeZonesTask {
    app_state: AppState,
}

impl GenerateDNSAuthoritativeZonesTask {
    pub fn new(app_state: AppState) -> Self {
        Self { app_state }
    }
}

impl Task for GenerateDNSAuthoritativeZonesTask {
    fn name(&self) -> &str {
        "Generate DNS Authoritative Zones"
    }

    fn run(&self) -> anyhow::Result<()> {
        let state = &self.app_state;

        let git_repo_local_path = Path::new(&state.config.git_repo_local_path);

        let dns_zones = if git_repo_local_path.exists() {
            let dns_directories = [
                git_repo_local_path.join(&state.config.git_repo_dns_relative_path),
            ];

            let inetnum_directories = [
                git_repo_local_path.join(&state.config.git_repo_inetnum_relative_path),
                git_repo_local_path.join(&state.config.git_repo_inet6num_relative_path),
            ];

            let dns_records = get_records_from_dirs("DNS", dns_directories.iter())?;
            let inetnum_records = get_records_from_dirs("INETNUM", inetnum_directories.iter())?;

            let mut dns_zones = get_parsed_ns_records(&dns_records, &self.app_state.config.dns_primary_master, &self.app_state.config.dns_responsible_party);
            dns_zones.extend(generate_reverse_zones(&inetnum_records, &self.app_state.config.dns_primary_master, &self.app_state.config.dns_responsible_party));

            dns_zones
        } else {
            warn!("Git repository path {:?} does not exist. Skipping DNS forward zone generation.", git_repo_local_path);

            Vec::default()
        };

        let zone_name_to_content = dns_zones
            .into_iter()
            .map(|zone| (zone.origin().to_string(), format_dns_zone(&zone)))
            .collect::<std::collections::HashMap<String, _>>();

        let mut data_lock = state.dns_data.write().unwrap();
        
        data_lock.last_updated = std::time::SystemTime::now();
        data_lock.content = zone_name_to_content;

        Ok(())
    }
}