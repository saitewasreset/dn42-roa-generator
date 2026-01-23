use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use strum::{Display, EnumString};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl FromStr for Prefix {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid prefix format: {}", s));
        }

        let network = parts[0]
            .parse::<IpAddr>()
            .map_err(|e| format!("Invalid IP address: {}", e))?;
        let prefix_len = parts[1]
            .parse::<u8>()
            .map_err(|e| format!("Invalid prefix length: {}", e))?;

        Ok(Prefix {
            network,
            prefix_len,
        })
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumString, Display)]
pub enum RecordField {
    #[strum(serialize = "route")]
    Route,
    #[strum(serialize = "route6")]
    Route6,
    #[strum(serialize = "origin")]
    Origin,
    #[strum(serialize = "source")]
    Source,
    #[strum(serialize = "max-length")]
    MaxLength,
    #[strum(serialize = "descr")]
    Description,

    // DNS
    #[strum(serialize = "domain")]
    Domain,
    #[strum(serialize = "nserver")]
    NameServer,
}

pub struct RecordFile {
    file_path: PathBuf,
    field_map: HashMap<RecordField, Vec<String>>,
}

fn parse_content(content: &str) -> HashMap<RecordField, Vec<String>> {
    let mut field_map = HashMap::new();

    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let str_key = key.trim();

            if !key.starts_with(str_key) {
                continue; // Skip malformed lines
            }

            let field = match RecordField::from_str(str_key) {
                Ok(f) => f,
                Err(_) => continue, // Skip unknown fields
            };

            field_map.entry(field).or_insert_with(Vec::new).push(value.trim().to_owned());
        }
    }

    field_map
}

impl RecordFile {
    pub fn new(file: PathBuf) -> anyhow::Result<RecordFile> {
        let content = std::fs::read_to_string(&file)?;

        Ok(RecordFile {
            file_path: file,
            field_map: parse_content(&content),
        })
    }

    pub fn get_field(&self, key: RecordField) -> Option<&Vec<String>> {
        self.field_map.get(&key)
    }

    pub fn get_file_path(&self) -> &Path {
        &self.file_path
    }
}