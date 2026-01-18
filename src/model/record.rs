use std::cell::{LazyCell};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordField {
    Route,
    Route6,
    Origin,
    Source,
    MaxLength,
    Description,
}

impl RecordField {
    const NAMES_TO_FIELDS: phf::Map<&'static str, RecordField> = phf::phf_map! {
        "route" => RecordField::Route,
        "route6" => RecordField::Route6,
        "origin" => RecordField::Origin,
        "source" => RecordField::Source,
        "max-length" => RecordField::MaxLength,
        "descr" => RecordField::Description,
    };

    const FIELDS_TO_NAMES: LazyCell<HashMap<RecordField, &'static str>> = LazyCell::new(|| {
        let mut map = HashMap::new();
        for (name, field) in RecordField::NAMES_TO_FIELDS.entries() {
            map.insert(field.clone(), *name);
        }
        map
    });
}

impl FromStr for RecordField {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RecordField::NAMES_TO_FIELDS
            .get(s)
            .cloned()
            .ok_or_else(|| format!("Unknown record field name: {}", s))
    }
}

impl Display for RecordField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = RecordField::FIELDS_TO_NAMES.get(self) {
            write!(f, "{}", name)
        } else {
            write!(f, "Unknown")
        }
    }
}

pub struct RecordFile {
    file_path: PathBuf,
    field_map: HashMap<RecordField, String>,
}

fn parse_content(content: &str) -> HashMap<RecordField, String> {
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

            field_map.insert(field, value.trim().to_string());
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

    pub fn get_field(&self, key: RecordField) -> Option<&String> {
        self.field_map.get(&key)
    }

    pub fn get_file_path(&self) -> &Path {
        &self.file_path
    }
}