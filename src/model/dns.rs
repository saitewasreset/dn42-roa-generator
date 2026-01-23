pub struct DNSZone {
    origin: FQDNName,
    soa: DNSRecordData,
    records: HashSet<DNSRecord>,
}

impl DNSZone {
    pub fn new(origin: FQDNName, soa: DNSRecordData) -> Self {
        if !matches!(soa, DNSRecordData::SOA { .. }) {
            panic!("SOA record data is required for DNSZone");
        }

        DNSZone {
            origin,
            soa,
            records: HashSet::new(),
        }
    }

    pub fn origin(&self) -> &FQDNName {
        &self.origin
    }

    pub fn soa(&self) -> &DNSRecordData {
        &self.soa
    }

    pub fn records(&self) -> &HashSet<DNSRecord> {
        &self.records
    }

    pub fn add_record(&mut self, record: DNSRecord) -> Result<(), String> {
        if !record.name.is_child_of(&self.origin) && record.name != self.origin {
            return Err(format!(
                "Record name '{}' is not within the zone origin '{}'",
                record.name, self.origin
            ));
        }

        self.records.insert(record);

        Ok(())
    }
}

impl Default for DNSZone {
    fn default() -> Self {
        DNSZone {
            origin: FQDNName::new("dn42").unwrap(),
            soa: DNSRecordData::SOA {
                mname: "default_not_set".to_string(),
                rname: "default_not_set".to_string(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 86400,
            },
            records: HashSet::new(),
        }
    }
}

use std::collections::HashSet;
use std::fmt;
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FQDNName(String);

#[derive(Debug, PartialEq, Eq)]
pub enum FQDNError {
    EmptyInput,
    LabelEmpty,
    LabelTooLong(String),
    InvalidLabelStart(String),
    InvalidLabelEnd(String),
    InvalidCharacter(char, String),
}

impl Display for FQDNError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FQDNError::EmptyInput => write!(f, "Domain name cannot be empty"),
            FQDNError::LabelEmpty => write!(f, "Domain label cannot be empty (e.g., '..')"),
            FQDNError::LabelTooLong(l) => write!(f, "Label '{}' exceeds 63 characters", l),
            FQDNError::InvalidLabelStart(l) => write!(f, "Label '{}' must start with a letter", l),
            FQDNError::InvalidLabelEnd(l) => write!(f, "Label '{}' must end with a letter or digit", l),
            FQDNError::InvalidCharacter(c, l) => write!(f, "Label '{}' contains invalid character '{}'", l, c),
        }
    }
}

impl std::error::Error for FQDNError {}

impl FQDNName {
    pub fn new(name: &str) -> Result<Self, FQDNError> {
        if name.trim().is_empty() || name == " " {
            return Err(FQDNError::EmptyInput);
        }

        let to_validate = name.strip_suffix('.').unwrap_or(name);

        if to_validate.is_empty() {
            return Err(FQDNError::EmptyInput);
        }

        for label in to_validate.split('.') {
            Self::validate_label(label)?;
        }

        Ok(FQDNName(name.to_lowercase()))
    }

    fn validate_label(label: &str) -> Result<(), FQDNError> {
        // Labels must be 63 characters or less.
        if label.len() > 63 {
            return Err(FQDNError::LabelTooLong(label.to_string()));
        }
        if label.is_empty() {
            return Err(FQDNError::LabelEmpty);
        }

        let chars: Vec<char> = label.chars().collect();

        // They must start with a letter.
        // <letter> ::= A-Z | a-z
        // NOTE: In modern DNS, labels can start with digits as well

        if !(chars[0].is_ascii_alphabetic() || chars[0].is_ascii_digit()) {
            return Err(FQDNError::InvalidLabelStart(label.to_string()));
        }

        // end with a letter or digit.
        // <let-dig> ::= <letter> | <digit>
        if !chars.last().unwrap().is_ascii_alphanumeric() {
            return Err(FQDNError::InvalidLabelEnd(label.to_string()));
        }

        // interior characters only letters, digits, and hyphen.
        for &c in &chars {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(FQDNError::InvalidCharacter(c, label.to_string()));
            }
        }

        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_child_of(&self, parent: &FQDNName) -> bool {
        let self_labels: Vec<&str> = self.0.trim_end_matches('.').split('.').collect();
        let parent_labels: Vec<&str> = parent.0.trim_end_matches('.').split('.').collect();

        if self_labels.len() <= parent_labels.len() {
            return false;
        }

        let start_index = self_labels.len() - parent_labels.len();
        self_labels[start_index..] == parent_labels[..]
    }

    pub fn relative_to(&self, parent: &FQDNName) -> Option<String> {
        if !(self.is_child_of(parent) || self == parent) {
            return None;
        }

        let self_labels: Vec<&str> = self.0.trim_end_matches('.').split('.').collect();
        let parent_labels: Vec<&str> = parent.0.trim_end_matches('.').split('.').collect();

        let relative_labels = &self_labels[..self_labels.len() - parent_labels.len()];

        if relative_labels.is_empty() {
            Some("@".to_string())
        } else {
            Some(relative_labels.join("."))
        }
    }

    pub fn tld(&self) -> Option<String> {
        let labels: Vec<&str> = self.0.trim_end_matches('.').split('.').collect();
        labels.last().map(|s| s.to_string())
    }

    pub fn name_len(&self) -> usize {
        self.0.len()
    }
}

impl FromStr for FQDNName {
    type Err = FQDNError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FQDNName::new(s)
    }
}

impl Display for FQDNName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum DNSRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX { preference: u16, exchange: String },
    TXT(Vec<String>),
    NS(String),
    SOA {
        mname: String,   // Primary NS
        rname: String,   // Admin Email
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    PTR(String),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
}

impl DNSRecordData {
    pub fn type_str(&self) -> &'static str {
        match self {
            DNSRecordData::A(_) => "A",
            DNSRecordData::AAAA(_) => "AAAA",
            DNSRecordData::CNAME(_) => "CNAME",
            DNSRecordData::MX { .. } => "MX",
            DNSRecordData::TXT(_) => "TXT",
            DNSRecordData::NS(_) => "NS",
            DNSRecordData::SOA { .. } => "SOA",
            DNSRecordData::PTR(_) => "PTR",
            DNSRecordData::SRV { .. } => "SRV",
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum DNSClass {
    IN = 1,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DNSRecord {
    pub name: FQDNName,
    pub class: DNSClass,
    pub ttl: u32,
    pub data: DNSRecordData,
}

// 辅助方法：为了方便获取类型
impl DNSRecord {
    pub fn get_type_code(&self) -> u16 {
        match &self.data {
            DNSRecordData::A(_) => 1,
            DNSRecordData::NS(_) => 2,
            DNSRecordData::CNAME(_) => 5,
            DNSRecordData::SOA { .. } => 6,
            DNSRecordData::PTR(_) => 12,
            DNSRecordData::MX { .. } => 15,
            DNSRecordData::TXT(_) => 16,
            DNSRecordData::AAAA(_) => 28,
            DNSRecordData::SRV { .. } => 33,
        }
    }
}