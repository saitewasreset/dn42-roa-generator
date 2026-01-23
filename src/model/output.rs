use std::net::IpAddr;
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct Metadata {
    #[serde(rename = "buildtime")]
    pub build_time: String,
    pub counts: u64,
    pub roas: u64,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            build_time: "".to_string(),
            counts: 0,
            roas: 0,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ROA {
    pub asn: u32,
    pub prefix: String,
    #[serde(rename = "maxLength")]
    pub max_length: u8,
}

#[derive(Serialize, Debug, Default)]
pub struct RpkiClientOutput {
    pub metadata: Metadata,
    pub roas: Vec<ROA>,
}

#[derive(Serialize, Debug)]
pub struct ForwardZoneItem {
    pub domain: String,
    pub servers: Vec<IpAddr>,
}