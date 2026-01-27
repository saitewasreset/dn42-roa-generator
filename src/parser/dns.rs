use crate::model::dns::{DNSClass, DNSRecord, DNSRecordData, DNSZone, FQDNName, PrefixTree};
use crate::model::record::{Prefix, RecordField, RecordFile};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tracing::{error, info, warn};

const DEFAULT_TTL: u32 = 3600;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExtractedNameServerInfo {
    name_server: FQDNName,
    name_server_ip: Option<IpAddr>,
}

impl TryFrom<&RecordFile> for Vec<ExtractedNameServerInfo> {
    type Error = String;

    fn try_from(record_file: &RecordFile) -> Result<Self, Self::Error> {
        let mut name_servers = Vec::new();

        if let Some(nservers) = record_file.get_field(RecordField::NameServer) {
            for nserver in nservers {
                let parts: Vec<&str> = nserver.split_whitespace().take(2).collect();

                if parts.is_empty() || parts.len() > 2 {
                    return Err(format!("Invalid nameserver format in record: {:?} : {}", record_file.get_file_path(), nserver));
                }

                let name_server = FQDNName::from_str(parts[0])
                    .map_err(|e| format!("Invalid nameserver FQDN in record {:?} : {}", record_file.get_file_path(), e))?;

                let name_server_ip = if parts.len() == 2 {
                    Some(
                        IpAddr::from_str(parts[1])
                            .map_err(|e| format!("Invalid nameserver IP in record {:?} : {}", record_file.get_file_path(), e))?,
                    )
                } else {
                    None
                };

                name_servers.push(ExtractedNameServerInfo {
                    name_server,
                    name_server_ip,
                });
            }
        }

        Ok(name_servers)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExtractedNetworkInfo {
    cidr: Prefix,
    name_servers: Vec<ExtractedNameServerInfo>,
    ds_rdata: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExtractedDomainInfo {
    domain: FQDNName,
    tld: String,
    name_servers: Vec<ExtractedNameServerInfo>,
    ds_rdata: Vec<String>,
}

impl TryFrom<&RecordFile> for ExtractedDomainInfo
{
    type Error = String;

    fn try_from(record_file: &RecordFile) -> Result<Self, Self::Error> {
        let domains = record_file
            .get_field(RecordField::Domain)
            .ok_or_else(|| format!("No domain in record {:?}", record_file.get_file_path()))?;

        if domains.len() != 1 {
            return Err(format!("Multiple domain fields in record: {:?}", record_file.get_file_path()));
        }

        let domain = FQDNName::from_str(&domains[0])
            .map_err(|e| format!("Invalid domain FQDN in record {:?}: {}", record_file.get_file_path(), e))?;

        let tld = domain
            .tld()
            .ok_or_else(|| format!("No TLD in record {:?}", record_file.get_file_path()))?;

        let name_servers = record_file.try_into()?;

        let ds_rdata = record_file.get_field(RecordField::DSRdata).cloned().unwrap_or_default();

        Ok(ExtractedDomainInfo {
            domain,
            tld,
            name_servers,
            ds_rdata,
        })
    }
}

impl TryFrom<&RecordFile> for ExtractedNetworkInfo {
    type Error = String;

    fn try_from(record_file: &RecordFile) -> Result<Self, Self::Error> {
        let prefixes = record_file
            .get_field(RecordField::Cidr)
            .ok_or_else(|| format!("No cidr in record {:?}", record_file.get_file_path()))?;

        if prefixes.len() != 1 {
            return Err(format!("Multiple cidr fields in record: {:?}", record_file.get_file_path()));
        }

        let cidr = Prefix::from_str(&prefixes[0])
            .map_err(|e| format!("Invalid cidr in record {:?}: {}", record_file.get_file_path(), e))?;

        let name_servers = record_file.try_into()?;

        let ds_rdata = record_file.get_field(RecordField::DSRdata).cloned().unwrap_or_default();

        Ok(ExtractedNetworkInfo {
            cidr,
            name_servers,
            ds_rdata,
        })
    }
}

fn new_zone(tld: &str, dns_primary_master: String, dns_responsible_person: String, serial: u32) -> DNSZone {
    DNSZone::new(FQDNName::from_str(tld).unwrap(), DNSRecordData::SOA {
        mname: dns_primary_master,
        rname: dns_responsible_person,
        serial,
        refresh: 3600,
        retry: 600,
        expire: 604800,
        minimum: 1440,
    })
}

fn is_registry_sync_domain(domain: &FQDNName) -> bool {
    domain.as_str().ends_with("registry-sync.dn42") && domain.as_str() != "registry-sync.dn42"
}

// 1.1.25.10.ipv4.registry-sync.dn42
fn extract_ipv4_from_labels(labels: &[&str]) -> Result<IpAddr, String> {
    if labels.len() != 7 {
        return Err(format!("Invalid IPv4 registry-sync domain labels: {:?}, should have exactly 7 labels: A.B.C.D.ipv4.registry-sync.dn42", labels));
    }

    let octets_result: Result<Vec<u8>, _> = labels
        .iter()
        .take(4)
        .rev()
        .map(|label| label.parse::<u8>())
        .collect();

    match octets_result {
        Ok(octets) => {
            if octets.len() != 4 {
                return Err(format!("Invalid number of octets parsed from labels {:?}: expected 4, got {}", labels, octets.len()));
            }

            Ok(IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])))
        }
        Err(e) => Err(format!("Failed to parse IPv4 octets from labels {:?}: {}", labels, e)),
    }
}

// 1.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.f.f.a.b.f.f.0.0.d.f.ipv6.registry-sync.dn42
fn extract_ipv6_from_labels(labels: &[&str]) -> Result<IpAddr, String> {
    if labels.len() != 35 {
        return Err(format!("Invalid IPv6 registry-sync domain labels: {:?}, should have exactly 35 labels", labels));
    }

    let nibbles_result: Result<Vec<u8>, _> = labels
        .iter()
        .take(32)
        .rev()
        .map(|label| u8::from_str_radix(label, 16))
        .collect();

    match nibbles_result {
        Ok(nibbles) => {
            if nibbles.len() != 32 {
                return Err(format!("Invalid number of nibbles parsed from labels {:?}: expected 32, got {}", labels, nibbles.len()));
            }


            let segments: Vec<u16> = nibbles.chunks(4).map(|c| ((c[0] as u16) << 12) | ((c[1] as u16) << 8) | ((c[2] as u16) << 4) | (c[3] as u16)).collect();

            if segments.len() != 8 {
                return Err(format!("Invalid number of segments formed from nibbles {:?}: expected 8, got {}", labels, segments.len()));
            }

            Ok(IpAddr::V6(std::net::Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )))
        }
        Err(e) => Err(format!("Failed to parse IPv6 nibbles from labels {:?}: {}", labels, e)),
    }
}

// 1.1.25.10.ipv4.registry-sync.dn42
// 1.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.f.f.a.b.f.f.0.0.d.f.ipv6.registry-sync.dn42
fn extract_ip_from_registry_sync_domain(domain: &FQDNName) -> Result<IpAddr, String> {
    let labels: Vec<&str> = domain.as_str().split('.').collect();
    if labels.len() < 4 {
        return Err(format!("Invalid registry-sync domain: {}, should have at least 4 labels", domain));
    }

    let ip_version_label = labels[labels.len() - 3];

    match ip_version_label {
        "ipv4" => extract_ipv4_from_labels(&labels),
        "ipv6" => extract_ipv6_from_labels(&labels),
        _ => Err(format!("Invalid IP version label in domain: {}", domain)),
    }
}

fn generate_registry_sync_records(record_files: &[RecordFile]) -> Vec<DNSRecord> {
    let mut resolved_registry_sync_records = Vec::new();

    for record_file in record_files {
        let extracted_info = match ExtractedDomainInfo::try_from(record_file) {
            Ok(info) => info,
            Err(_) => {
                // Error has been logged in the caller function
                // warn!("{}", e);
                continue;
            }
        };

        for name_server in extracted_info.name_servers {
            let registry_sync_domain = name_server.name_server;

            if is_registry_sync_domain(&registry_sync_domain) {
                let resolved_ip = match extract_ip_from_registry_sync_domain(&registry_sync_domain) {
                    Ok(ip) => ip,
                    Err(e) => {
                        warn!("{}", e);
                        continue;
                    }
                };

                let record = DNSRecord {
                    name: registry_sync_domain,
                    class: DNSClass::IN,
                    ttl: DEFAULT_TTL,
                    data: match resolved_ip {
                        IpAddr::V4(ipv4) => DNSRecordData::A(ipv4),
                        IpAddr::V6(ipv6) => DNSRecordData::AAAA(ipv6),
                    },
                };

                resolved_registry_sync_records.push(record);
            }
        }
    }

    resolved_registry_sync_records
}

pub fn get_parsed_ns_records(record_files: &[RecordFile], dns_primary_master: &str, dns_responsible_person: &str) -> Vec<DNSZone> {
    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);


    let mut tld_to_zone: HashMap<String, DNSZone> = HashMap::new();

    for record_file in record_files {
        let extracted_info = match ExtractedDomainInfo::try_from(record_file) {
            Ok(info) => info,
            Err(e) => {
                warn!("{}", e);
                continue;
            }
        };


        let zone = tld_to_zone.entry(extracted_info.tld.clone()).or_insert_with(|| new_zone(&extracted_info.tld, dns_primary_master.to_string(), dns_responsible_person.to_string(), serial));

        for name_server in extracted_info.name_servers {
            if let Err(e) = zone.add_record(DNSRecord {
                name: extracted_info.domain.clone(),
                class: DNSClass::IN,
                ttl: DEFAULT_TTL,
                data: DNSRecordData::NS(name_server.name_server.to_string()),
            }) {
                warn!("Failed to add NS record to zone {}: {}", zone.origin(), e);
            }

            if let Some(ip) = name_server.name_server_ip
                && let Err(e) = zone.add_record(DNSRecord {
                name: name_server.name_server,
                class: DNSClass::IN,
                ttl: DEFAULT_TTL,
                data: match ip {
                    IpAddr::V4(ipv4) => DNSRecordData::A(ipv4),
                    IpAddr::V6(ipv6) => DNSRecordData::AAAA(ipv6),
                },
            }) {
                warn!("Failed to add glue record to zone {}: {}", zone.origin(), e);
            }
        }

        for ds_rdata in extracted_info.ds_rdata {
            let record = DNSRecord {
                name: extracted_info.domain.clone(),
                class: DNSClass::IN,
                ttl: DEFAULT_TTL,
                data: DNSRecordData::DS(ds_rdata),
            };

            // do not add DS record to its own zone
            if zone.origin() != &extracted_info.domain {
                zone.add_record(record).unwrap_or_else(|e| {
                    warn!("Failed to add DS record to zone {}: {}", zone.origin(), e);
                });
            }
        }
    }

    info!("Generating registry-sync records...");

    let registry_sync_records = generate_registry_sync_records(record_files);

    info!("Generated {} registry-sync records.", registry_sync_records.len());

    if let Some(zone) = tld_to_zone.get_mut("dn42") {
        for record in registry_sync_records {
            if let Err(e) = zone.add_record(record.clone()) {
                warn!("Failed to add registry-sync record to zone {}: {}", zone.origin(), e);
            }
        }
    }

    info!("Generated {} DNS forward zones.", tld_to_zone.values().map(|z| z.records().len()).sum::<usize>());

    tld_to_zone.into_values().collect()
}

#[derive(Default)]
struct ReverseRecordCounter {
    ipv4_align: usize,
    ipv4_non_align: usize,
    ipv6_align: usize,
    ipv6_non_align: usize,
}

fn generate_reverse_record_name(cidr: &Prefix) -> Option<FQDNName> {
    match cidr.network() {
        IpAddr::V4(ipv4) => {
            if cidr.prefix_len().is_multiple_of(8) {
                // IPv4 align with octet boundaries
                // 192.0.2.0/24 -> 2.0.192.in-addr.arpa
                let octets = ipv4.octets();

                let num_octets = (cidr.prefix_len() / 8) as usize;
                let reversed_labels: Vec<String> = octets[..num_octets]
                    .iter()
                    .rev()
                    .map(|o| o.to_string())
                    .collect();
                let reverse_zone_name = format!("{}.in-addr.arpa", reversed_labels.join("."));

                Some(FQDNName::from_str(&reverse_zone_name).unwrap())
            } else {
                // IPv4 not align with octet boundaries
                // 192.0.2.0/25 -> CNAME *.0/25.2.0.192.in-addr.arpa.

                let octets = ipv4.octets();
                let num_full_octets = (cidr.prefix_len() / 8) as usize;

                let labels: Vec<String> = octets[..num_full_octets]
                    .iter()
                    .map(|o| o.to_string())
                    .collect();

                let first_host_id = octets[num_full_octets];

                let cidr_part = format!("{}/{}", first_host_id, cidr.prefix_len());

                let mut with_insert_cidr_part = labels.clone();
                with_insert_cidr_part.push(cidr_part);

                let with_insert_cidr_reversed = with_insert_cidr_part.into_iter().rev().collect::<Vec<_>>();
                let mapped_full_name = format!("{}.in-addr.arpa", with_insert_cidr_reversed.join("."));

                Some(FQDNName::from_str(&mapped_full_name).unwrap())
            }
        }
        IpAddr::V6(ipv6) => {
            // IPv6 align with nibble boundaries
            // 2001:db8::/32 -> 8.b.d.0.1.0.0.2.ip6.arpa
            if cidr.prefix_len().is_multiple_of(4) {
                let segments = ipv6.segments();

                let mut nibbles = Vec::new();

                for segment in &segments {
                    nibbles.push(format!("{:x}", (segment >> 12) & 0xF));
                    nibbles.push(format!("{:x}", (segment >> 8) & 0xF));
                    nibbles.push(format!("{:x}", (segment >> 4) & 0xF));
                    nibbles.push(format!("{:x}", segment & 0xF));
                }

                let num_nibbles = (cidr.prefix_len() / 4) as usize;
                let reversed_labels: Vec<String> = nibbles[..num_nibbles]
                    .iter()
                    .rev()
                    .cloned()
                    .collect();

                let reverse_zone_name = format!("{}.ip6.arpa", reversed_labels.join("."));

                Some(FQDNName::from_str(&reverse_zone_name).unwrap())
            } else {
                None
            }
        }
    }
}

fn generate_reverse_records(cidr: &Prefix, name_servers: &[ExtractedNameServerInfo], counter: &mut ReverseRecordCounter) -> Vec<DNSRecord> {
    fn generate_reverse_records_for_nameserver(name: FQDNName, name_servers: &[ExtractedNameServerInfo]) -> Vec<DNSRecord> {
        let mut records = Vec::new();

        for ns in name_servers {
            records.push(DNSRecord {
                name: name.clone(),
                class: DNSClass::IN,
                ttl: DEFAULT_TTL,
                data: DNSRecordData::NS(ns.name_server.to_string()),
            });

            if let Some(ip) = &ns.name_server_ip {
                records.push(DNSRecord {
                    name: name.clone(),
                    class: DNSClass::IN,
                    ttl: DEFAULT_TTL,
                    data: match ip {
                        IpAddr::V4(ipv4) => DNSRecordData::A(*ipv4),
                        IpAddr::V6(ipv6) => DNSRecordData::AAAA(*ipv6),
                    },
                });
            }
        }

        records
    }

    let mut reverse_records = Vec::new();

    match cidr.network() {
        IpAddr::V4(ipv4) => {
            if cidr.prefix_len().is_multiple_of(8) {
                // IPv4 align with octet boundaries
                // 192.0.2.0/24 -> 2.0.192.in-addr.arpa
                let octets = ipv4.octets();

                let num_octets = (cidr.prefix_len() / 8) as usize;
                let reversed_labels: Vec<String> = octets[..num_octets]
                    .iter()
                    .rev()
                    .map(|o| o.to_string())
                    .collect();
                let reverse_zone_name = format!("{}.in-addr.arpa", reversed_labels.join("."));

                counter.ipv4_align += 1;
                reverse_records.extend(generate_reverse_records_for_nameserver(FQDNName::from_str(&reverse_zone_name).unwrap(), name_servers));
            } else {
                // IPv4 not align with octet boundaries
                // 192.0.2.0/25 -> CNAME *.0/25.2.0.192.in-addr.arpa.

                let octets = ipv4.octets();
                let num_full_octets = (cidr.prefix_len() / 8) as usize;
                let remaining_bits = cidr.prefix_len() % 8;

                let labels: Vec<String> = octets[..num_full_octets]
                    .iter()
                    .map(|o| o.to_string())
                    .collect();

                let first_host_id = octets[num_full_octets];

                let cidr_part = format!("{}/{}", first_host_id, cidr.prefix_len());

                let mut with_insert_cidr_part = labels.clone();
                with_insert_cidr_part.push(cidr_part);

                for host_id in first_host_id..=(first_host_id + ((1 << (8 - remaining_bits)) - 1)) {
                    let mut source_full_labels = labels.clone();
                    source_full_labels.push(host_id.to_string());

                    let source_full_reversed = source_full_labels.into_iter().rev().collect::<Vec<_>>();

                    let reverse_name = format!("{}.in-addr.arpa", source_full_reversed.join("."));

                    let mut mapped_full_labels = with_insert_cidr_part.clone();
                    mapped_full_labels.push(host_id.to_string());

                    let mapped_full_reversed = mapped_full_labels.into_iter().rev().collect::<Vec<_>>();

                    let mapped_full_name = format!("{}.in-addr.arpa", mapped_full_reversed.join("."));

                    reverse_records.push(DNSRecord {
                        name: FQDNName::from_str(&reverse_name).unwrap(),
                        class: DNSClass::IN,
                        ttl: DEFAULT_TTL,
                        data: DNSRecordData::CNAME(mapped_full_name),
                    });
                }

                let with_insert_cidr_reversed = with_insert_cidr_part.into_iter().rev().collect::<Vec<_>>();
                let mapped_full_name = format!("{}.in-addr.arpa", with_insert_cidr_reversed.join("."));

                reverse_records.extend(generate_reverse_records_for_nameserver(FQDNName::from_str(&mapped_full_name).unwrap(), name_servers));

                counter.ipv4_non_align += 1;
            }
        }
        IpAddr::V6(ipv6) => {
            // IPv6 align with nibble boundaries
            // 2001:db8::/32 -> 8.b.d.0.1.0.0.2.ip6.arpa
            if cidr.prefix_len().is_multiple_of(4) {
                let segments = ipv6.segments();

                let mut nibbles = Vec::new();

                for segment in &segments {
                    nibbles.push(format!("{:x}", (segment >> 12) & 0xF));
                    nibbles.push(format!("{:x}", (segment >> 8) & 0xF));
                    nibbles.push(format!("{:x}", (segment >> 4) & 0xF));
                    nibbles.push(format!("{:x}", segment & 0xF));
                }

                let num_nibbles = (cidr.prefix_len() / 4) as usize;
                let reversed_labels: Vec<String> = nibbles[..num_nibbles]
                    .iter()
                    .rev()
                    .cloned()
                    .collect();

                let reverse_zone_name = format!("{}.ip6.arpa", reversed_labels.join("."));

                reverse_records.extend(generate_reverse_records_for_nameserver(FQDNName::from_str(&reverse_zone_name).unwrap(), name_servers));

                counter.ipv6_align += 1;
            } else {
                // IPv6 not align with nibble boundaries is strongly discouraged, so we won't handle it for now
                warn!("IPv6 CIDR not aligned with nibble boundaries is not supported: {}", cidr);
                counter.ipv6_non_align += 1;
            }
        }
    }
    reverse_records
}

fn generate_reverse_ds_record(cidr: &Prefix, ds_rdata_list: &[String]) -> Vec<DNSRecord> {
    let mut ds_records = Vec::new();

    if let Some(name) = generate_reverse_record_name(cidr) {
        for ds_rdata in ds_rdata_list {
            ds_records.push(DNSRecord {
                name: name.clone(),
                class: DNSClass::IN,
                ttl: DEFAULT_TTL,
                data: DNSRecordData::DS(ds_rdata.clone()),
            });
        }
    }


    ds_records
}

pub fn generate_reverse_zones(record_files: &[RecordFile], dns_primary_master: &str, dns_responsible_person: &str) -> Vec<DNSZone> {
    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);


    let mut ipv4_zone = new_zone("in-addr.arpa", dns_primary_master.to_string(), dns_responsible_person.to_string(), serial);
    let mut ipv6_zone = new_zone("ip6.arpa", dns_primary_master.to_string(), dns_responsible_person.to_string(), serial);

    // Every zone should have at least one NS record pointing to the primary master
    ipv4_zone.add_record(DNSRecord {
        name: "in-addr.arpa".parse().unwrap(),
        class: DNSClass::IN,
        ttl: DEFAULT_TTL,
        data: DNSRecordData::NS(dns_primary_master.to_string()),
    }).unwrap();

    ipv6_zone.add_record(DNSRecord {
        name: "ip6.arpa".parse().unwrap(),
        class: DNSClass::IN,
        ttl: DEFAULT_TTL,
        data: DNSRecordData::NS(dns_primary_master.to_string()),
    }).unwrap();

    let mut ipv4_tree = PrefixTree::new();
    let mut ipv6_tree = PrefixTree::new();

    let mut cidr_to_nameservers: HashMap<Prefix, Vec<ExtractedNameServerInfo>> = HashMap::new();
    let mut cidr_to_ds_rdata: HashMap<Prefix, Vec<String>> = HashMap::new();

    for record_file in record_files {
        let extracted_info = match ExtractedNetworkInfo::try_from(record_file) {
            Ok(info) => info,
            Err(e) => {
                warn!("{}", e);
                continue;
            }
        };

        if !extracted_info.name_servers.is_empty() {
            cidr_to_nameservers.insert(extracted_info.cidr.clone(), extracted_info.name_servers.clone());
            cidr_to_ds_rdata.insert(extracted_info.cidr.clone(), extracted_info.ds_rdata.clone());

            match extracted_info.cidr.network() {
                IpAddr::V4(_) => {
                    ipv4_tree.insert(extracted_info.cidr.clone());
                }
                IpAddr::V6(_) => {
                    ipv6_tree.insert(extracted_info.cidr.clone());
                }
            }
        }
    }

    let mut counter = ReverseRecordCounter::default();

    ipv4_tree.visit_leaf(&mut |prefix| {
        let name_servers = cidr_to_nameservers.get(prefix).unwrap();
        let ds_rdata = cidr_to_ds_rdata.get(prefix).unwrap();

        for record in generate_reverse_records(prefix, name_servers, &mut counter) {
            if let Err(e) = ipv4_zone.add_record(record) {
                error!("Failed to add reverse record to IPv4 zone {}: {}", ipv4_zone.origin(), e);
            }
        }

        for record in generate_reverse_ds_record(prefix, ds_rdata) {
            if let Err(e) = ipv4_zone.add_record(record) {
                error!("Failed to add DS record to IPv4 zone {}: {}", ipv4_zone.origin(), e);
            }
        }
    });

    ipv6_tree.visit_leaf(&mut |prefix| {
        let name_servers = cidr_to_nameservers.get(prefix).unwrap();

        for record in generate_reverse_records(prefix, name_servers, &mut counter) {
            if let Err(e) = ipv6_zone.add_record(record) {
                error!("Failed to add reverse record to IPv6 zone {}: {}", ipv6_zone.origin(), e);
            }
        }

        for record in generate_reverse_ds_record(prefix, cidr_to_ds_rdata.get(prefix).unwrap()) {
            if let Err(e) = ipv6_zone.add_record(record) {
                error!("Failed to add DS record to IPv6 zone {}: {}", ipv6_zone.origin(), e);
            }
        }
    });

    info!("Generated {} IPv4 reverse records ({} aligned, {} non-aligned).", counter.ipv4_align + counter.ipv4_non_align, counter.ipv4_align, counter.ipv4_non_align);
    info!("Generated {} IPv6 reverse records ({} aligned). {} non-aligned not generated", counter.ipv6_align + counter.ipv6_non_align, counter.ipv6_align, counter.ipv6_non_align);

    vec![ipv4_zone, ipv6_zone]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_aligned_generation() {
        // Case: 192.0.2.0/24 (Standard Class C)
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap();

        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        // Expectation:
        // 1. Zone name: 2.0.192.in-addr.arpa
        // 2. Records: 1 NS record, 1 A record (glue)

        assert_eq!(counter.ipv4_align, 1);
        assert_eq!(counter.ipv4_non_align, 0);
        assert_eq!(records.len(), 2);

        // Verify NS Record
        let ns_record = &records[0];
        assert_eq!(ns_record.name.as_str(), "2.0.192.in-addr.arpa");
        if let DNSRecordData::NS(target) = &ns_record.data {
            assert_eq!(target, "ns1.example.com.");
        } else {
            panic!("Expected NS record");
        }

        // Verify Glue Record
        let glue_record = &records[1];
        assert_eq!(glue_record.name.as_str(), "2.0.192.in-addr.arpa");
        if let DNSRecordData::A(ip) = &glue_record.data {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_ipv6_aligned_generation() {
        // Case: 2001:db8::/32
        // Hex: 2001 0db8 ...
        // Nibbles: 2.0.0.1.0.d.b.8
        // Reversed: 8.b.d.0.1.0.0.2
        let prefix = Prefix::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), 32).unwrap();

        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv6_align, 1);
        assert_eq!(records.len(), 1); // Only NS, no glue

        let record = &records[0];
        assert_eq!(record.name.as_str(), "8.b.d.0.1.0.0.2.ip6.arpa");
    }

    #[test]
    fn test_ipv4_non_aligned_rfc2317() {
        // Case: 192.0.2.0/25 (Classless)
        // This splits the /24 into two /25s. We are generating for the lower half.
        // Base: 2.0.192.in-addr.arpa
        // Range: 0-127

        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 25).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.child.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);

        // /25 contains 128 hosts.
        // For each host, we expect 1 CNAME record
        // For the mapped zone, we expect 1 NS record.
        // Total = 128 CNAME + 1 NS = 129 records
        assert_eq!(records.len(), 129);

        // Check the first host (IP: 192.0.2.0)
        // The Record Name (Reverse IP) should be: 0.2.0.192.in-addr.arpa
        let ptr_name_0 = "0.2.0.192.in-addr.arpa";

        // Find CNAME for host 0
        let cname_rec = records.iter().find(|r| r.name.as_str() == ptr_name_0 && matches!(r.data, DNSRecordData::CNAME(_)));
        assert!(cname_rec.is_some(), "CNAME record for host 0 missing");

        if let Some(rec) = cname_rec {
            if let DNSRecordData::CNAME(target) = &rec.data {
                assert_eq!(target, "0.0/25.2.0.192.in-addr.arpa", "RFC2317 CNAME target format is incorrect");
            }
        }
    }

    #[test]
    fn test_ipv4_aligned_prefix_8() {
        // Test /8 network: 10.0.0.0/8 -> 10.in-addr.arpa
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_align, 1);
        assert_eq!(records.len(), 1); // Only NS record
        assert_eq!(records[0].name.as_str(), "10.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_aligned_prefix_16() {
        // Test /16 network: 172.16.0.0/16 -> 16.172.in-addr.arpa
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 16).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_align, 1);
        assert_eq!(records.len(), 2); // NS + A glue
        assert_eq!(records[0].name.as_str(), "16.172.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_aligned_prefix_32() {
        // Edge case: /32 single host - should still work as aligned
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_align, 1);
        assert_eq!(records[0].name.as_str(), "1.2.0.192.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_non_aligned_upper_half() {
        // Critical test: Upper half of /24 split
        // 192.0.2.128/25 should generate CNAMEs for 128-255, NOT 0-127
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 128)), 25).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);
        assert_eq!(records.len(), 129); // 128 CNAMEs + 1 NS

        // Check first host should be 128, not 0
        let first_cname = records.iter()
            .find(|r| r.name.as_str() == "128.2.0.192.in-addr.arpa")
            .expect("CNAME for 192.0.2.128 (first IP in range) should exist");

        if let DNSRecordData::CNAME(target) = &first_cname.data {
            // Bug check: target should reference the network base (128), not relative offset
            assert_eq!(target, "128.128/25.2.0.192.in-addr.arpa",
                       "CNAME target should use network base address in CIDR part");
        } else {
            panic!("Expected CNAME record");
        }

        // Check last host should be 255
        let last_cname = records.iter()
            .find(|r| r.name.as_str() == "255.2.0.192.in-addr.arpa")
            .expect("CNAME for 192.0.2.255 (last IP in range) should exist");
        assert!(matches!(last_cname.data, DNSRecordData::CNAME(_)));

        // Ensure no CNAME for IPs outside the range (0-127)
        let invalid_cname = records.iter()
            .find(|r| r.name.as_str() == "0.2.0.192.in-addr.arpa" && matches!(r.data, DNSRecordData::CNAME(_)));
        assert!(invalid_cname.is_none(), "Should not generate CNAME for IP 192.0.2.0 which is outside 192.0.2.128/25");
    }

    #[test]
    fn test_ipv4_non_aligned_prefix_26() {
        // Test /26: 64 addresses
        // 192.0.2.64/26 covers 192.0.2.64 - 192.0.2.127
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 64)), 26).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);
        assert_eq!(records.len(), 65); // 64 CNAMEs + 1 NS

        // Verify first IP in range
        let first_cname = records.iter()
            .find(|r| r.name.as_str() == "64.2.0.192.in-addr.arpa");
        assert!(first_cname.is_some(), "Should have CNAME for first IP (64)");

        // Verify last IP in range
        let last_cname = records.iter()
            .find(|r| r.name.as_str() == "127.2.0.192.in-addr.arpa");
        assert!(last_cname.is_some(), "Should have CNAME for last IP (127)");

        // Verify NS record zone name
        let ns_record = records.iter()
            .find(|r| matches!(r.data, DNSRecordData::NS(_)))
            .expect("Should have NS record");
        assert_eq!(ns_record.name.as_str(), "64/26.2.0.192.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_non_aligned_prefix_27() {
        // Test /27: 32 addresses
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 96)), 27).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);
        assert_eq!(records.len(), 33); // 32 CNAMEs + 1 NS
    }

    #[test]
    fn test_ipv4_non_aligned_prefix_28() {
        // Test /28: 16 addresses
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 16)), 28).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);
        assert_eq!(records.len(), 17); // 16 CNAMEs + 1 NS
    }

    #[test]
    fn test_ipv4_non_aligned_prefix_29() {
        // Test /29: 8 addresses (common for small allocations)
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)), 29).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);
        assert_eq!(records.len(), 9); // 8 CNAMEs + 1 NS
    }

    #[test]
    fn test_ipv4_non_aligned_prefix_30() {
        // Test /30: 4 addresses (common for point-to-point links)
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)), 30).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);
        assert_eq!(records.len(), 5); // 4 CNAMEs + 1 NS
    }

    #[test]
    fn test_ipv4_non_aligned_prefix_31() {
        // Test /31: 2 addresses (RFC 3021 point-to-point)
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 31).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);
        assert_eq!(records.len(), 3); // 2 CNAMEs + 1 NS
    }

    #[test]
    fn test_ipv4_non_aligned_prefix_17() {
        // Test /17: larger non-octet-aligned network
        // 172.16.0.0/17 covers 172.16.0.0 - 172.16.127.255
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 17).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_non_align, 1);
        // For /17, we have 16 full octets (2), remaining 1 bit
        // So we generate 128 delegations (0-127 for the third octet)
        assert_eq!(records.len(), 129); // 128 CNAMEs + 1 NS
    }

    #[test]
    fn test_multiple_nameservers_with_mixed_glue() {
        // Test with multiple nameservers, some with glue, some without
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            },
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns2.example.com.").unwrap(),
                name_server_ip: None,
            },
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns3.example.com.").unwrap(),
                name_server_ip: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            },
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_align, 1);
        // 3 NS records + 1 A glue + 1 AAAA glue = 5 records
        assert_eq!(records.len(), 5);

        // Count record types
        let ns_count = records.iter().filter(|r| matches!(r.data, DNSRecordData::NS(_))).count();
        let a_count = records.iter().filter(|r| matches!(r.data, DNSRecordData::A(_))).count();
        let aaaa_count = records.iter().filter(|r| matches!(r.data, DNSRecordData::AAAA(_))).count();

        assert_eq!(ns_count, 3, "Should have 3 NS records");
        assert_eq!(a_count, 1, "Should have 1 A glue record");
        assert_eq!(aaaa_count, 1, "Should have 1 AAAA glue record");
    }

    #[test]
    fn test_empty_nameserver_list() {
        // Edge case: no nameservers provided
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap();
        let ns_info = vec![];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv4_align, 1);
        assert_eq!(records.len(), 0, "Should generate no records with empty nameserver list");
    }

    #[test]
    fn test_ipv6_aligned_prefix_48() {
        // Test /48 - common site prefix
        // 2001:db8:1234::/48
        let prefix = Prefix::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0)), 48).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv6_align, 1);
        assert_eq!(records.len(), 1);
        // 2001:0db8:1234 -> nibbles: 2.0.0.1.0.d.b.8.1.2.3.4
        // Reversed: 4.3.2.1.8.b.d.0.1.0.0.2
        assert_eq!(records[0].name.as_str(), "4.3.2.1.8.b.d.0.1.0.0.2.ip6.arpa");
    }

    #[test]
    fn test_ipv6_aligned_prefix_64() {
        // Test /64 - common subnet prefix
        // 2001:db8:abcd:ef01::/64
        let prefix = Prefix::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0xef01, 0, 0, 0, 0)), 64).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0xef01, 0, 0, 0, 1))),
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv6_align, 1);
        assert_eq!(records.len(), 2); // NS + AAAA glue
        // 16 nibbles for /64
        assert_eq!(records[0].name.as_str(), "1.0.f.e.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa");
    }

    #[test]
    fn test_ipv6_aligned_prefix_128() {
        // Edge case: /128 single address
        let prefix = Prefix::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 128).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns1.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        assert_eq!(counter.ipv6_align, 1);
        assert_eq!(records.len(), 1);
        // Full 32 nibbles
        assert_eq!(records[0].name.as_str(), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
    }

    #[test]
    fn test_cname_target_format_consistency() {
        // Verify CNAME target format follows RFC 2317 conventions
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 192)), 26).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        // Find any CNAME record
        let cname_rec = records.iter()
            .find(|r| matches!(r.data, DNSRecordData::CNAME(_)))
            .expect("Should have at least one CNAME");

        if let DNSRecordData::CNAME(target) = &cname_rec.data {
            // Target should contain the CIDR notation
            assert!(target.contains("/26"), "CNAME target should contain prefix length");
            assert!(target.contains("192/26"), "CNAME target should contain network base address");
            assert!(target.ends_with(".in-addr.arpa"), "CNAME target should end with .in-addr.arpa");
        }
    }

    #[test]
    fn test_counter_increments() {
        // Verify counters are correctly incremented for different scenarios
        let mut counter = ReverseRecordCounter::default();

        // IPv4 aligned
        let prefix1 = Prefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap();
        generate_reverse_records(&prefix1, &[], &mut counter);

        // IPv4 non-aligned
        let prefix2 = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 25).unwrap();
        generate_reverse_records(&prefix2, &[], &mut counter);

        // IPv6 aligned
        let prefix3 = Prefix::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), 32).unwrap();
        generate_reverse_records(&prefix3, &[], &mut counter);

        // IPv6 non-aligned
        let prefix4 = Prefix::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), 37).unwrap();
        generate_reverse_records(&prefix4, &[], &mut counter);

        assert_eq!(counter.ipv4_align, 1);
        assert_eq!(counter.ipv4_non_align, 1);
        assert_eq!(counter.ipv6_align, 1);
        assert_eq!(counter.ipv6_non_align, 1);
    }

    #[test]
    fn test_ipv4_non_aligned_boundary_addresses() {
        // Test that first and last addresses in range have correct CNAMEs
        // Using 192.0.2.240/28 (range: 240-255)
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 240)), 28).unwrap();
        let ns_info = vec![
            ExtractedNameServerInfo {
                name_server: FQDNName::new("ns.example.com.").unwrap(),
                name_server_ip: None,
            }
        ];

        let mut counter = ReverseRecordCounter::default();
        let records = generate_reverse_records(&prefix, &ns_info, &mut counter);

        // Check first address (240)
        let first = records.iter()
            .find(|r| r.name.as_str() == "240.2.0.192.in-addr.arpa" && matches!(r.data, DNSRecordData::CNAME(_)))
            .expect("Should have CNAME for first IP in range (240)");

        if let DNSRecordData::CNAME(target) = &first.data {
            assert_eq!(target, "240.240/28.2.0.192.in-addr.arpa");
        }

        // Check last address (255)
        let last = records.iter()
            .find(|r| r.name.as_str() == "255.2.0.192.in-addr.arpa" && matches!(r.data, DNSRecordData::CNAME(_)))
            .expect("Should have CNAME for last IP in range (255)");

        if let DNSRecordData::CNAME(target) = &last.data {
            assert_eq!(target, "255.240/28.2.0.192.in-addr.arpa");
        }

        // Ensure no CNAME for address just before range (239)
        let before = records.iter()
            .find(|r| r.name.as_str() == "239.2.0.192.in-addr.arpa");
        assert!(before.is_none(), "Should not have CNAME for IP outside range");
    }
}