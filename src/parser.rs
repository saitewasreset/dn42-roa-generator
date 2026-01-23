use crate::model::dns::{DNSClass, DNSRecord, DNSRecordData, DNSZone, FQDNName};
use crate::model::output::{Metadata, RpkiClientOutput};
use crate::model::record::{Prefix, RecordField, RecordFile};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{info, warn};

pub fn get_parsed_roa_routes(record_files: &[RecordFile]) -> RpkiClientOutput {
    let mut roas = Vec::with_capacity(record_files.len());
    for record_file in record_files {
        let asn_strs = record_file.get_field(RecordField::Origin);
        let route_strs = record_file.get_field(RecordField::Route);
        let route6_strs = record_file.get_field(RecordField::Route6);
        let max_length_strs = record_file.get_field(RecordField::MaxLength);

        let route_str = match (route_strs, route6_strs) {
            (Some(r), _) => Some(r),
            (_, Some(r6)) => Some(r6),
            _ => None,
        };

        if let (Some(asn_strs), Some(route_strs)) =
            (asn_strs, route_str)
        {
            if route_strs.len() != 1 {
                warn!("Multiple route fields in record: {:?}", record_file.get_file_path());
                continue;
            }

            let route_str = &route_strs[0];

            if let Ok(prefix) = Prefix::from_str(route_str) {
                let max_length = match max_length_strs {
                    Some(max_length_strs) => {
                        if max_length_strs.len() != 1 {
                            warn!("Multiple max-length fields in record: {:?}", record_file.get_file_path());
                            continue;
                        }
                        let max_length_str = &max_length_strs[0];

                        match max_length_str.parse::<u8>() {
                            Ok(length) => length,
                            Err(_) => continue,
                        }
                    }
                    None => prefix.prefix_len,
                };

                for asn_str in asn_strs {
                    if let Some((_, number_part)) = asn_str.split_once("AS") {
                        if let Ok(asn) = number_part.parse::<u32>() {
                            let roa = crate::model::output::ROA {
                                asn,
                                prefix: route_str.to_string(),
                                max_length,
                            };
                            roas.push(roa);
                        } else {
                            warn!("Invalid ASN {:?} in record: {:?}", asn_str, record_file.get_file_path());
                        }
                    } else {
                        warn!("Invalid ASN {:?} in record: {:?}", asn_str, record_file.get_file_path());
                    }
                }
            } else {
                warn!("Invalid prefix {:?} in record: {:?}", route_str, record_file.get_file_path());
            }
        } else {
            warn!("Missing required fields in record: {:?}", record_file.get_file_path());
        }
    }

    info!("Generated {} ROA entries.", roas.len());

    let metadata = Metadata {
        build_time: chrono::Utc::now().to_rfc3339(),
        counts: roas.len() as u64,
        roas: roas.len() as u64,
    };

    RpkiClientOutput { metadata, roas }
}

pub fn get_parsed_ns_records(record_files: &[RecordFile], dns_primary_master: &str, dns_responsible_person: &str) -> Vec<DNSZone> {
    // TODO: 处理registry-sync.dn42
    // TODO: 处理反向解析
    const DEFAULT_TTL: u32 = 3600;

    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

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

    let mut tld_to_zone: HashMap<String, DNSZone> = HashMap::new();

    for record_file in record_files {
        if let Some(domains) = record_file.get_field(RecordField::Domain) {
            if domains.len() != 1 {
                warn!("Multiple domain fields in record: {:?}", record_file.get_file_path());
                continue;
            }

            let domain = match FQDNName::from_str(&domains[0]) {
                Ok(fqdn) => fqdn,
                Err(e) => {
                    warn!("Invalid domain FQDN in record: {:?}, value: {:?}, error: {:?}", record_file.get_file_path(), domains[0], e);
                    continue;
                }
            };

            let tld = match domain.tld() {
                Some(label) => label.to_string(),
                None => {
                    warn!("Invalid domain with no labels in record: {:?}, value: {:?}", record_file.get_file_path(), domain);
                    continue;
                }
            };

            let zone = tld_to_zone.entry(tld.clone()).or_insert_with(|| new_zone(&tld, dns_primary_master.to_string(), dns_responsible_person.to_string(), serial));

            if let Some(nservers) = record_file.get_field(RecordField::NameServer) {
                // nserver:  ns1.burble.dn42 172.20.129.1
                // nserver:  ns1.lee.dn42
                for nserver in nservers {
                    let parts: Vec<&str> = nserver.split_whitespace().take(2).collect();

                    if parts.is_empty() || parts.len() > 2 {
                        warn!("Invalid nameserver format in record: {:?}, value: {:?}", record_file.get_file_path(), nserver);
                        continue;
                    }

                    let name_server = parts[0];

                    let name_server_ip = if parts.len() == 2 {
                        Some(parts[1])
                    } else {
                        None
                    };

                    let name_server = match FQDNName::from_str(name_server) {
                        Ok(fqdn) => fqdn,
                        Err(e) => {
                            warn!("Invalid nameserver FQDN in record: {:?}, value: {:?}, error: {:?}", record_file.get_file_path(), name_server, e);
                            continue;
                        }
                    };

                    let ns_record = DNSRecord {
                        name: domain.clone(),
                        class: DNSClass::IN,
                        ttl: DEFAULT_TTL,
                        data: DNSRecordData::NS(name_server.to_string()),
                    };

                    if let Err(e) = zone.add_record(ns_record) {
                        warn!("Failed to add DNS NS record from record: {:?}, error: {:?}", record_file.get_file_path(), e);
                    }

                    if let Some(name_server_ip) = name_server_ip {
                        let name_server_ip = match IpAddr::from_str(name_server_ip) {
                            Ok(ip) => ip,
                            Err(e) => {
                                warn!("Invalid nameserver IP in record: {:?}, value: {:?}, error: {:?}", record_file.get_file_path(), name_server_ip, e);
                                continue;
                            }
                        };

                        let record = match name_server_ip {
                            IpAddr::V4(ipv4) => {
                                DNSRecord {
                                    name: name_server,
                                    class: DNSClass::IN,
                                    ttl: DEFAULT_TTL,
                                    data: DNSRecordData::A(ipv4),
                                }
                            }
                            IpAddr::V6(ipv6) => {
                                DNSRecord {
                                    name: name_server,
                                    class: DNSClass::IN,
                                    ttl: DEFAULT_TTL,
                                    data: DNSRecordData::AAAA(ipv6),
                                }
                            }
                        };

                        if let Err(e) = zone.add_record(record) {
                            warn!("Failed to add DNS record from record: {:?}, error: {:?}", record_file.get_file_path(), e);
                        }
                    }
                }
            } else {
                warn!("Missing nameserver field in record: {:?}", record_file.get_file_path());
            }
        }
    }

    info!("Generated {} DNS forward zones.", tld_to_zone.values().map(|z| z.records().len()).sum::<usize>());

    tld_to_zone.into_values().collect()
}