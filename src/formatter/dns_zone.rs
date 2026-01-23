use crate::model::dns::{DNSRecord, DNSRecordData, DNSZone, FQDNName};
use std::collections::{HashMap, HashSet};
use tracing::error;

const DEFAULT_TTL: u32 = 3600;

const RECORD_NAME_COLUMN_MIN_WIDTH: usize = 5;
const RECORD_TTL_COLUMN_MIN_WIDTH: usize = 3;
const RECORD_CLASS_COLUMN_WIDTH: usize = 2;

const RECORD_TYPE_COLUMN_WIDTH: usize = 4;

fn calculate_default_ttl(zone: &DNSZone) -> u32 {
    // Use the most frequent TTL among the records as the default TTL

    let mut ttl_to_count = HashMap::new();

    for record in zone.records() {
        *ttl_to_count.entry(record.ttl).or_insert(0) += 1;
    }

    ttl_to_count.iter().map(|(ttl, count)| (count, ttl))
        .max_by(|(x_count, _), (y_count, _)| x_count.cmp(y_count))
        .map(|(_, &ttl)| ttl)
        .unwrap_or(DEFAULT_TTL) // Default to 3600 if no records
}

fn ensure_fqdn(name: &str) -> String {
    let name = name.replace("@", ".");

    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

fn generate_header(buffer: &mut String, ttl: u32, origin: &str) {
    buffer.push_str(format!("$TTL {}\n$ORIGIN {}\n", ttl, ensure_fqdn(origin)).as_str());
}

fn generate_soa_header(buffer: &mut String, soa: &DNSRecordData) {
    /*
    @         IN      SOA   ns1.example.com. hostmaster.example.com. (
                                2003080800 ; serial number
                                12h        ; refresh
                                15m        ; update retry
                                3w         ; expiry
                                2h         ; minimum
                                )
    */
    match soa {
        DNSRecordData::SOA {
            mname,   // Primary NS
            rname,   // Admin Email
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            buffer.push_str(format!("@ IN SOA {} {} (\n", ensure_fqdn(mname), ensure_fqdn(rname)).as_str());
            buffer.push_str(format!("                {} ; serial number\n", serial).as_str());
            buffer.push_str(format!("                {} ; refresh\n", refresh).as_str());
            buffer.push_str(format!("                {} ; update retry\n", retry).as_str());
            buffer.push_str(format!("                {} ; expiry\n", expire).as_str());
            buffer.push_str(format!("                {} ) ; minimum\n", minimum).as_str());
        }
        _ => panic!("Invalid SOA record data"),
    }

    buffer.push('\n');
}

fn generate_record_data(buffer: &mut String, data: &DNSRecordData) {
    match data {
        DNSRecordData::A(ipv4) => {
            buffer.push_str(format!("{}", ipv4).as_str());
        }
        DNSRecordData::AAAA(ipv6) => {
            buffer.push_str(format!("{}", ipv6).as_str());
        }
        DNSRecordData::CNAME(cname) => {
            buffer.push_str(&ensure_fqdn(cname));
        }
        DNSRecordData::MX { preference, exchange } => {
            buffer.push_str(format!("{} {}", preference, ensure_fqdn(exchange)).as_str());
        }
        DNSRecordData::TXT(txts) => {
            let txt_combined = txts.iter()
                .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                .collect::<Vec<String>>()
                .join(" ");
            buffer.push_str(txt_combined.as_str());
        }
        DNSRecordData::NS(ns) => {
            buffer.push_str(&ensure_fqdn(ns));
        }
        DNSRecordData::SOA { .. } => {
            // SOA is handled separately
            panic!("SOA record data should be handled separately");
        }
        DNSRecordData::PTR(ptr) => {
            buffer.push_str(&ensure_fqdn(ptr));
        }
        DNSRecordData::SRV { priority, weight, port, target } => {
            buffer.push_str(format!("{} {} {} {}", priority, weight, port, ensure_fqdn(target)).as_str());
        }
    }
}

fn generate_record_lines(buffer: &mut String, records: &HashSet<DNSRecord>, current_origin: FQDNName, default_ttl: u32) {
    // [Name] [TTL] [Class] [Type] [RDATA]

    /*
    ; Name Server (NS) records
    @           IN NS ns1.example.com.
    @           IN NS ns2.external-nameserver.net.

    ; Address (A and AAAA) records
    ns1         IN A     192.0.2.1
    mail        IN A     192.0.2.2
    www         IN AAAA  2001:db8::1

    ; Mail Exchanger (MX) records
    @           IN MX 10 mail.example.com.

    ; Canonical Name (CNAME) record
    ftp         IN CNAME www.example.com.

    ; Text (TXT) record
    @           IN TXT "v=spf1 include:_spf.example.com ~all"
    */

    let name_column_width = records
        .iter()
        .map(|r| r.name.relative_to(&current_origin))
        .map(|r|
            r
                .map(|r| r.len())
                .unwrap_or(0))
        .max()
        .unwrap_or(5)
        .max(RECORD_NAME_COLUMN_MIN_WIDTH);

    let ttl_column_width = records
        .iter()
        .map(|r| if r.ttl != default_ttl { r.ttl.to_string().len() } else { 0 })
        .max()
        .unwrap_or(3)
        .max(RECORD_TTL_COLUMN_MIN_WIDTH);

    let class_column_width = records
        .iter()
        .map(|r| r.class as usize)
        .max()
        .unwrap_or(2)
        .max(RECORD_CLASS_COLUMN_WIDTH);

    let type_column_width = records
        .iter()
        .map(|r| r.data.type_str().len())
        .max()
        .unwrap_or(4)
        .max(RECORD_TYPE_COLUMN_WIDTH);

    let mut records = records.iter().collect::<Vec<&DNSRecord>>();

    // Sort by Name, then by Type to group similar records together for better readability
    records.sort_by(|x, y| x
        .name
        .as_str()
        .cmp(&y.name.as_str())
        .then(
            x.data.type_str()
                .cmp(y.data.type_str())));

    for record in records {
        let relative_name = match record.name.relative_to(&current_origin) {
            Some(name) => name,
            None => {
                error!("Record name '{}' is not a child of zone origin '{}'", record.name, current_origin);
                continue;
            }
        };

        let name = format!("{:<width$}", relative_name, width = name_column_width);

        let ttl_str = if record.ttl != default_ttl {
            format!("{:<width$} ", record.ttl, width = ttl_column_width)
        } else {
            " ".repeat(ttl_column_width + 1)
        };

        let class_str = format!("{:<width$} ", format!("{:?}", record.class), width = class_column_width);
        let type_str = format!("{:<width$} ", record.data.type_str(), width = type_column_width);

        buffer.push_str(format!("{} {} {} {}",
                                name,
                                ttl_str,
                                class_str,
                                type_str
        ).as_str());

        generate_record_data(buffer, &record.data);

        buffer.push('\n');
    }
}

pub fn format_dns_zone(zone: &DNSZone) -> String {
    let mut buffer = String::new();

    let default_ttl = calculate_default_ttl(zone);

    generate_header(&mut buffer, default_ttl, zone.origin().as_str());
    generate_soa_header(&mut buffer, zone.soa());
    generate_record_lines(&mut buffer, zone.records(), zone.origin().clone(), default_ttl);

    buffer
}