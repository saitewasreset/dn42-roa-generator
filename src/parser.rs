use std::str::FromStr;
use crate::model::output::{Metadata, RpkiClientOutput};
use crate::model::record::{Prefix, RecordField, RecordFile};

pub fn get_parsed_roa_routes(record_files: &[RecordFile]) -> RpkiClientOutput {
    let mut roas = Vec::with_capacity(record_files.len());
    for record_file in record_files {

        let asn_str = record_file.get_field(RecordField::Origin);
        let route_str = record_file.get_field(RecordField::Route);
        let route6_str = record_file.get_field(RecordField::Route6);
        let max_length_str = record_file.get_field(RecordField::MaxLength);

        let route_str = match (route_str, route6_str) {
            (Some(r), _) => Some(r),
            (_, Some(r6)) => Some(r6),
            _ => None,
        };

        if let (Some(asn_str), Some(route_str)) =
            (asn_str, route_str)
        {
            if let Ok(prefix) = Prefix::from_str(route_str) {
                let max_length = match max_length_str {
                    Some(max_length_str) => {
                        match max_length_str.parse::<u8>() {
                            Ok(length) => length,
                            Err(_) => continue,
                        }
                    }
                    None => prefix.prefix_len,
                };

                if let Some((_, number_part)) = asn_str.split_once("AS") {
                    if let Ok(asn) = number_part.parse::<u32>() {
                        let roa = crate::model::output::ROA {
                            asn,
                            prefix: route_str.to_string(),
                            max_length,
                        };
                        roas.push(roa);
                    } else {
                        println!("Invalid ASN {:?} in record: {:?}", asn_str, record_file.get_file_path());
                    }
                } else {
                    println!("Invalid ASN {:?} in record: {:?}", asn_str, record_file.get_file_path());
                }
            } else {
                println!("Invalid prefix {:?} in record: {:?}", route_str, record_file.get_file_path());
            }
        } else {
            println!("Missing required fields in record: {:?}", record_file.get_file_path());
        }
    }

    let metadata = Metadata {
        build_time: chrono::Utc::now().to_rfc3339(),
        counts: roas.len() as u64,
        roas: roas.len() as u64,
    };

    RpkiClientOutput { metadata, roas  }
}