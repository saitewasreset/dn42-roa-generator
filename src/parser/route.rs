use crate::model::output::{Metadata, RpkiClientOutput};
use crate::model::record::{Prefix, RecordField, RecordFile};
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
                    None => prefix.prefix_len(),
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