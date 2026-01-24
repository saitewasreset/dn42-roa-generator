use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use strum::{Display, EnumString};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prefix {
    network: IpAddr,
    prefix_len: u8,
}

fn octets_to_bits(octets: &[u8], prefix_len: u8) -> Vec<u8> {
    let mut bits = Vec::new();
    let total_bits = prefix_len as usize;

    for &octet in octets {
        for i in (0..8).rev() {
            if bits.len() < total_bits {
                bits.push((octet >> i) & 1);
            } else {
                break;
            }
        }
    }

    bits
}

fn bits_to_octets(bits: &[u8]) -> Vec<u8> {
    let mut octets = Vec::new();
    let mut current_octet = 0u8;

    for (i, bit) in bits.iter().enumerate() {
        current_octet = (current_octet << 1) | bit;

        if (i + 1) % 8 == 0 {
            octets.push(current_octet);
            current_octet = 0;
        }
    }

    if bits.len() % 8 != 0 {
        current_octet <<= 8 - (bits.len() % 8);
        octets.push(current_octet);
    }

    octets
}

fn vec_to_slice_zero_fill<const N: usize>(vec: &Vec<u8>) -> [u8; N] {
    let mut slice: [u8; N] = [0u8; N];
    for (i, &octet) in vec.iter().enumerate().take(N) {
        slice[i] = octet;
    }
    slice
}

impl Prefix {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, String> {
        let network = match network {
            IpAddr::V4(ipv4) => {
                if prefix_len > 32 {
                    return Err(format!("Invalid prefix length for IPv4: {}", prefix_len));
                }

                IpAddr::V4(Ipv4Addr::from(vec_to_slice_zero_fill(&bits_to_octets(&octets_to_bits(&ipv4.octets(), prefix_len)))))
            }
            IpAddr::V6(ipv6) => {
                if prefix_len > 128 {
                    return Err(format!("Invalid prefix length for IPv6: {}", prefix_len));
                }

                IpAddr::V6(Ipv6Addr::from(vec_to_slice_zero_fill(&bits_to_octets(&octets_to_bits(&ipv6.octets(), prefix_len)))))
            }
        };

        Ok(Prefix {
            network,
            prefix_len,
        })
    }

    pub fn with_prefix_len(&self, new_prefix_len: u8) -> Self {
        let mut bits = self.get_bits();

        bits.truncate(new_prefix_len as usize);

        let octets = bits_to_octets(&bits);

        let network = match self.network {
            IpAddr::V4(_) => {
                let octets: [u8; 4] = vec_to_slice_zero_fill(&octets);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            IpAddr::V6(_) => {
                let octets = vec_to_slice_zero_fill(&octets);
                IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
        };

        Prefix {
            network,
            prefix_len: new_prefix_len,
        }
    }

    pub fn from_bits_v4(bits: &[u8]) -> Option<Self> {
        if bits.len() > 32 {
            return None;
        }

        let octets = bits_to_octets(bits);

        let octets: [u8; 4] = vec_to_slice_zero_fill(&octets);

        Some(Prefix {
            network: IpAddr::V4(Ipv4Addr::from(octets)),
            prefix_len: bits.len() as u8,
        })
    }

    pub fn from_bits_v6(bits: &[u8]) -> Option<Self> {
        if bits.len() > 128 {
            return None;
        }

        let octets = bits_to_octets(bits);

        let octets = vec_to_slice_zero_fill(&octets);

        Some(Prefix {
            network: IpAddr::V6(std::net::Ipv6Addr::from(octets)),
            prefix_len: bits.len() as u8,
        })
    }

    pub fn get_bits(&self) -> Vec<u8> {
        let to_bits = |octets: &[u8]| octets
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
            .take(self.prefix_len as usize)
            .collect::<Vec<u8>>();

        match self.network {
            IpAddr::V4(addr) => to_bits(&addr.octets()),
            IpAddr::V6(addr) => to_bits(&addr.octets()),
        }
    }

    pub fn network(&self) -> &IpAddr {
        &self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
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

        match network {
            IpAddr::V4(_) if prefix_len > 32 => {
                return Err(format!("Invalid prefix length for IPv4: {}", prefix_len));
            }
            IpAddr::V6(_) if prefix_len > 128 => {
                return Err(format!("Invalid prefix length for IPv6: {}", prefix_len));
            }
            _ => {}
        }

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

    // Inetnum
    #[strum(serialize = "cidr")]
    Cidr,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_bits_to_octets() {
        // 192 (11000000)
        let bits = vec![1, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(bits_to_octets(&bits), vec![192]);

        // 192.168 (16 bits)
        let mut bits = vec![1, 1, 0, 0, 0, 0, 0, 0]; // 192
        bits.extend_from_slice(&[1, 0, 1, 0, 1, 0, 0, 0]); // 168
        assert_eq!(bits_to_octets(&bits), vec![192, 168]);

        // 1 -> 10000000 (128)
        let bits = vec![1];
        assert_eq!(bits_to_octets(&bits), vec![128]);
    }

    #[test]
    fn test_from_str_v4() {
        let p: Prefix = "192.168.1.1/24".parse().unwrap();
        assert_eq!(p.network, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(p.prefix_len, 24);
    }

    #[test]
    fn test_from_str_v6() {
        let p: Prefix = "2001:db8::1/64".parse().unwrap();
        assert_eq!(p.network, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(p.prefix_len, 64);
    }

    #[test]
    fn test_from_str_invalid() {
        assert!("192.168.1.1".parse::<Prefix>().is_err()); // Missing network length
        assert!("999.999.999.999/24".parse::<Prefix>().is_err()); // Invalid IP
        assert!("192.168.1.1/abc".parse::<Prefix>().is_err()); // Non-numeric length
        assert!("192.168.1.1/33".parse::<Prefix>().is_err()); // Invalid IPv4 length
        assert!("::1/129".parse::<Prefix>().is_err()); // Invalid IPv6 length
    }

    #[test]
    fn test_get_bits() {
        let p: Prefix = "192.0.0.0/8".parse().unwrap();
        // 192 = 11000000
        let bits = p.get_bits();
        assert_eq!(bits, vec![1, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bits.len(), 8);

        let p2: Prefix = "255.255.0.0/10".parse().unwrap();
        let bits2 = p2.get_bits();
        assert_eq!(bits2, vec![1; 10]);
    }

    #[test]
    fn test_with_prefix_len_shrinking() {
        let p: Prefix = "192.168.1.1/24".parse().unwrap();
        let new_p = p.with_prefix_len(16);

        assert_eq!(new_p.prefix_len, 16);
        assert_eq!(new_p.network, "192.168.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_with_prefix_len_expanding() {
        let p: Prefix = "192.168.0.0/16".parse().unwrap();
        let new_p = p.with_prefix_len(24);

        assert_eq!(new_p.prefix_len, 24);
        assert_eq!(new_p.network, "192.168.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_from_bits_v4() {
        let bits = vec![0, 0, 0, 0, 1, 0, 1, 0];
        let p = Prefix::from_bits_v4(&bits).unwrap();

        assert_eq!(p.prefix_len, 8);
        assert_eq!(p.network, "10.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_from_bits_v6() {
        let p = Prefix::from_bits_v6(&[]).unwrap();
        assert_eq!(p.prefix_len, 0);
        assert_eq!(p.network, "::".parse::<IpAddr>().unwrap());

        let bits = vec![1; 16];
        let p = Prefix::from_bits_v6(&bits).unwrap();
        assert_eq!(p.prefix_len, 16);
        assert_eq!(p.network, "ffff::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_display() {
        let p: Prefix = "10.10.10.10/32".parse().unwrap();
        assert_eq!(format!("{}", p), "10.10.10.10/32");
    }

    #[test]
    fn test_bits_to_octets_empty() {
        let bits = vec![];

        let octets = bits_to_octets(&bits);

        assert_eq!(octets.len(), 0);
    }

    #[test]
    fn test_bits_to_octets_various_lengths() {
        // 2 bits: 11 -> 11000000 (192)
        assert_eq!(bits_to_octets(&[1, 1]), vec![192]);

        // 3 bits: 101 -> 10100000 (160)
        assert_eq!(bits_to_octets(&[1, 0, 1]), vec![160]);

        // 4 bits: 1111 -> 11110000 (240)
        assert_eq!(bits_to_octets(&[1, 1, 1, 1]), vec![240]);

        // 5 bits: 10101 -> 10101000 (168)
        assert_eq!(bits_to_octets(&[1, 0, 1, 0, 1]), vec![168]);

        // 9 bits: 11111111 1 -> 11111111 10000000 (255, 128)
        let bits = vec![1, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(bits_to_octets(&bits), vec![255, 128]);

        // 17 bits
        let bits = vec![1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1];
        // 11000000 10101000 1 -> 192, 168, 128
        assert_eq!(bits_to_octets(&bits), vec![192, 168, 128]);
    }

    #[test]
    fn test_from_bits_v4_empty() {
        let p = Prefix::from_bits_v4(&[]).unwrap();
        assert_eq!(p.prefix_len, 0);
        assert_eq!(p.network, "0.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_from_bits_v4_exact_32_bits() {
        let bits = vec![1; 32];
        let p = Prefix::from_bits_v4(&bits).unwrap();
        assert_eq!(p.prefix_len, 32);
        assert_eq!(p.network, "255.255.255.255".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_from_bits_v4_exceeds_limit() {
        let bits = vec![1; 33];
        assert!(Prefix::from_bits_v4(&bits).is_none());
    }

    #[test]
    fn test_from_bits_v4_non_octet_boundary() {
        // 12 bits: 11000000 1010 -> 192.160.0.0/12
        let bits = vec![1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0];
        let p = Prefix::from_bits_v4(&bits).unwrap();
        assert_eq!(p.prefix_len, 12);
        assert_eq!(p.network, "192.160.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_from_bits_v4_single_bit() {
        let bits = vec![1];
        let p = Prefix::from_bits_v4(&bits).unwrap();
        assert_eq!(p.prefix_len, 1);
        assert_eq!(p.network, "128.0.0.0".parse::<IpAddr>().unwrap());

        let bits = vec![0];
        let p = Prefix::from_bits_v4(&bits).unwrap();
        assert_eq!(p.prefix_len, 1);
        assert_eq!(p.network, "0.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_from_bits_v6_exact_128_bits() {
        let bits = vec![1; 128];
        let p = Prefix::from_bits_v6(&bits).unwrap();
        assert_eq!(p.prefix_len, 128);
        assert_eq!(p.network, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_from_bits_v6_exceeds_limit() {
        let bits = vec![1; 129];
        assert!(Prefix::from_bits_v6(&bits).is_none());
    }

    #[test]
    fn test_from_bits_v6_non_octet_boundary() {
        // 12 bits: 0010 0000 0001 -> 2010::/12
        let bits = vec![0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let p = Prefix::from_bits_v6(&bits).unwrap();
        assert_eq!(p.prefix_len, 12);
        // 0010 0000 0001 0000 (padding) -> 0x2010 -> 2010::
        assert_eq!(p.network, "2010::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_from_bits_v6_64_bits() {
        let bits = vec![0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // 2001
                        0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, // 0db8
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0000
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 0000
        let p = Prefix::from_bits_v6(&bits).unwrap();
        assert_eq!(p.prefix_len, 64);
        assert_eq!(p.network, "2001:db8::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_with_prefix_len_to_zero() {
        let p: Prefix = "192.168.1.1/24".parse().unwrap();
        let new_p = p.with_prefix_len(0);

        assert_eq!(new_p.prefix_len, 0);
        assert_eq!(new_p.network, "0.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_with_prefix_len_to_max_v4() {
        let p: Prefix = "192.168.1.0/24".parse().unwrap();
        let new_p = p.with_prefix_len(32);

        assert_eq!(new_p.prefix_len, 32);
        assert_eq!(new_p.network, "192.168.1.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_with_prefix_len_same_length() {
        let p: Prefix = "192.168.1.0/24".parse().unwrap();
        let new_p = p.with_prefix_len(24);

        assert_eq!(new_p.prefix_len, 24);
        assert_eq!(new_p.network, "192.168.1.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_with_prefix_len_v6_shrinking() {
        let p: Prefix = "2001:db8:abcd:ef01::/64".parse().unwrap();
        let new_p = p.with_prefix_len(48);

        assert_eq!(new_p.prefix_len, 48);
        assert_eq!(new_p.network, "2001:db8:abcd::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_with_prefix_len_v6_expanding() {
        let p: Prefix = "2001:db8::/32".parse().unwrap();
        let new_p = p.with_prefix_len(64);

        assert_eq!(new_p.prefix_len, 64);
        assert_eq!(new_p.network, "2001:db8::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_with_prefix_len_v6_to_max() {
        let p: Prefix = "2001:db8::1/64".parse().unwrap();
        let new_p = p.with_prefix_len(128);

        assert_eq!(new_p.prefix_len, 128);
        assert_eq!(new_p.network, "2001:db8::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_with_prefix_len_non_octet_boundaries() {
        // Test various non-8-multiple boundaries
        let p: Prefix = "255.255.255.255/32".parse().unwrap();

        let p7 = p.with_prefix_len(7);
        assert_eq!(p7.network, "254.0.0.0".parse::<IpAddr>().unwrap());

        let p9 = p.with_prefix_len(9);
        assert_eq!(p9.network, "255.128.0.0".parse::<IpAddr>().unwrap());

        let p17 = p.with_prefix_len(17);
        assert_eq!(p17.network, "255.255.128.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_get_bits_zero_length() {
        let p: Prefix = "192.168.1.1/0".parse().unwrap();
        let bits = p.get_bits();
        assert_eq!(bits.len(), 0);
    }

    #[test]
    fn test_get_bits_max_length_v4() {
        let p: Prefix = "255.255.255.255/32".parse().unwrap();
        let bits = p.get_bits();
        assert_eq!(bits.len(), 32);
        assert_eq!(bits, vec![1; 32]);
    }

    #[test]
    fn test_get_bits_max_length_v6() {
        let p: Prefix = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".parse().unwrap();
        let bits = p.get_bits();
        assert_eq!(bits.len(), 128);
        assert_eq!(bits, vec![1; 128]);
    }

    #[test]
    fn test_get_bits_v6_partial() {
        let p: Prefix = "2001:db8::/32".parse().unwrap();
        let bits = p.get_bits();
        assert_eq!(bits.len(), 32);
        // 2001 = 0010 0000 0000 0001
        // 0db8 = 0000 1101 1011 1000
        let expected = vec![
            0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0,
        ];
        assert_eq!(bits, expected);
    }

    #[test]
    fn test_get_bits_pattern_recognition() {
        let p: Prefix = "170.170.0.0/16".parse().unwrap();
        let bits = p.get_bits();
        // 170 = 10101010
        assert_eq!(bits, vec![1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0]);
    }

    #[test]
    fn test_roundtrip_from_bits_get_bits_v4() {
        let original_bits = vec![1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0];
        let p = Prefix::from_bits_v4(&original_bits).unwrap();
        let retrieved_bits = p.get_bits();

        assert_eq!(original_bits, retrieved_bits);
    }

    #[test]
    fn test_roundtrip_from_bits_get_bits_v6() {
        let original_bits = vec![0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let p = Prefix::from_bits_v6(&original_bits).unwrap();
        let retrieved_bits = p.get_bits();

        assert_eq!(original_bits, retrieved_bits);
    }

    #[test]
    fn test_roundtrip_with_prefix_len_get_bits() {
        let p: Prefix = "192.168.1.128/25".parse().unwrap();
        let new_p = p.with_prefix_len(24);
        let bits = new_p.get_bits();

        // Should have exactly 24 bits
        assert_eq!(bits.len(), 24);

        // Reconstruct and verify
        let reconstructed = Prefix::from_bits_v4(&bits).unwrap();
        assert_eq!(reconstructed.network, new_p.network);
        assert_eq!(reconstructed.prefix_len, new_p.prefix_len);
    }
    #[test]
    fn test_from_str_v4_boundary_values() {
        assert!("0.0.0.0/0".parse::<Prefix>().is_ok());
        assert!("255.255.255.255/32".parse::<Prefix>().is_ok());
        assert!("192.168.1.1/1".parse::<Prefix>().is_ok());
        assert!("192.168.1.1/31".parse::<Prefix>().is_ok());
    }

    #[test]
    fn test_from_str_v6_boundary_values() {
        assert!("::/0".parse::<Prefix>().is_ok());
        assert!("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".parse::<Prefix>().is_ok());
        assert!("2001:db8::1/1".parse::<Prefix>().is_ok());
        assert!("2001:db8::1/127".parse::<Prefix>().is_ok());
    }

    #[test]
    fn test_from_str_malformed() {
        assert!("/24".parse::<Prefix>().is_err());
        assert!("192.168.1.1/".parse::<Prefix>().is_err());
        assert!("192.168.1.1/24/32".parse::<Prefix>().is_err());
        assert!("".parse::<Prefix>().is_err());
        assert!("192.168.1.1/-1".parse::<Prefix>().is_err());
        assert!("192.168.1.1/256".parse::<Prefix>().is_err());
    }
    #[test]
    fn test_special_addresses() {
        // Loopback
        let p: Prefix = "127.0.0.1/8".parse().unwrap();
        assert_eq!(p.network, "127.0.0.1".parse::<IpAddr>().unwrap());

        // IPv6 loopback
        let p6: Prefix = "::1/128".parse().unwrap();
        assert_eq!(p6.network, "::1".parse::<IpAddr>().unwrap());

        // Unspecified
        let p_unspec: Prefix = "0.0.0.0/0".parse::<Prefix>().unwrap();
        assert_eq!(p_unspec.network, "0.0.0.0".parse::<IpAddr>().unwrap());

        // IPv6 unspecified
        let p6_unspec: Prefix = "::/0".parse::<Prefix>().unwrap();
        assert_eq!(p6_unspec.network, "::".parse::<IpAddr>().unwrap());
    }
    #[test]
    fn test_display_v6() {
        let p: Prefix = "2001:db8::1/64".parse().unwrap();
        assert_eq!(format!("{}", p), "2001:db8::1/64");

        let p2: Prefix = "::/0".parse().unwrap();
        assert_eq!(format!("{}", p2), "::/0");
    }

    #[test]
    fn test_display_various_lengths() {
        assert_eq!(format!("{}", "192.168.0.0/0".parse::<Prefix>().unwrap()), "192.168.0.0/0");
        assert_eq!(format!("{}", "192.168.0.0/16".parse::<Prefix>().unwrap()), "192.168.0.0/16");
        assert_eq!(format!("{}", "10.0.0.0/8".parse::<Prefix>().unwrap()), "10.0.0.0/8");
    }

    #[test]
    fn test_complex_workflow() {
        // Parse -> modify -> get bits -> reconstruct
        let p1: Prefix = "192.168.128.0/17".parse().unwrap();
        let p2 = p1.with_prefix_len(20);
        let bits = p2.get_bits();
        let p3 = Prefix::from_bits_v4(&bits).unwrap();

        assert_eq!(p2, p3);
        assert_eq!(p3.prefix_len, 20);
    }

    #[test]
    fn test_prefix_len_expansion_preserves_zeros() {
        let p: Prefix = "192.168.0.0/16".parse().unwrap();
        let expanded = p.with_prefix_len(24);

        // Expansion should add zeros
        assert_eq!(expanded.network, "192.168.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(expanded.prefix_len, 24);

        let bits = expanded.get_bits();
        // Last 8 bits should be 0
        assert_eq!(&bits[16..24], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_all_zeros_all_ones() {
        // All zeros
        let p_zeros = Prefix::from_bits_v4(&vec![0; 24]).unwrap();
        assert_eq!(p_zeros.network, "0.0.0.0".parse::<IpAddr>().unwrap());

        // All ones
        let p_ones = Prefix::from_bits_v4(&vec![1; 24]).unwrap();
        assert_eq!(p_ones.network, "255.255.255.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_alternating_bits() {
        // 10101010 (170)
        let bits = vec![1, 0, 1, 0, 1, 0, 1, 0];
        let p = Prefix::from_bits_v4(&bits).unwrap();
        assert_eq!(p.network, "170.0.0.0".parse::<IpAddr>().unwrap());

        // 01010101 (85)
        let bits2 = vec![0, 1, 0, 1, 0, 1, 0, 1];
        let p2 = Prefix::from_bits_v4(&bits2).unwrap();
        assert_eq!(p2.network, "85.0.0.0".parse::<IpAddr>().unwrap());
    }
}