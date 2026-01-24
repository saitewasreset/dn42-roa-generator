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

use crate::model::record::Prefix;
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
        // For reverse DNS, we also allow '/'.
        for &c in &chars {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '/' {
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

pub struct PrefixTree(Option<Box<PrefixNode>>);

impl PrefixTree {
    pub fn new() -> Self {
        PrefixTree(None)
    }

    pub fn insert(&mut self, prefix: Prefix) {
        let mut current_node = &mut self.0;

        let bits = prefix.get_bits();

        if current_node.is_none() {
            *current_node = Some(Box::new(PrefixNode {
                prefix: prefix.with_prefix_len(0),
                zero: None,
                one: None,
            }));
        }

        for (prefix_len, &bit) in bits.iter().enumerate() {
            let node = current_node.as_mut().unwrap();

            let next_node = if bit == 0 {
                &mut node.zero
            } else {
                &mut node.one
            };

            if next_node.is_none() {
                *next_node = Some(Box::new(PrefixNode {
                    prefix: prefix.with_prefix_len((prefix_len + 1) as u8),
                    zero: None,
                    one: None,
                }));
            }

            // Move down to the child
            current_node = next_node;
        }
    }

    fn visit_node<F>(&self, node: &Option<Box<PrefixNode>>, f: &mut F)
    where
        F: FnMut(&Prefix),
    {
        if let Some(n) = node {
            if n.zero.is_none() && n.one.is_none() {
                f(&n.prefix);
            } else {
                self.visit_node(&n.zero, f);
                self.visit_node(&n.one, f);
            }
        }
    }

    pub fn visit_leaf<F>(&self, f: &mut F)
    where
        F: FnMut(&Prefix),
    {
        self.visit_node(&self.0, f);
    }
}

struct PrefixNode {
    prefix: Prefix,
    zero: Option<Box<PrefixNode>>,
    one: Option<Box<PrefixNode>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::str::FromStr;

    // Helper to collect results from visit_leaf
    fn collect_leaves(tree: &PrefixTree) -> Vec<Prefix> {
        let mut results = Vec::new();
        tree.visit_leaf(&mut |p| results.push(p.clone()));
        results
    }


    #[test]
    fn test_insert_basic_ipv4() {
        let mut tree = PrefixTree::new();
        let p = Prefix::from_str("192.168.1.0/24").unwrap();

        tree.insert(p.clone());

        let leaves = collect_leaves(&tree);

        // Assert that we found exactly one leaf and it is the one we inserted.
        // If the implementation is buggy (off-by-one), this usually fails
        // because the node for /24 is never created, only up to /23.
        assert_eq!(leaves.len(), 1, "Should have exactly 1 leaf");
        assert_eq!(leaves[0], p, "The leaf should match the inserted prefix");
    }

    #[test]
    fn test_insert_basic_ipv6() {
        let mut tree = PrefixTree::new();
        let p = Prefix::from_str("2001:db8::/32").unwrap();

        tree.insert(p.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], p);
    }

    #[test]
    fn test_insert_branching() {
        let mut tree = PrefixTree::new();
        // 0.0.0.0/1 (starts with 0)
        let p1 = Prefix::from_str("0.0.0.0/1").unwrap();
        // 128.0.0.0/1 (starts with 1)
        let p2 = Prefix::from_str("128.0.0.0/1").unwrap();

        tree.insert(p1.clone());
        tree.insert(p2.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 2);

        let leaf_set: HashSet<Prefix> = leaves.into_iter().collect();
        assert!(leaf_set.contains(&p1));
        assert!(leaf_set.contains(&p2));
    }

    #[test]
    fn test_leaf_logic_nested() {
        // Test that verify_leaf only returns actual nodes with no children.
        // If we insert /24 and /25, /24 becomes an internal node,
        // so only /25 should be returned by visit_leaf.
        let mut tree = PrefixTree::new();
        let parent = Prefix::from_str("10.0.0.0/24").unwrap();
        let child = Prefix::from_str("10.0.0.0/25").unwrap();

        tree.insert(parent.clone());
        tree.insert(child.clone());

        let leaves = collect_leaves(&tree);

        assert_eq!(leaves.len(), 1, "Should only have 1 leaf (the most specific one)");
        assert_eq!(leaves[0], child, "The leaf should be the /25 prefix");
    }

    #[test]
    fn test_insert_root() {
        let mut tree = PrefixTree::new();
        let root_prefix = Prefix::from_str("0.0.0.0/0").unwrap();
        tree.insert(root_prefix.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], root_prefix);
    }

    #[test]
    fn test_multiple_branches() {
        let mut tree = PrefixTree::new();
        // 10.0.0.0/8
        let p1 = Prefix::from_str("10.0.0.0/8").unwrap();
        // 192.168.1.0/24
        let p2 = Prefix::from_str("192.168.1.0/24").unwrap();
        // 192.168.2.0/24
        let p3 = Prefix::from_str("192.168.2.0/24").unwrap();

        tree.insert(p1.clone());
        tree.insert(p2.clone());
        tree.insert(p3.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 3);

        let leaf_set: HashSet<Prefix> = leaves.into_iter().collect();
        assert!(leaf_set.contains(&p1));
        assert!(leaf_set.contains(&p2));
        assert!(leaf_set.contains(&p3));
    }

    #[test]
    fn test_ipv4_max_prefix_length() {
        // Test inserting a /32 prefix (maximum for IPv4)
        let mut tree = PrefixTree::new();
        let p = Prefix::from_str("192.168.1.1/32").unwrap();

        tree.insert(p.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], p);
    }

    #[test]
    fn test_ipv6_max_prefix_length() {
        // Test inserting a /128 prefix (maximum for IPv6)
        let mut tree = PrefixTree::new();
        let p = Prefix::from_str("2001:db8::1/128").unwrap();

        tree.insert(p.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], p);
    }

    #[test]
    fn test_empty_tree_visit_leaf() {
        // Ensure visit_leaf on an empty tree doesn't crash
        let tree = PrefixTree::new();
        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 0, "Empty tree should have no leaves");
    }

    #[test]
    fn test_insert_duplicate_prefix() {
        // Inserting the same prefix twice should still result in one leaf
        let mut tree = PrefixTree::new();
        let p = Prefix::from_str("10.0.0.0/16").unwrap();

        tree.insert(p.clone());
        tree.insert(p.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], p);
    }

    #[test]
    fn test_child_before_parent_insertion() {
        // Insert child first, then parent - parent should become internal node
        let mut tree = PrefixTree::new();
        let child = Prefix::from_str("192.168.1.128/25").unwrap();
        let parent = Prefix::from_str("192.168.1.0/24").unwrap();

        tree.insert(child.clone());
        tree.insert(parent.clone());

        let leaves = collect_leaves(&tree);
        // The /24 should become an internal node, only /25 should be a leaf
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], child);
    }

    #[test]
    fn test_deep_nesting() {
        // Test a deep chain of prefixes where each is more specific than the previous
        let mut tree = PrefixTree::new();
        let p1 = Prefix::from_str("10.0.0.0/8").unwrap();
        let p2 = Prefix::from_str("10.1.0.0/16").unwrap();
        let p3 = Prefix::from_str("10.1.1.0/24").unwrap();
        let p4 = Prefix::from_str("10.1.1.128/25").unwrap();

        tree.insert(p1.clone());
        tree.insert(p2.clone());
        tree.insert(p3.clone());
        tree.insert(p4.clone());

        let leaves = collect_leaves(&tree);
        // Only the most specific prefix should be a leaf
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], p4);
    }

    #[test]
    fn test_sibling_branches_different_depths() {
        // Test that siblings can have different depths
        let mut tree = PrefixTree::new();
        let p1 = Prefix::from_str("10.0.0.0/24").unwrap();    // Deep branch
        let p2 = Prefix::from_str("192.0.0.0/8").unwrap();    // Shallow branch

        tree.insert(p1.clone());
        tree.insert(p2.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 2);

        let leaf_set: HashSet<Prefix> = leaves.into_iter().collect();
        assert!(leaf_set.contains(&p1));
        assert!(leaf_set.contains(&p2));
    }


    #[test]
    fn test_multiple_prefixes_same_branch() {
        // Insert multiple prefixes along the same branch
        let mut tree = PrefixTree::new();
        let p1 = Prefix::from_str("10.0.0.0/8").unwrap();
        let p2 = Prefix::from_str("10.128.0.0/9").unwrap();  // Different second bit
        let p3 = Prefix::from_str("10.0.0.0/9").unwrap();    // Same as first 9 bits of p1

        tree.insert(p1.clone());
        tree.insert(p2.clone());
        tree.insert(p3.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 2, "Should have 2 leaves (two /9 prefixes)");

        let leaf_set: HashSet<Prefix> = leaves.into_iter().collect();
        assert!(leaf_set.contains(&p2));
        assert!(leaf_set.contains(&p3));
        assert!(!leaf_set.contains(&p1), "/8 should be internal node, not a leaf");
    }

    #[test]
    fn test_ipv6_various_lengths() {
        // Test IPv6 with various prefix lengths
        let mut tree = PrefixTree::new();
        let p32 = Prefix::from_str("2001:db8::/32").unwrap();
        let p48 = Prefix::from_str("2001:db8:1::/48").unwrap();
        let p64 = Prefix::from_str("2001:db8:1:2::/64").unwrap();

        tree.insert(p32.clone());
        tree.insert(p48.clone());
        tree.insert(p64.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], p64, "Most specific prefix should be the leaf");
    }

    #[test]
    fn test_complex_tree_structure() {
        // Build a more complex tree with multiple levels and branches
        let mut tree = PrefixTree::new();
        let prefixes = vec![
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.2.0.0/16",
            "10.1.1.0/24",
            "172.16.0.0/12",
            "172.16.1.0/24",
            "192.168.0.0/16",
            "192.168.1.0/24",
            "192.168.2.0/24",
        ];

        let parsed_prefixes: Vec<Prefix> = prefixes
            .iter()
            .map(|s| Prefix::from_str(s).unwrap())
            .collect();

        for p in &parsed_prefixes {
            tree.insert(p.clone());
        }

        let leaves = collect_leaves(&tree);
        // Count actual leaves (most specific prefixes with no more specific children):
        // 10.1.1.0/24, 10.2.0.0/16, 172.16.1.0/24, 192.168.1.0/24, 192.168.2.0/24
        assert_eq!(leaves.len(), 5);
    }

    #[test]
    fn test_single_bit_prefixes() {
        // Test with /1 prefixes (single bit differentiation)
        let mut tree = PrefixTree::new();
        let p_zero = Prefix::from_str("0.0.0.0/1").unwrap();
        let p_one = Prefix::from_str("128.0.0.0/1").unwrap();

        tree.insert(p_zero.clone());
        tree.insert(p_one.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 2);

        let leaf_set: HashSet<Prefix> = leaves.into_iter().collect();
        assert!(leaf_set.contains(&p_zero));
        assert!(leaf_set.contains(&p_one));
    }

    #[test]
    fn test_ipv6_compressed_notation() {
        // Test IPv6 with compressed notation (should be treated identically)
        let mut tree = PrefixTree::new();
        let p1 = Prefix::from_str("2001:db8::1/128").unwrap();
        let p2 = Prefix::from_str("2001:db8:0:0:0:0:0:1/128").unwrap();

        // These should be the same prefix
        tree.insert(p1.clone());
        tree.insert(p2.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1, "Compressed and full notation should represent the same prefix");
        assert_eq!(leaves[0], p1);
    }

    #[test]
    fn test_ordering_independence() {
        // Test that insertion order doesn't affect the final tree structure
        let mut tree1 = PrefixTree::new();
        let mut tree2 = PrefixTree::new();

        let p1 = Prefix::from_str("10.0.0.0/8").unwrap();
        let p2 = Prefix::from_str("10.1.0.0/16").unwrap();
        let p3 = Prefix::from_str("10.1.1.0/24").unwrap();

        // Insert in forward order
        tree1.insert(p1.clone());
        tree1.insert(p2.clone());
        tree1.insert(p3.clone());

        // Insert in reverse order
        tree2.insert(p3.clone());
        tree2.insert(p2.clone());
        tree2.insert(p1.clone());

        let leaves1 = collect_leaves(&tree1);
        let leaves2 = collect_leaves(&tree2);

        assert_eq!(leaves1.len(), leaves2.len());
        assert_eq!(leaves1, leaves2, "Insertion order should not affect final tree structure");
    }

    #[test]
    fn test_adjacent_prefixes() {
        // Test inserting adjacent prefixes that share a common parent
        let mut tree = PrefixTree::new();
        // These two /25 prefixes combine to form 192.168.1.0/24
        let p1 = Prefix::from_str("192.168.1.0/25").unwrap();
        let p2 = Prefix::from_str("192.168.1.128/25").unwrap();

        tree.insert(p1.clone());
        tree.insert(p2.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 2);

        let leaf_set: HashSet<Prefix> = leaves.into_iter().collect();
        assert!(leaf_set.contains(&p1));
        assert!(leaf_set.contains(&p2));
    }

    #[test]
    fn test_three_level_branching() {
        // Test a tree with three levels of branching
        let mut tree = PrefixTree::new();
        let p1 = Prefix::from_str("10.0.0.0/8").unwrap();
        let p2 = Prefix::from_str("10.0.0.0/16").unwrap();
        let p3 = Prefix::from_str("10.0.0.0/24").unwrap();
        let p4 = Prefix::from_str("10.0.1.0/24").unwrap();  // Sibling of p3
        let p5 = Prefix::from_str("10.1.0.0/16").unwrap();  // Sibling of p2

        tree.insert(p1.clone());
        tree.insert(p2.clone());
        tree.insert(p3.clone());
        tree.insert(p4.clone());
        tree.insert(p5.clone());

        let leaves = collect_leaves(&tree);
        // Leaves should be: p3, p4, p5
        assert_eq!(leaves.len(), 3);

        let leaf_set: HashSet<Prefix> = leaves.into_iter().collect();
        assert!(leaf_set.contains(&p3));
        assert!(leaf_set.contains(&p4));
        assert!(leaf_set.contains(&p5));
    }

    #[test]
    fn test_ipv6_zero_prefix() {
        // Test IPv6 ::/0 (default route)
        let mut tree = PrefixTree::new();
        let p = Prefix::from_str("::/0").unwrap();

        tree.insert(p.clone());

        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], p);
    }
}