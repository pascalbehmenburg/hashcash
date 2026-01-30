//! Hashcash proof-of-work implementation.
//!
//! Hashcash is a proof-of-work system used to limit email spam and denial-of-service attacks.
//! A stamp proves that computational work was performed, making mass sending expensive.

use std::fmt::{self, Display, Formatter, Write as FmtWrite};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use rand::Rng;

const DATE_FORMAT: &str = "%y%m%d%H%M%S";
const SALT_LEN: usize = 16;

fn main() {
    let stamp = Stamp::new(FormatVersion::V1, 20, "test@example.com".into(), None);
    let minted = stamp.mint();

    println!("X-Hashcash: {minted}");
    println!("SHA-1: {}", minted.sha1_hex());
    println!("Leading zeros: {}", minted.leading_zeros());
    println!("Counter: {}", minted.counter);

    match minted.check("test@example.com", &Duration::days(2)) {
        Ok(_) => println!("Valid!"),
        Err(e) => println!("Invalid: {e}"),
    }
}

/// Hashcash format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatVersion {
    /// Version 0 (deprecated).
    V0 = 0,
    /// Version 1 (current).
    V1 = 1,
}

impl Display for FormatVersion {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_char(if *self == FormatVersion::V0 { '0' } else { '1' })
    }
}

/// A hashcash stamp proving computational work was performed.
#[derive(Debug, Clone)]
pub struct Stamp {
    /// Format version.
    pub version: FormatVersion,
    /// Required number of leading zero bits in hash.
    pub bits: u8,
    /// When the stamp was created.
    pub date: DateTime<Utc>,
    /// Protected resource (e.g., email address).
    pub resource: String,
    /// Optional extension data (ignored in v1).
    pub extension: Option<String>,
    /// Random salt for uniqueness.
    pub salt: [u8; SALT_LEN],
    /// Counter value found during mining.
    pub counter: u64,
}

impl Stamp {
    /// Creates a new stamp with random salt and counter at zero.
    pub fn new(version: FormatVersion, bits: u8, resource: String, extension: Option<String>) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill(&mut salt);
        Self { version, bits, date: Utc::now(), resource, extension, salt, counter: 0 }
    }

    /// Mines a valid stamp by incrementing counter until hash has enough leading zeros.
    pub fn mint(mut self) -> Self {
        let prefix = self.build_prefix();
        let mut buf = String::with_capacity(prefix.len() + 12);

        loop {
            buf.clear();
            buf.push_str(&prefix);
            STANDARD.encode_string(&self.counter.to_be_bytes(), &mut buf);

            if has_leading_zeros(&sha1_hash(buf.as_bytes()), self.bits) {
                return self;
            }
            self.counter += 1;
        }
    }

    /// Validates the stamp against expected resource and expiry duration.
    pub fn check(&self, resource: &str, expiry: &Duration) -> Result<(), &'static str> {
        if self.resource != resource {
            return Err("resource mismatch");
        }
        if Utc::now() >= self.date + *expiry {
            return Err("expired");
        }
        if !has_leading_zeros(&sha1_hash(self.to_string().as_bytes()), self.bits) {
            return Err("insufficient proof of work");
        }
        Ok(())
    }

    /// Returns SHA-1 hash as hex string.
    pub fn sha1_hex(&self) -> String {
        let hash = sha1_hash(self.to_string().as_bytes());
        let mut hex = String::with_capacity(40);
        for b in hash {
            write!(hex, "{b:02x}").unwrap();
        }
        hex
    }

    /// Returns count of leading zero bits in the stamp's hash.
    pub fn leading_zeros(&self) -> u32 {
        count_leading_zeros(&sha1_hash(self.to_string().as_bytes()))
    }

    fn build_prefix(&self) -> String {
        let mut s = String::with_capacity(128);
        write!(
            s, "{}:{}:{}:{}:{}:",
            self.version, self.bits, self.date.format(DATE_FORMAT),
            self.resource, self.extension.as_deref().unwrap_or("")
        ).unwrap();
        STANDARD.encode_string(&self.salt, &mut s);
        s.push(':');
        s
    }
}

impl Display for Stamp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f, "{}:{}:{}:{}:{}:{}:{}",
            self.version, self.bits, self.date.format(DATE_FORMAT),
            self.resource, self.extension.as_deref().unwrap_or(""),
            STANDARD.encode(&self.salt), STANDARD.encode(self.counter.to_be_bytes())
        )
    }
}

impl TryFrom<&str> for Stamp {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let p: Vec<&str> = s.split(':').collect();
        if p.len() < 6 {
            return Err("missing fields");
        }

        let version = match p[0] {
            "0" => FormatVersion::V0,
            "1" => FormatVersion::V1,
            _ => return Err("invalid version"),
        };

        let bits = p[1].parse().map_err(|_| "invalid bits")?;
        let date = NaiveDateTime::parse_from_str(p[2], DATE_FORMAT)
            .map_err(|_| "invalid date")?
            .and_utc();
        let resource = p[3].to_string();
        let extension = (p.len() > 6 && !p[4].is_empty()).then(|| p[4].to_string());

        let salt_bytes = STANDARD.decode(p[p.len() - 2]).map_err(|_| "invalid salt")?;
        if salt_bytes.len() != SALT_LEN {
            return Err("invalid salt length");
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_bytes);

        let counter_bytes = STANDARD.decode(p[p.len() - 1]).map_err(|_| "invalid counter")?;
        if counter_bytes.len() > 8 {
            return Err("counter too large");
        }
        let mut buf = [0u8; 8];
        buf[8 - counter_bytes.len()..].copy_from_slice(&counter_bytes);
        let counter = u64::from_be_bytes(buf);

        Ok(Self { version, bits, date, resource, extension, salt, counter })
    }
}

impl TryFrom<String> for Stamp {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut h = sha1_smol::Sha1::new();
    h.update(data);
    h.digest().bytes()
}

fn has_leading_zeros(hash: &[u8; 20], bits: u8) -> bool {
    let (full, rem) = (bits as usize / 8, bits % 8);
    hash[..full].iter().all(|&b| b == 0)
        && (rem == 0 || hash[full] & (0xFF << (8 - rem)) == 0)
}

fn count_leading_zeros(hash: &[u8; 20]) -> u32 {
    let mut count = 0;
    for &b in hash {
        if b == 0 {
            count += 8;
        } else {
            return count + b.leading_zeros();
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_STAMP: &str = "1:20:240525120406:test@example.com::AAAAAAAAAAAAAAAAAAAAAA==:AAAAAAAAAFA=";

    #[test]
    fn format_version_display() {
        assert_eq!(FormatVersion::V0.to_string(), "0");
        assert_eq!(FormatVersion::V1.to_string(), "1");
    }

    #[test]
    fn stamp_new_initializes_correctly() {
        let stamp = Stamp::new(FormatVersion::V1, 16, "test@example.com".into(), None);
        assert_eq!(stamp.version, FormatVersion::V1);
        assert_eq!(stamp.bits, 16);
        assert_eq!(stamp.resource, "test@example.com");
        assert!(stamp.extension.is_none());
        assert_eq!(stamp.counter, 0);
    }

    #[test]
    fn stamp_new_with_extension() {
        let stamp = Stamp::new(FormatVersion::V1, 16, "res".into(), Some("ext".into()));
        assert_eq!(stamp.extension, Some("ext".into()));
    }

    #[test]
    fn stamp_display_roundtrip() {
        let stamp = Stamp::try_from(TEST_STAMP).unwrap();
        let formatted = stamp.to_string();
        let reparsed = Stamp::try_from(formatted.as_str()).unwrap();
        assert_eq!(stamp.version, reparsed.version);
        assert_eq!(stamp.bits, reparsed.bits);
        assert_eq!(stamp.resource, reparsed.resource);
        assert_eq!(stamp.salt, reparsed.salt);
        assert_eq!(stamp.counter, reparsed.counter);
    }

    #[test]
    fn parse_v0_stamp() {
        let stamp = Stamp::try_from("0:20:240525120406:test::AAAAAAAAAAAAAAAAAAAAAA==:AAAAAAAAAA==").unwrap();
        assert_eq!(stamp.version, FormatVersion::V0);
    }

    #[test]
    fn parse_with_extension() {
        let s = "1:20:240525120406:test:myext:AAAAAAAAAAAAAAAAAAAAAA==:AAAAAAAAAA==";
        let stamp = Stamp::try_from(s).unwrap();
        assert_eq!(stamp.extension, Some("myext".into()));
    }

    #[test]
    fn parse_missing_fields() {
        assert_eq!(Stamp::try_from("1:20:240525").unwrap_err(), "missing fields");
    }

    #[test]
    fn parse_invalid_version() {
        let s = "9:20:240525120406:test::AAAAAAAAAAAAAAAAAAAAAA==:AA==";
        assert_eq!(Stamp::try_from(s).unwrap_err(), "invalid version");
    }

    #[test]
    fn parse_invalid_bits() {
        let s = "1:abc:240525120406:test::AAAAAAAAAAAAAAAAAAAAAA==:AA==";
        assert_eq!(Stamp::try_from(s).unwrap_err(), "invalid bits");
    }

    #[test]
    fn parse_invalid_date() {
        let s = "1:20:notadate:test::AAAAAAAAAAAAAAAAAAAAAA==:AA==";
        assert_eq!(Stamp::try_from(s).unwrap_err(), "invalid date");
    }

    #[test]
    fn parse_invalid_salt() {
        let s = "1:20:240525120406:test::!!!invalid!!!:AA==";
        assert_eq!(Stamp::try_from(s).unwrap_err(), "invalid salt");
    }

    #[test]
    fn parse_invalid_salt_length() {
        let s = "1:20:240525120406:test::AQID:AA=="; // only 3 bytes
        assert_eq!(Stamp::try_from(s).unwrap_err(), "invalid salt length");
    }

    #[test]
    fn parse_invalid_counter() {
        let s = "1:20:240525120406:test::AAAAAAAAAAAAAAAAAAAAAA==:!!!";
        assert_eq!(Stamp::try_from(s).unwrap_err(), "invalid counter");
    }

    #[test]
    fn parse_counter_too_large() {
        let s = "1:20:240525120406:test::AAAAAAAAAAAAAAAAAAAAAA==:AAAAAAAAAAAAAA=="; // 9+ bytes
        assert_eq!(Stamp::try_from(s).unwrap_err(), "counter too large");
    }

    #[test]
    fn try_from_string() {
        let stamp = Stamp::try_from(TEST_STAMP.to_string()).unwrap();
        assert_eq!(stamp.resource, "test@example.com");
    }

    #[test]
    fn mint_produces_valid_hash() {
        let stamp = Stamp::new(FormatVersion::V1, 8, "test".into(), None);
        let minted = stamp.mint();
        assert!(minted.leading_zeros() >= 8);
        assert!(has_leading_zeros(&sha1_hash(minted.to_string().as_bytes()), 8));
    }

    #[test]
    fn check_valid_stamp() {
        let stamp = Stamp::new(FormatVersion::V1, 8, "test".into(), None).mint();
        assert!(stamp.check("test", &Duration::days(1)).is_ok());
    }

    #[test]
    fn check_wrong_resource() {
        let stamp = Stamp::new(FormatVersion::V1, 8, "test".into(), None).mint();
        assert_eq!(stamp.check("other", &Duration::days(1)).unwrap_err(), "resource mismatch");
    }

    #[test]
    fn check_expired() {
        let stamp = Stamp::new(FormatVersion::V1, 8, "test".into(), None).mint();
        assert_eq!(stamp.check("test", &Duration::seconds(-1)).unwrap_err(), "expired");
    }

    #[test]
    fn check_insufficient_work() {
        let mut stamp = Stamp::new(FormatVersion::V1, 40, "test".into(), None);
        stamp.counter = 1; // won't have 40 leading zeros
        assert_eq!(stamp.check("test", &Duration::days(1)).unwrap_err(), "insufficient proof of work");
    }

    #[test]
    fn sha1_hex_format() {
        let stamp = Stamp::try_from(TEST_STAMP).unwrap();
        let hex = stamp.sha1_hex();
        assert_eq!(hex.len(), 40);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn leading_zeros_count() {
        // Hash with known prefix
        let hash: [u8; 20] = [0, 0, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(count_leading_zeros(&hash), 20);
    }

    #[test]
    fn leading_zeros_all_zero() {
        let hash = [0u8; 20];
        assert_eq!(count_leading_zeros(&hash), 160);
    }

    #[test]
    fn leading_zeros_first_byte_nonzero() {
        let mut hash = [0u8; 20];
        hash[0] = 0x80; // first bit is 1
        assert_eq!(count_leading_zeros(&hash), 0);
    }

    #[test]
    fn has_leading_zeros_exact_bytes() {
        let hash: [u8; 20] = [0, 0, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(has_leading_zeros(&hash, 16));
        assert!(!has_leading_zeros(&hash, 17));
    }

    #[test]
    fn has_leading_zeros_partial_byte() {
        let hash: [u8; 20] = [0, 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(has_leading_zeros(&hash, 12));
        assert!(!has_leading_zeros(&hash, 13));
    }

    #[test]
    fn has_leading_zeros_zero_bits() {
        let hash = [0xFF; 20];
        assert!(has_leading_zeros(&hash, 0));
    }

    #[test]
    fn build_prefix_contains_all_fields() {
        let stamp = Stamp::new(FormatVersion::V1, 20, "test@example.com".into(), Some("ext".into()));
        let prefix = stamp.build_prefix();
        assert!(prefix.starts_with("1:20:"));
        assert!(prefix.contains(":test@example.com:ext:"));
        assert!(prefix.ends_with(':'));
    }
}
