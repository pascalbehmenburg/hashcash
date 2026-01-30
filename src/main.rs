use std::fmt::{self, Display, Formatter, Write as FmtWrite};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use rand::{distributions::Standard, Rng};

static DATE_FORMAT: &str = "%y%m%d%H%M%S";

fn main() {
    // Example usage:
    // Stamp parameters
    let requested_bits = 20;
    let requested_resource = "2021780@uni-wuppertal.de";
    let expiry_duration = Duration::days(2);

    // Create new stamp object
    let stamp = Stamp::new(
        FormatVersion::V1,
        requested_bits,
        requested_resource.to_string(),
        None,
    );

    // Produce valid stamp (usually client side)
    let minted_stamp = stamp.mint();
    println!("X-Hashcash: {}", minted_stamp);
    println!("SHA-1 hash: {}", minted_stamp.sha1_hex());
    println!(
        "Leading zero bits: {}",
        minted_stamp.count_leading_zero_bits()
    );
    println!("Counter: {}", minted_stamp.counter);

    // Validate Stamp (usually server side)
    match minted_stamp.check(requested_resource, &expiry_duration) {
        Ok(checked_stamp) => println!("Valid stamp: {}", checked_stamp),
        Err(e) => println!("Validation error: {}", e),
    };

    // Parse stamp from string (using standard hashcash format with base64 counter)
    let stamp_str =
        "1:20:240525120406:2021780@uni-wuppertal.de::NFs/AwRqLgRFoCXRI7aajw==:AAAAAAAPXA==";
    let stamp = Stamp::try_from(stamp_str).unwrap();
    println!("Parsed stamp: {}", stamp);
}

#[derive(Clone, Copy)]
pub enum FormatVersion {
    V0 = 0,
    V1 = 1,
}

impl Display for FormatVersion {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            FormatVersion::V0 => f.write_char('0'),
            FormatVersion::V1 => f.write_char('1'),
        }
    }
}

pub struct Stamp {
    // Hashcash format version
    version: FormatVersion,

    // Number of "partial pre-image" (zero) bits in the hashed code.
    // referred to as 'w' in the original paper
    requested_bits: u8,

    // The time that the stamp was created/sent, in the format YYMMDD[hhmm[ss]].
    creation_date: DateTime<Utc>,

    // Resource which is being transmitted, e.g., an IP address or email address.
    resource: String,

    // Extension (optional; ignored in version 1).
    extension: Option<String>,

    // Random bytes for uniqueness (16 bytes like reference implementation)
    salt: [u8; 16],

    // Counter incremented during mining until valid hash is found
    counter: u64,
}

impl Stamp {
    pub fn new(
        version: FormatVersion,
        requested_bits: u8,
        resource: String,
        extension: Option<String>,
    ) -> Self {
        let mut salt = [0u8; 16];
        rand::thread_rng()
            .sample_iter(&Standard)
            .take(16)
            .enumerate()
            .for_each(|(i, b)| salt[i] = b);

        Stamp {
            version,
            requested_bits,
            creation_date: Utc::now(),
            resource,
            extension,
            salt,
            counter: 0,
        }
    }

    /// Count leading zero bits in the SHA-1 hash of this stamp
    #[inline]
    pub fn count_leading_zero_bits(&self) -> u32 {
        let hash = self.sha1_bytes();
        count_leading_zero_bits(&hash)
    }

    /// Get SHA-1 hash as hex string (for display purposes)
    pub fn sha1_hex(&self) -> String {
        let hash = self.sha1_bytes();
        let mut hex = String::with_capacity(40);
        for byte in hash {
            write!(hex, "{:02x}", byte).unwrap();
        }
        hex
    }

    /// Get raw SHA-1 hash bytes
    #[inline]
    fn sha1_bytes(&self) -> [u8; 20] {
        let mut hasher = sha1_smol::Sha1::new();
        hasher.update(self.to_string().as_bytes());
        hasher.digest().bytes()
    }

    /// Mine a valid hashcash stamp by incrementing counter until hash has enough leading zeros
    pub fn mint(mut self) -> Self {
        let bits = self.requested_bits;

        // Pre-compute the static prefix (everything except the counter)
        // Format: "version:bits:date:resource:extension:salt:"
        let prefix = self.build_prefix();

        // Pre-allocate buffer for the full stamp string
        // Counter as base64 of u64 is at most 12 bytes (8 bytes -> ~11 base64 chars + padding)
        let mut stamp_buf = String::with_capacity(prefix.len() + 12);

        loop {
            // Build stamp string efficiently: prefix + base64(counter)
            stamp_buf.clear();
            stamp_buf.push_str(&prefix);
            STANDARD.encode_string(&self.counter.to_be_bytes(), &mut stamp_buf);

            // Hash and check leading zeros directly on bytes
            let mut hasher = sha1_smol::Sha1::new();
            hasher.update(stamp_buf.as_bytes());
            let hash = hasher.digest().bytes();

            if has_leading_zero_bits(&hash, bits) {
                return self;
            }

            self.counter += 1;
        }
    }

    /// Build the prefix part of the stamp (everything before the counter)
    fn build_prefix(&self) -> String {
        let mut prefix = String::with_capacity(128);
        write!(
            prefix,
            "{}:{}:{}:{}:{}:",
            self.version,
            self.requested_bits,
            self.creation_date.format(DATE_FORMAT),
            self.resource,
            self.extension.as_deref().unwrap_or("")
        )
        .unwrap();
        STANDARD.encode_string(&self.salt, &mut prefix);
        prefix.push(':');
        prefix
    }

    /// Validate the stamp
    pub fn check(
        &self,
        resource: &str,
        expiry_duration: &Duration,
    ) -> Result<&Self, &'static str> {
        if resource != self.resource {
            return Err("The stamp resource doesn't match the expected resource.");
        }

        if Utc::now() >= self.creation_date + *expiry_duration {
            return Err("Stamp has expired.");
        }

        let hash = self.sha1_bytes();
        if !has_leading_zero_bits(&hash, self.requested_bits) {
            return Err("Stamp hash doesn't have required leading zero bits.");
        }

        Ok(self)
    }
}

/// Check if hash has at least `bits` leading zero bits
#[inline]
fn has_leading_zero_bits(hash: &[u8; 20], bits: u8) -> bool {
    let bits = bits as usize;

    // Check full bytes first
    let full_bytes = bits / 8;
    for i in 0..full_bytes {
        if hash[i] != 0 {
            return false;
        }
    }

    // Check remaining bits in the next byte
    let remaining_bits = bits % 8;
    if remaining_bits > 0 {
        let mask = 0xFF << (8 - remaining_bits);
        if hash[full_bytes] & mask != 0 {
            return false;
        }
    }

    true
}

/// Count leading zero bits in a hash
#[inline]
fn count_leading_zero_bits(hash: &[u8; 20]) -> u32 {
    let mut count = 0u32;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

impl TryFrom<&str> for Stamp {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split(':').collect();

        if parts.len() < 6 {
            return Err("Stamp is missing required fields");
        }

        let version = match parts[0] {
            "0" => FormatVersion::V0,
            "1" => FormatVersion::V1,
            _ => return Err("Invalid version"),
        };

        let requested_bits = parts[1].parse::<u8>().map_err(|_| "Invalid requested bits")?;

        let creation_date = NaiveDateTime::parse_from_str(parts[2], DATE_FORMAT)
            .map_err(|_| "Invalid creation date")?
            .and_utc();

        let resource = parts[3].to_string();

        let extension = if parts.len() > 6 && !parts[4].is_empty() {
            Some(parts[4].to_string())
        } else {
            None
        };

        // Salt is second to last
        let salt_vec = STANDARD
            .decode(parts[parts.len() - 2])
            .map_err(|_| "Invalid salt")?;

        if salt_vec.len() != 16 {
            return Err("Invalid salt length");
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_vec);

        // Counter is always the last element (base64 encoded u64 big-endian)
        let counter_bytes = STANDARD
            .decode(parts[parts.len() - 1])
            .map_err(|_| "Invalid counter")?;

        // Handle variable-length counter bytes (pad to 8 bytes)
        let counter = if counter_bytes.len() <= 8 {
            let mut buf = [0u8; 8];
            let offset = 8 - counter_bytes.len();
            buf[offset..].copy_from_slice(&counter_bytes);
            u64::from_be_bytes(buf)
        } else {
            return Err("Counter too large");
        };

        Ok(Stamp {
            version,
            requested_bits,
            creation_date,
            resource,
            extension,
            salt,
            counter,
        })
    }
}

impl TryFrom<String> for Stamp {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Stamp::try_from(value.as_str())
    }
}

impl Display for Stamp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}",
            self.version,
            self.requested_bits,
            self.creation_date.format(DATE_FORMAT),
            self.resource,
            self.extension.as_deref().unwrap_or(""),
            STANDARD.encode(&self.salt),
            STANDARD.encode(self.counter.to_be_bytes())
        )
    }
}
