use std::fmt::{self, Display, Formatter};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use rand::{distributions::Standard, Rng};

static DATE_FORMAT: &str = "%y%m%d%H%M%S";

fn main() {
    // Example usage:
    // Stamp parameters
    let requested_bits = 16;
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
    println!("SHA-1 hash: {}", minted_stamp.to_sha1_hash());
    println!(
        "First {} bits of hash: {}",
        minted_stamp.requested_bits,
        &minted_stamp.to_binary_sha1_hash()[0..minted_stamp.requested_bits as usize]
    );
    println!("Counter: {}", minted_stamp.counter);

    // Validate Stamp (usually server side)
    match minted_stamp.check(requested_resource, &expiry_duration) {
        Ok(checked_stamp) => println!("Valid stamp: {}", checked_stamp),
        Err(e) => println!("Validation error: {}", e),
    };

    // Parse stamp from string
    let stamp = "1:16:240525120406:2021780@uni-wuppertal.de::NFs/AwRqLgRFoCXRI7aajw==:MTExMTAwMTEwMTExMTAwMDAw".to_string();
    let stamp = Stamp::try_from(stamp).unwrap();
    println!("Parsed stamp: {}", stamp);
}

pub enum FormatVersion {
    V0 = 0,
    V1 = 1,
}

impl Display for FormatVersion {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            FormatVersion::V0 => write!(f, "0"),
            FormatVersion::V1 => write!(f, "1"),
        }
    }
}

pub struct Stamp {
    // Hashcash format version
    version: FormatVersion,

    // Number of "partial pre-image" (zero) bits in the hashed code.
    // refered to as 'w' in the original paper
    requested_bits: u8,

    // The time that the stamp was created/sent, in the format YYMMDD[hhmm[ss]].
    creation_date: DateTime<Utc>,

    // Resource which is being transmitted, e.g., an IP address or email address.
    resource: String,

    // Extension (optional; ignored in version 1).
    extension: Option<String>,

    // String of random alphanumeric characters
    // c implementation defaults to a length of 16 so do we
    salt: Vec<u8>,

    // Used to add variance after each hashing until we bruteforce a valid one
    counter: usize,
}

impl<'a> Stamp {
    pub fn new(
        version: FormatVersion,
        requested_bits: u8,
        resource: String,
        extension: Option<String>,
    ) -> Self {
        let salt: Vec<u8> = rand::thread_rng().sample_iter(&Standard).take(16).collect();

        let creation_date = chrono::offset::Utc::now();

        Stamp {
            version,
            requested_bits,
            creation_date,
            resource,
            extension,
            salt,
            counter: 0,
        }
    }

    pub fn get_requested_zeros(&self) -> String {
        str::repeat("0", self.requested_bits as usize)
    }

    pub fn to_sha1_hash(&self) -> String {
        let mut hasher = sha1_smol::Sha1::new();
        hasher.update(self.to_string().as_bytes());
        hasher.hexdigest()
    }

    pub fn to_binary_sha1_hash(&self) -> String {
        let mut hasher = sha1_smol::Sha1::new();
        hasher.update(self.to_string().as_bytes());
        hasher
            .digest()
            .bytes()
            .map(|byte| format!("{:08b}", byte))
            .concat()
    }

    pub fn mint(mut self) -> Self {
        let requested_zeros = &self.get_requested_zeros();
        loop {
            let mut hasher = sha1_smol::Sha1::new();
            hasher.update(self.to_string().as_bytes());

            let hash = hasher
                .digest()
                .bytes()
                .map(|byte| format!("{:08b}", byte))
                .concat();

            if hash.starts_with(requested_zeros) {
                return self;
            }

            self.counter += 1;
        }
    }

    pub fn check(
        &self,
        resource: &'a str,
        expiry_duration: &'a Duration,
    ) -> Result<&Self, &'static str> {
        if resource != self.resource {
            return Err("The stamp resource doesn't match the expected resource.");
        }

        if chrono::offset::Utc::now() >= self.creation_date + *expiry_duration {
            return Err("Stamp has expired.");
        }

        let mut hasher = sha1_smol::Sha1::new();
        hasher.update(self.to_string().as_bytes());

        let requested_zeros = &self.get_requested_zeros();
        let hash = hasher
            .digest()
            .bytes()
            .map(|byte| format!("{:08b}", byte))
            .concat();

        if !hash.starts_with(requested_zeros) {
            return Err("Stamp isn't producing hash with expected zero bit count.");
        }

        Ok(self)
    }
}

impl TryFrom<String> for Stamp {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split(':').collect();

        if parts.len() < 6 {
            return Err("Stamp is missing required fields");
        }

        let version = match parts[0] {
            "0" => FormatVersion::V0,
            "1" => FormatVersion::V1,
            _ => return Err("Invalid version"),
        };

        let requested_bits = match parts[1].parse::<u8>() {
            Ok(v) => v,
            Err(_) => return Err("Invalid requested bits"),
        };

        let creation_date = match NaiveDateTime::parse_from_str(parts[2], DATE_FORMAT) {
            Ok(v) => v.and_utc(),
            Err(_) => return Err("Invalid creation date"),
        };

        let resource = parts[3].to_string();

        let extension = if parts.len() > 6 {
            Some(parts[4].to_string())
        } else {
            None
        };

        // we have to use indices from the end of the array here
        // since we may only assume that the salt is the second to last
        let salt = match STANDARD.decode(parts[parts.len() - 2]) {
            Ok(v) => v,
            Err(_) => return Err("Invalid salt"),
        };

        // same here counter is always the last element
        let counter = match STANDARD.decode(parts[parts.len() - 1]) {
            Ok(v) => usize::from_str_radix(std::str::from_utf8(&v).unwrap(), 2).unwrap(),
            Err(_) => return Err("Invalid counter"),
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

impl Display for Stamp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let creation_date = self.creation_date.format(DATE_FORMAT);

        let extension = (self.extension).clone().unwrap_or_default();

        let salt = STANDARD.encode(self.salt.clone());
        let counter = STANDARD.encode(format!("{:b}", self.counter));

        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}",
            self.version,
            self.requested_bits,
            creation_date,
            self.resource,
            extension,
            salt,
            counter
        )
    }
}
