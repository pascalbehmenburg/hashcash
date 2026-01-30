# Hashcash

A proof-of-work implementation in Rust.

## Overview

Hashcash is a proof-of-work system used to limit email spam and denial-of-service attacks. A stamp proves computational work was performed, making mass sending expensive.

This implementation:
- Supports parsing v0 and v1 stamps, generates v1 only
- Performs bit-level validation (not just byte-level)
- Does not implement double-spend protection

## Usage

```rust
use chrono::Duration;

// Create and mine a stamp
let stamp = Stamp::new(FormatVersion::V1, 20, "user@example.com".into(), None);
let minted = stamp.mint();

println!("X-Hashcash: {minted}");
println!("SHA-1: {}", minted.sha1_hex());
println!("Leading zeros: {}", minted.leading_zeros());

// Validate a stamp
match minted.check("user@example.com", &Duration::days(2)) {
    Ok(()) => println!("Valid!"),
    Err(e) => println!("Invalid: {e}"),
}

// Parse from string
let stamp = Stamp::try_from("1:20:240525120406:user@example.com::base64salt==:base64counter==").unwrap();
```

## Format

Stamps use colon-separated format: `version:bits:date:resource:extension:salt:counter`

- **version**: 0 or 1
- **bits**: required leading zero bits
- **date**: YYMMDDHHMMSS
- **resource**: protected resource (email, IP, etc.)
- **extension**: optional data (ignored in v1)
- **salt**: base64-encoded random bytes
- **counter**: base64-encoded u64

## Credits

Based on [Hashcash](http://hashcash.org/) by Adam Back.
