# Hashcash

This is a proof of concept implementation of hashcash for Rust.

## Scale of this implementation

There are more sophisticated hashcash implementations out there. This one is for learning purposes only.

It does not implement double spend protection. It does however perform checks on bit-level unlike for example
the python hashcash implementation referenced [here](http://hashcash.org/libs/) which only performs byte-level
checks.

Currently it supports parsing / validating v0 stamps but not generating them. It only generates v1 as v0 is deprecated anyway. It also assumes that the timestamp consists of this format `%y%m%d%H%M%S`. The time portion is not optional.

Feel free to open PR's if you are interested in making this a more complete implementation.

## Usage

```rust
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
```

## Credits & Sources

Thanks to Adam Black author of HashCash and corresponding papers:
[hashcash.org](http://hashcash.org/)
[hashcash.org: Papers](http://hashcash.org/papers/)
[wikipedia.org: HashCash](https://en.wikipedia.org/w/index.php?title=Hashcash&oldid=1224409252)