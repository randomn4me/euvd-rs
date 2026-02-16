# euvd-rs

Rust client library for ENISA's European Union Vulnerability Database (EUVD).

## Features

- Async API client using `reqwest` and `tokio`
- Built-in rate limiting (10 requests/second by default, configurable)
- Full type safety with `serde` deserialization
- Comprehensive error handling
- No authentication required

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
euvd-rs = "0.1"
```

## Usage

### Basic Example

```rust
use euvd_rs::{EuvdClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = EuvdClient::new();

    // Get latest vulnerabilities
    let vulnerabilities = client.latest_vulnerabilities().await?;
    println!("Found {} vulnerabilities", vulnerabilities.len());

    // Get a specific vulnerability by EUVD ID
    let vuln = client.get_by_id("EUVD-2024-45012").await?;
    println!("Vulnerability: {}", vuln.description);

    Ok(())
}
```

### Custom Configuration

```rust
use euvd_rs::EuvdClient;

let client = EuvdClient::builder()
    .rate_limit(5)  // 5 requests per second
    .build();
```

### Search Vulnerabilities

```rust
use euvd_rs::{EuvdClient, SearchParams};

let client = EuvdClient::new();

// Search by text
let params = SearchParams {
    text: Some("Microsoft".to_string()),
    from_score: None,
    to_score: None,
};
let results = client.search(&params).await?;

// Search by CVSS score range
let params = SearchParams {
    text: None,
    from_score: Some(9),
    to_score: Some(10),
};
let critical = client.search(&params).await?;
```

### Get Exploited Vulnerabilities

```rust
let client = EuvdClient::new();
let exploited = client.exploited_vulnerabilities().await?;

for vuln in exploited {
    if let Some(exploited_since) = vuln.exploited_since {
        println!("{} exploited since {}", vuln.id, exploited_since);
    }
}
```

### Search by CVE ID

```rust
let client = EuvdClient::new();
let results = client.get_by_cve("CVE-2024-50831").await?;
```

## API Endpoints

The client supports the following EUVD API endpoints:

- `GET /lastvulnerabilities` - Latest published vulnerabilities
- `GET /exploitedvulnerabilities` - Known exploited vulnerabilities
- `GET /criticalvulnerabilities` - Critical vulnerabilities
- `GET /search` - Search with filters (text, score range)
- `GET /enisaid` - Get vulnerability by EUVD ID

## Data Model

The main types are:

- `Vulnerability` - Full vulnerability record with EUVD ID, CVE mapping, CVSS scores, affected products, vendors, and references
- `VulnerabilityList` - Vector of vulnerabilities
- `SearchParams` - Search parameters (text, score range)

All types implement `Clone`, `Debug`, `Serialize`, `Deserialize`, and `PartialEq`.

## Error Handling

```rust
use euvd_rs::{EuvdClient, EuvdError};

let client = EuvdClient::new();
match client.get_by_id("INVALID-ID").await {
    Ok(vuln) => println!("Found: {}", vuln.id),
    Err(EuvdError::NotFound(id)) => println!("Not found: {}", id),
    Err(EuvdError::RateLimited) => println!("Rate limited"),
    Err(e) => println!("Error: {}", e),
}
```

## Testing

The library includes comprehensive tests with HTTP mocking using `mockito`:

```bash
cargo test
```

Test fixtures are captured from the real EUVD API and stored in `tests/fixtures/`.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
