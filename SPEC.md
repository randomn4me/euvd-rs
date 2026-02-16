# euvd-rs — ENISA EU Vulnerability Database Client for Rust

## Purpose
Rust client for ENISA's European Union Vulnerability Database (EUVD). REST API, no authentication required. Designed for the cybersec-knowledge-graph but publishable standalone.

## EUVD API

Base URL: `https://euvd.enisa.europa.eu/api`

### Endpoints (research and implement all available):
- **GET /vulnerabilities** — list/search vulnerabilities
  - Query params: `search`, `page`, `size`, `sort`
- **GET /vulnerabilities/{id}** — get vulnerability by EUVD ID
- **GET /vulnerabilities/byCve/{cveId}** — lookup by CVE ID
- **GET /exploited** — list exploited vulnerabilities (KEV equivalent for EU)
- **GET /statistics** — dashboard statistics

**IMPORTANT:** Before implementing, fetch the actual API docs or explore the endpoints to discover the real schema. The above is a starting point — adjust based on what the API actually returns.

### Rate Limiter:
- No auth needed, but be respectful
- Default: 10 requests per second
- Configurable via builder
- Retry with backoff on 429

## Data Types
Model based on actual API responses. Expected fields:
- `EuvdVulnerability` — full vulnerability record
  - EUVD ID, CVE ID (if mapped), description, severity, CVSS scores
  - Affected products, references, dates
  - Exploitation status
- `ExploitedVulnerability` — exploited vuln with additional context
- `Statistics` — dashboard numbers

All types: `Clone`, `Debug`, `Serialize`, `Deserialize`, `PartialEq`

## Client Design
```rust
pub struct EuvdClient {
    // reqwest client, rate limiter, base URL
}

impl EuvdClient {
    pub fn new() -> Self; // default config
    pub fn builder() -> EuvdClientBuilder; // customizable
    
    pub async fn search_vulnerabilities(&self, query: &str, page: u32, size: u32) -> Result<VulnerabilityPage, EuvdError>;
    pub async fn get_vulnerability(&self, id: &str) -> Result<EuvdVulnerability, EuvdError>;
    pub async fn get_by_cve(&self, cve_id: &str) -> Result<EuvdVulnerability, EuvdError>;
    pub async fn list_exploited(&self, page: u32, size: u32) -> Result<ExploitedPage, EuvdError>;
    pub async fn statistics(&self) -> Result<Statistics, EuvdError>;
}
```

## Dependencies (keep minimal)
- `reqwest` (with `json` feature)
- `tokio`
- `serde` + `serde_json`
- `thiserror`
- `tracing`
- `chrono`

## Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum EuvdError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("rate limited")]
    RateLimited,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("API error: {status} {body}")]
    Api { status: u16, body: String },
}
```

## Test Requirements
- One assert per test function
- Test categories:
  - Client builder configuration
  - URL construction for each endpoint
  - JSON deserialization from fixture files
  - Error handling (404, 429, malformed JSON)
  - Rate limiter behavior
- Use `mockito` or `wiremock` for HTTP mocking
- Include test fixtures: capture real EUVD API responses as JSON fixtures

### Discovery Task
Before writing the implementation, the coding agent should:
1. Fetch `https://euvd.enisa.europa.eu/api` and explore available endpoints
2. Capture sample responses as test fixtures
3. Model types based on actual response schemas

## Crate Metadata
- Name: `euvd-rs`
- License: MIT OR Apache-2.0
- Edition: 2021
