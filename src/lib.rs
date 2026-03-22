//! # euvd-rs
//!
//! Rust client library for ENISA's European Union Vulnerability Database (EUVD).
//!
//! ## Features
//!
//! - Async API client using `reqwest` and `tokio`
//! - Built-in rate limiting (10 requests/second by default, configurable)
//! - Full type safety with `serde` deserialization
//! - Comprehensive error handling
//! - No authentication required
//!
//! ## Example
//!
//! ```no_run
//! use euvd_rs::{EuvdClient, Result};
//!
//! # async fn example() -> Result<()> {
//! let client = EuvdClient::new();
//!
//! // Get latest vulnerabilities
//! let vulnerabilities = client.latest_vulnerabilities().await?;
//! println!("Found {} vulnerabilities", vulnerabilities.len());
//!
//! // Get a specific vulnerability by EUVD ID
//! let vuln = client.get_by_id("EUVD-2024-45012").await?;
//! println!("Vulnerability: {}", vuln.description);
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod error;
pub mod models;
mod rate_limiter;

pub use client::{EuvdClient, EuvdClientBuilder, SearchParams};
pub use error::{EuvdError, Result};
pub use models::{CveEuvdMapping, SearchResponse, Vulnerability, VulnerabilityList};
