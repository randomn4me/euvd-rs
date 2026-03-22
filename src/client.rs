use crate::{
    error::{EuvdError, Result},
    models::{CveEuvdMapping, Vulnerability, VulnerabilityList},
    rate_limiter::RateLimiter,
};
use reqwest::Client;
use tracing::{debug, warn};

const DEFAULT_BASE_URL: &str = "https://euvdservices.enisa.europa.eu/api";

/// EUVD API client
///
/// Provides async access to the European Union Vulnerability Database.
/// Includes automatic rate limiting to respect API usage limits.
///
/// # Example
///
/// ```no_run
/// use euvd_rs::EuvdClient;
///
/// # async fn example() -> euvd_rs::Result<()> {
/// let client = EuvdClient::new();
/// let vulnerabilities = client.latest_vulnerabilities().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct EuvdClient {
    #[allow(dead_code)]
    client: Client,
    #[allow(dead_code)]
    base_url: String,
    #[allow(dead_code)]
    rate_limiter: RateLimiter,
}

impl EuvdClient {
    /// Create a new EUVD client with default configuration
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create a client builder for custom configuration
    pub fn builder() -> EuvdClientBuilder {
        EuvdClientBuilder::default()
    }

    /// Get the latest published vulnerabilities
    pub async fn latest_vulnerabilities(&self) -> Result<VulnerabilityList> {
        self.get_list("lastvulnerabilities").await
    }

    /// Get known exploited vulnerabilities
    pub async fn exploited_vulnerabilities(&self) -> Result<VulnerabilityList> {
        self.get_list("exploitedvulnerabilities").await
    }

    /// Get critical vulnerabilities (high CVSS scores)
    pub async fn critical_vulnerabilities(&self) -> Result<VulnerabilityList> {
        self.get_list("criticalvulnerabilities").await
    }

    /// Search vulnerabilities with filters
    ///
    /// # Example
    ///
    /// ```no_run
    /// use euvd_rs::{EuvdClient, SearchParams};
    ///
    /// # async fn example() -> euvd_rs::Result<()> {
    /// let client = EuvdClient::new();
    /// let params = SearchParams {
    ///     text: Some("Microsoft".to_string()),
    ///     from_score: Some(7),
    ///     to_score: Some(10),
    /// };
    /// let results = client.search(&params).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn search(&self, params: &SearchParams) -> Result<VulnerabilityList> {
        let mut url = format!("{}/search", self.base_url);
        let mut query_parts = Vec::new();

        if let Some(text) = &params.text {
            query_parts.push(format!("text={}", urlencoding::encode(text)));
        }
        if let Some(from_score) = params.from_score {
            query_parts.push(format!("fromScore={}", from_score));
        }
        if let Some(to_score) = params.to_score {
            query_parts.push(format!("toScore={}", to_score));
        }

        if !query_parts.is_empty() {
            url.push('?');
            url.push_str(&query_parts.join("&"));
        }

        self.rate_limiter.wait().await;
        debug!("GET {}", url);

        let response = self.client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Get a specific vulnerability by its EUVD ID
    ///
    /// # Example
    ///
    /// ```no_run
    /// use euvd_rs::EuvdClient;
    ///
    /// # async fn example() -> euvd_rs::Result<()> {
    /// let client = EuvdClient::new();
    /// let vuln = client.get_by_id("EUVD-2024-45012").await?;
    /// println!("Description: {}", vuln.description);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_by_id(&self, id: &str) -> Result<Vulnerability> {
        let url = format!("{}/enisaid?id={}", self.base_url, urlencoding::encode(id));

        self.rate_limiter.wait().await;
        debug!("GET {}", url);

        let response = self.client.get(&url).send().await?;

        if response.status() == 404 {
            return Err(EuvdError::NotFound(id.to_string()));
        }

        if response.status() == 429 {
            return Err(EuvdError::RateLimited);
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(EuvdError::Api { status, body });
        }

        response.json().await.map_err(|e| {
            EuvdError::Parse(format!("Failed to parse vulnerability: {}", e))
        })
    }

    /// Search for vulnerabilities by CVE ID
    ///
    /// # Example
    ///
    /// ```no_run
    /// use euvd_rs::EuvdClient;
    ///
    /// # async fn example() -> euvd_rs::Result<()> {
    /// let client = EuvdClient::new();
    /// let results = client.get_by_cve("CVE-2024-50831").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_by_cve(&self, cve_id: &str) -> Result<VulnerabilityList> {
        self.search(&SearchParams {
            text: Some(cve_id.to_string()),
            from_score: None,
            to_score: None,
        })
        .await
    }

    /// Download the full CVE-to-EUVD ID mapping (CSV dump)
    ///
    /// Returns the complete mapping of CVE IDs to EUVD IDs.
    /// This dataset is updated daily at 07:00 UTC.
    /// Contains only records linked to published CVEs.
    pub async fn cve_euvd_mapping(&self) -> Result<Vec<CveEuvdMapping>> {
        let url = format!("{}/dump/cve-euvd-mapping", self.base_url);

        self.rate_limiter.wait().await;
        debug!("GET {}", url);

        let response = self.client.get(&url).send().await?;

        if response.status() == 429 {
            warn!("Rate limited by server");
            return Err(EuvdError::RateLimited);
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(EuvdError::Api { status, body });
        }

        let body = response.text().await.map_err(|e| {
            EuvdError::Parse(format!("Failed to read CSV body: {}", e))
        })?;

        Ok(parse_csv_mapping(&body))
    }

    async fn get_list(&self, endpoint: &str) -> Result<VulnerabilityList> {
        let url = format!("{}/{}", self.base_url, endpoint);

        self.rate_limiter.wait().await;
        debug!("GET {}", url);

        let response = self.client.get(&url).send().await?;
        self.handle_response(response).await
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        if response.status() == 429 {
            warn!("Rate limited by server");
            return Err(EuvdError::RateLimited);
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(EuvdError::Api { status, body });
        }

        response.json().await.map_err(|e| {
            EuvdError::Parse(format!("Failed to parse response: {}", e))
        })
    }
}

impl Default for EuvdClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for configuring an EUVD client
///
/// # Example
///
/// ```
/// use euvd_rs::EuvdClient;
///
/// let client = EuvdClient::builder()
///     .rate_limit(5)  // 5 requests per second
///     .build();
/// ```
pub struct EuvdClientBuilder {
    base_url: String,
    rate_limit: u32,
    client: Option<Client>,
}

impl EuvdClientBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom base URL (useful for testing)
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set the rate limit in requests per second (default: 10)
    pub fn rate_limit(mut self, requests_per_second: u32) -> Self {
        self.rate_limit = requests_per_second;
        self
    }

    /// Set a custom reqwest client
    pub fn client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Build the client with the configured settings
    pub fn build(self) -> EuvdClient {
        EuvdClient {
            client: self.client.unwrap_or_default(),
            base_url: self.base_url,
            rate_limiter: RateLimiter::new(self.rate_limit),
        }
    }
}

impl Default for EuvdClientBuilder {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            rate_limit: 10,
            client: None,
        }
    }
}

/// Parse CSV body into a list of CVE-EUVD mappings.
/// Skips the header row and any malformed/empty rows.
pub(crate) fn parse_csv_mapping(body: &str) -> Vec<CveEuvdMapping> {
    body.lines()
        .skip(1) // skip header row
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let mut parts = line.splitn(2, ',');
            let euvd_id = parts.next()?.trim().to_string();
            let cve_id = parts.next()?.trim().to_string();
            if euvd_id.is_empty() || cve_id.is_empty() {
                warn!("Skipping malformed CSV row: {}", line);
                return None;
            }
            Some(CveEuvdMapping { euvd_id, cve_id })
        })
        .collect()
}

/// Search parameters for filtering vulnerabilities
///
/// # Example
///
/// ```
/// use euvd_rs::SearchParams;
///
/// // Search by text
/// let params = SearchParams {
///     text: Some("Microsoft".to_string()),
///     from_score: None,
///     to_score: None,
/// };
///
/// // Search by score range
/// let params = SearchParams {
///     text: None,
///     from_score: Some(9),
///     to_score: Some(10),
/// };
/// ```
#[derive(Clone, Debug, Default)]
pub struct SearchParams {
    /// Text search query
    pub text: Option<String>,
    /// Minimum CVSS score (0-10)
    pub from_score: Option<u32>,
    /// Maximum CVSS score (0-10)
    pub to_score: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_mapping_happy_path() {
        let csv = "euvd_id,cve_id\nEUVD-2024-45012,CVE-2024-50831\nEUVD-2024-45013,CVE-2024-50832\n";
        let result = parse_csv_mapping(csv);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].euvd_id, "EUVD-2024-45012");
        assert_eq!(result[0].cve_id, "CVE-2024-50831");
        assert_eq!(result[1].euvd_id, "EUVD-2024-45013");
        assert_eq!(result[1].cve_id, "CVE-2024-50832");
    }

    #[test]
    fn parse_csv_mapping_empty_body() {
        let result = parse_csv_mapping("");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_csv_mapping_header_only() {
        let result = parse_csv_mapping("euvd_id,cve_id\n");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_csv_mapping_skips_malformed_rows() {
        let csv = "euvd_id,cve_id\nEUVD-2024-1,CVE-2024-1\nbadrow\n,\n,CVE-2024-2\nEUVD-2024-3,\nEUVD-2024-4,CVE-2024-4\n";
        let result = parse_csv_mapping(csv);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].euvd_id, "EUVD-2024-1");
        assert_eq!(result[1].euvd_id, "EUVD-2024-4");
    }

    #[test]
    fn parse_csv_mapping_trims_whitespace() {
        let csv = "euvd_id,cve_id\n  EUVD-2024-1 , CVE-2024-1  \n";
        let result = parse_csv_mapping(csv);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].euvd_id, "EUVD-2024-1");
        assert_eq!(result[0].cve_id, "CVE-2024-1");
    }

    #[test]
    fn parse_csv_mapping_trailing_newlines() {
        let csv = "euvd_id,cve_id\nEUVD-2024-1,CVE-2024-1\n\n\n";
        let result = parse_csv_mapping(csv);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn parse_csv_mapping_extra_commas_kept_in_cve_id() {
        // splitn(2, ',') means extra commas stay in the second field
        let csv = "euvd_id,cve_id\nEUVD-2024-1,CVE-2024-1,extra\n";
        let result = parse_csv_mapping(csv);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].cve_id, "CVE-2024-1,extra");
    }
}
