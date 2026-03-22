use serde::{Deserialize, Serialize};

/// A vulnerability record from the EUVD database
///
/// Contains comprehensive information about a security vulnerability including
/// CVSS scores, affected products and vendors, CVE mappings, and exploitation status.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    /// EUVD identifier (e.g., "EUVD-2024-45012")
    pub id: String,
    /// ENISA UUID for this vulnerability
    pub enisa_uuid: String,
    /// Detailed description of the vulnerability
    pub description: String,
    /// Date when the vulnerability was first published
    pub date_published: String,
    /// Date of the last update
    pub date_updated: String,
    /// CVSS base score (0.0-10.0, or -1.0 if not available)
    #[serde(default)]
    pub base_score: f64,
    /// CVSS version (e.g., "3.1", "4.0")
    #[serde(default)]
    pub base_score_version: Option<String>,
    /// CVSS vector string
    #[serde(default)]
    pub base_score_vector: Option<String>,
    /// URLs to references and advisories
    #[serde(default)]
    pub references: Option<String>,
    /// CVE IDs and other aliases
    #[serde(default)]
    pub aliases: Option<String>,
    /// Organization that assigned this vulnerability
    pub assigner: String,
    /// EPSS (Exploit Prediction Scoring System) score
    pub epss: f64,
    /// Date when exploitation was first observed (if exploited)
    #[serde(default)]
    pub exploited_since: Option<String>,
    /// Affected products
    pub enisa_id_product: Vec<ProductRelation>,
    /// Related vendors
    pub enisa_id_vendor: Vec<VendorRelation>,
    /// Related vulnerability details
    #[serde(default)]
    pub enisa_id_vulnerability: Vec<VulnerabilityRelation>,
    /// Related security advisories
    #[serde(default)]
    pub enisa_id_advisory: Vec<AdvisoryRelation>,
}

/// Relationship between a vulnerability and an affected product
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProductRelation {
    /// Relation identifier
    pub id: String,
    /// Product information
    pub product: Product,
    /// Affected version(s)
    pub product_version: String,
}

/// Product information
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Product {
    /// Product name
    pub name: String,
}

/// Relationship between a vulnerability and a vendor
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VendorRelation {
    /// Relation identifier
    pub id: String,
    /// Vendor information
    pub vendor: Vendor,
}

/// Vendor information
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Vendor {
    /// Vendor name
    pub name: String,
}

/// Relationship to detailed vulnerability information
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityRelation {
    /// Relation identifier
    pub id: String,
    /// Detailed vulnerability data
    pub vulnerability: VulnerabilityDetail,
}

/// Detailed vulnerability information from nested API responses
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityDetail {
    /// CVE or other vulnerability identifier
    pub id: String,
    /// Vulnerability description
    pub description: String,
    /// Publication date
    pub date_published: String,
    /// Last update date
    pub date_updated: String,
    /// Publication status
    pub status: String,
    /// CVSS base score
    pub base_score: f64,
    /// Reference URLs
    #[serde(default)]
    pub references: Option<String>,
    /// EUVD identifier
    #[serde(rename = "enisa_id")]
    pub enisa_id: String,
    /// Assigning organization
    pub assigner: String,
    /// EPSS score
    pub epss: f64,
    /// Data processing timestamp
    pub data_processed: String,
    /// Related products
    pub vulnerability_product: Vec<ProductRelation>,
    /// Related vendors
    pub vulnerability_vendor: Vec<VendorRelation>,
}

/// Relationship to a security advisory
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AdvisoryRelation {
    /// Advisory identifier
    pub id: String,
}

/// List of vulnerabilities
pub type VulnerabilityList = Vec<Vulnerability>;

/// Paginated search response from the EUVD search endpoint
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SearchResponse {
    /// Matching vulnerabilities
    pub items: Vec<Vulnerability>,
    /// Total number of matching results
    pub total: u64,
}

/// A mapping between a CVE ID and an EUVD ID from the bulk dump endpoint
#[derive(Clone, Debug, PartialEq)]
pub struct CveEuvdMapping {
    /// EUVD identifier (e.g., "EUVD-2024-45012")
    pub euvd_id: String,
    /// CVE identifier (e.g., "CVE-2024-50831")
    pub cve_id: String,
}
