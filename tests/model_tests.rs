use euvd_rs::models::{Vulnerability, VulnerabilityList};

#[test]
fn test_deserialize_latest_vulnerabilities() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let result: Result<VulnerabilityList, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_deserialize_latest_vulnerabilities_count() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert_eq!(vulns.len(), 2);
}

#[test]
fn test_deserialize_latest_vulnerabilities_first_id() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert_eq!(vulns[0].id, "EUVD-2023-58662");
}

#[test]
fn test_deserialize_exploited_vulnerabilities() {
    let json = include_str!("fixtures/exploited_vulnerabilities.json");
    let result: Result<VulnerabilityList, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_deserialize_exploited_vulnerabilities_has_exploited_since() {
    let json = include_str!("fixtures/exploited_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert!(vulns[0].exploited_since.is_some());
}

#[test]
fn test_deserialize_critical_vulnerabilities() {
    let json = include_str!("fixtures/critical_vulnerabilities.json");
    let result: Result<VulnerabilityList, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_deserialize_vulnerability_by_id() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let result: Result<Vulnerability, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_deserialize_vulnerability_by_id_fields() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let vuln: Vulnerability = serde_json::from_str(json).unwrap();
    assert_eq!(vuln.id, "EUVD-2024-45012");
}

#[test]
fn test_deserialize_vulnerability_by_id_has_relations() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let vuln: Vulnerability = serde_json::from_str(json).unwrap();
    assert!(!vuln.enisa_id_vulnerability.is_empty());
}

#[test]
fn test_vulnerability_clone() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let vuln: Vulnerability = serde_json::from_str(json).unwrap();
    let cloned = vuln.clone();
    assert_eq!(vuln, cloned);
}

#[test]
fn test_vulnerability_debug() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let vuln: Vulnerability = serde_json::from_str(json).unwrap();
    let debug_str = format!("{:?}", vuln);
    assert!(debug_str.contains("EUVD-2024-45012"));
}

#[test]
fn test_serialize_vulnerability() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let vuln: Vulnerability = serde_json::from_str(json).unwrap();
    let serialized = serde_json::to_string(&vuln);
    assert!(serialized.is_ok());
}

#[test]
fn test_vulnerability_partial_eq() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let vuln1: Vulnerability = serde_json::from_str(json).unwrap();
    let vuln2: Vulnerability = serde_json::from_str(json).unwrap();
    assert_eq!(vuln1, vuln2);
}

#[test]
fn test_vulnerability_has_products() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert!(!vulns[0].enisa_id_product.is_empty());
}

#[test]
fn test_vulnerability_has_vendors() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert!(!vulns[0].enisa_id_vendor.is_empty());
}

#[test]
fn test_vulnerability_product_name() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert_eq!(
        vulns[0].enisa_id_product[0].product.name,
        "Online Clinic Management System"
    );
}

#[test]
fn test_vulnerability_vendor_name() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert_eq!(vulns[0].enisa_id_vendor[0].vendor.name, "BigProf ");
}

#[test]
fn test_vulnerability_epss_score() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert_eq!(vulns[0].epss, 0.17);
}

#[test]
fn test_vulnerability_base_score() {
    let json = include_str!("fixtures/latest_vulnerabilities.json");
    let vulns: VulnerabilityList = serde_json::from_str(json).unwrap();
    assert_eq!(vulns[0].base_score, 6.3);
}

#[test]
fn test_deserialize_vulnerability_with_ghsa_nested() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let vuln: Vulnerability = serde_json::from_str(json).unwrap();
    assert_eq!(vuln.enisa_id_vulnerability.len(), 2);
    let ghsa = &vuln.enisa_id_vulnerability[0].vulnerability;
    assert!(ghsa.id.starts_with("GHSA-"));
    assert!(ghsa.status.is_none());
    assert!(ghsa.assigner.is_none());
}

#[test]
fn test_deserialize_vulnerability_with_cve_nested() {
    let json = include_str!("fixtures/vulnerability_by_id.json");
    let vuln: Vulnerability = serde_json::from_str(json).unwrap();
    let cve = &vuln.enisa_id_vulnerability[1].vulnerability;
    assert!(cve.id.starts_with("CVE-"));
    assert!(cve.status.is_some());
    assert!(cve.assigner.is_some());
    assert!(cve.base_score_version.is_some());
}

#[test]
fn test_deserialize_vulnerability_with_advisory() {
    let json = include_str!("fixtures/vulnerability_with_advisory.json");
    let vuln: Vulnerability = serde_json::from_str(json).unwrap();
    assert!(!vuln.enisa_id_advisory.is_empty());
    let advisory = &vuln.enisa_id_advisory[0].advisory;
    assert!(!advisory.id.is_empty());
    assert!(!advisory.description.is_empty());
    assert!(advisory.source.is_some());
    assert!(!advisory.advisory_product.is_empty());
}
