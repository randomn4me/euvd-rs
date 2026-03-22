use euvd_rs::{EuvdClient, SearchParams};
use mockito::{Matcher, Server};

#[tokio::test]
async fn test_rate_limit_zero_does_not_panic() {
    // BUG-1 regression: rate_limit(0) previously panicked via NonZeroU32::new(0).unwrap()
    let client = EuvdClient::builder().rate_limit(0).build();
    // Should not panic — just verify we got a valid client
    let _ = format!("{:?}", client);
}

#[tokio::test]
async fn test_client_builder_default() {
    let client = EuvdClient::builder().build();
    assert!(format!("{:?}", client).contains("EuvdClient"));
}

#[tokio::test]
async fn test_client_builder_custom_base_url() {
    let client = EuvdClient::builder()
        .base_url("https://example.com/api")
        .build();
    assert!(format!("{:?}", client).contains("EuvdClient"));
}

#[tokio::test]
async fn test_client_builder_custom_rate_limit() {
    let client = EuvdClient::builder().rate_limit(5).build();
    assert!(format!("{:?}", client).contains("EuvdClient"));
}

#[tokio::test]
async fn test_latest_vulnerabilities() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/latest_vulnerabilities.json");

    let mock = server
        .mock("GET", "/lastvulnerabilities")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.latest_vulnerabilities().await;
    assert!(result.is_ok());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_latest_vulnerabilities_count() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/latest_vulnerabilities.json");

    server
        .mock("GET", "/lastvulnerabilities")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.latest_vulnerabilities().await.unwrap();
    assert_eq!(result.len(), 2);
}

#[tokio::test]
async fn test_exploited_vulnerabilities() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/exploited_vulnerabilities.json");

    let mock = server
        .mock("GET", "/exploitedvulnerabilities")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.exploited_vulnerabilities().await;
    assert!(result.is_ok());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_exploited_vulnerabilities_contains_exploited_since() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/exploited_vulnerabilities.json");

    server
        .mock("GET", "/exploitedvulnerabilities")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.exploited_vulnerabilities().await.unwrap();
    assert!(result[0].exploited_since.is_some());
}

#[tokio::test]
async fn test_critical_vulnerabilities() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/critical_vulnerabilities.json");

    let mock = server
        .mock("GET", "/criticalvulnerabilities")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.critical_vulnerabilities().await;
    assert!(result.is_ok());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_by_id() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/vulnerability_by_id.json");

    let mock = server
        .mock("GET", "/enisaid")
        .match_query(Matcher::UrlEncoded("id".into(), "EUVD-2024-45012".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.get_by_id("EUVD-2024-45012").await;
    assert!(result.is_ok());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_by_id_returns_correct_id() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/vulnerability_by_id.json");

    server
        .mock("GET", "/enisaid")
        .match_query(Matcher::UrlEncoded("id".into(), "EUVD-2024-45012".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.get_by_id("EUVD-2024-45012").await.unwrap();
    assert_eq!(result.id, "EUVD-2024-45012");
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/enisaid")
        .match_query(Matcher::UrlEncoded("id".into(), "EUVD-INVALID".into()))
        .with_status(404)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.get_by_id("EUVD-INVALID").await;
    assert!(result.is_err());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_with_text() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/search_response.json");

    let mock = server
        .mock("GET", "/search")
        .match_query(Matcher::UrlEncoded("search".into(), "linux".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let params = SearchParams {
        text: Some("linux".to_string()),
        from_score: None,
        to_score: None,
    };

    let result = client.search(&params).await.unwrap();
    assert_eq!(result.total, 2);
    assert_eq!(result.items.len(), 2);

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_with_score_range() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/search_response.json");

    let mock = server
        .mock("GET", "/search")
        .match_query(Matcher::AllOf(vec![
            Matcher::UrlEncoded("fromScore".into(), "9".into()),
            Matcher::UrlEncoded("toScore".into(), "10".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let params = SearchParams {
        text: None,
        from_score: Some(9),
        to_score: Some(10),
    };

    let result = client.search(&params).await.unwrap();
    assert_eq!(result.items.len(), 2);

    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_by_cve() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/vulnerability_by_id.json");

    let mock = server
        .mock("GET", "/enisaid")
        .match_query(Matcher::UrlEncoded("id".into(), "CVE-2024-50831".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.get_by_cve("CVE-2024-50831").await.unwrap();
    assert_eq!(result.id, "EUVD-2024-45012");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_by_cve_not_found() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/enisaid")
        .match_query(Matcher::UrlEncoded("id".into(), "CVE-9999-99999".into()))
        .with_status(404)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.get_by_cve("CVE-9999-99999").await;
    assert!(result.is_err());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_list_not_found() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/lastvulnerabilities")
        .with_status(404)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.latest_vulnerabilities().await;
    assert!(matches!(
        result.unwrap_err(),
        euvd_rs::EuvdError::NotFound(_)
    ));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_cve_euvd_mapping_not_found() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/dump/cve-euvd-mapping")
        .with_status(404)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.cve_euvd_mapping().await;
    assert!(matches!(
        result.unwrap_err(),
        euvd_rs::EuvdError::NotFound(_)
    ));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_rate_limited_error() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/lastvulnerabilities")
        .with_status(429)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.latest_vulnerabilities().await;
    assert!(result.is_err());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_api_error_500() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/lastvulnerabilities")
        .with_status(500)
        .with_body("Internal Server Error")
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.latest_vulnerabilities().await;
    assert!(result.is_err());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_malformed_json_error() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/lastvulnerabilities")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("not valid json")
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.latest_vulnerabilities().await;
    assert!(result.is_err());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_cve_euvd_mapping() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/cve_euvd_mapping.csv");

    let mock = server
        .mock("GET", "/dump/cve-euvd-mapping")
        .with_status(200)
        .with_header("content-type", "text/csv")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let mappings = client.cve_euvd_mapping().await.unwrap();

    assert_eq!(mappings.len(), 3);
    assert_eq!(mappings[0].euvd_id, "EUVD-2024-45012");
    assert_eq!(mappings[0].cve_id, "CVE-2024-50831");
    assert_eq!(mappings[2].euvd_id, "EUVD-2024-45014");
    assert_eq!(mappings[2].cve_id, "CVE-2024-50833");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_cve_euvd_mapping_empty() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/dump/cve-euvd-mapping")
        .with_status(200)
        .with_header("content-type", "text/csv")
        .with_body("euvd_id,cve_id\n")
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let mappings = client.cve_euvd_mapping().await.unwrap();
    assert!(mappings.is_empty());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_cve_euvd_mapping_malformed_row() {
    let mut server = Server::new_async().await;

    let body = "euvd_id,cve_id\nEUVD-2024-45012,CVE-2024-50831\nbadrow\n,\nEUVD-2024-45014,CVE-2024-50833\n";

    let mock = server
        .mock("GET", "/dump/cve-euvd-mapping")
        .with_status(200)
        .with_header("content-type", "text/csv")
        .with_body(body)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let mappings = client.cve_euvd_mapping().await.unwrap();
    assert_eq!(mappings.len(), 2);
    assert_eq!(mappings[0].euvd_id, "EUVD-2024-45012");
    assert_eq!(mappings[1].euvd_id, "EUVD-2024-45014");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_cve_euvd_mapping_rate_limited() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/dump/cve-euvd-mapping")
        .with_status(429)
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.cve_euvd_mapping().await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        euvd_rs::EuvdError::RateLimited
    ));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_cve_euvd_mapping_server_error() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", "/dump/cve-euvd-mapping")
        .with_status(500)
        .with_body("Internal Server Error")
        .create_async()
        .await;

    let client = EuvdClient::builder().base_url(server.url()).build();

    let result = client.cve_euvd_mapping().await;
    assert!(result.is_err());
    match result.unwrap_err() {
        euvd_rs::EuvdError::Api { status, body } => {
            assert_eq!(status, 500);
            assert_eq!(body, "Internal Server Error");
        }
        other => panic!("Expected Api error, got: {:?}", other),
    }

    mock.assert_async().await;
}
