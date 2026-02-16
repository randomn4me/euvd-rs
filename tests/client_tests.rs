use euvd_rs::{EuvdClient, SearchParams};
use mockito::{Matcher, Server};

#[tokio::test]
async fn test_client_builder_default() {
    let client = EuvdClient::builder().build();
    assert_eq!(
        format!("{:?}", client).contains("EuvdClient"),
        true
    );
}

#[tokio::test]
async fn test_client_builder_custom_base_url() {
    let client = EuvdClient::builder()
        .base_url("https://example.com/api")
        .build();
    assert_eq!(
        format!("{:?}", client).contains("EuvdClient"),
        true
    );
}

#[tokio::test]
async fn test_client_builder_custom_rate_limit() {
    let client = EuvdClient::builder().rate_limit(5).build();
    assert_eq!(
        format!("{:?}", client).contains("EuvdClient"),
        true
    );
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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

    let result = client.get_by_id("EUVD-INVALID").await;
    assert!(result.is_err());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_with_text() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/latest_vulnerabilities.json");

    let mock = server
        .mock("GET", "/search")
        .match_query(Matcher::UrlEncoded("text".into(), "Microsoft".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

    let params = SearchParams {
        text: Some("Microsoft".to_string()),
        from_score: None,
        to_score: None,
    };

    let result = client.search(&params).await;
    assert!(result.is_ok());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_with_score_range() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/critical_vulnerabilities.json");

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

    let params = SearchParams {
        text: None,
        from_score: Some(9),
        to_score: Some(10),
    };

    let result = client.search(&params).await;
    assert!(result.is_ok());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_by_cve() {
    let mut server = Server::new_async().await;
    let fixture = include_str!("fixtures/latest_vulnerabilities.json");

    let mock = server
        .mock("GET", "/search")
        .match_query(Matcher::UrlEncoded("text".into(), "CVE-2023-6425".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(fixture)
        .create_async()
        .await;

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

    let result = client.get_by_cve("CVE-2023-6425").await;
    assert!(result.is_ok());

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

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

    let client = EuvdClient::builder()
        .base_url(server.url())
        .build();

    let result = client.latest_vulnerabilities().await;
    assert!(result.is_err());

    mock.assert_async().await;
}
