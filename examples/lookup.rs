use euvd_rs::{EuvdClient, SearchParams};
use std::env;

#[tokio::main]
async fn main() -> euvd_rs::Result<()> {
    let client = EuvdClient::new();

    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("latest");

    match command {
        "latest" => {
            let vulns = client.latest_vulnerabilities().await?;
            println!("Latest vulnerabilities ({} results):\n", vulns.len());
            for v in &vulns {
                println!(
                    "  {} (CVSS {:.1}) - {}",
                    v.id,
                    v.base_score,
                    truncate(&v.description, 80)
                );
            }
        }
        "exploited" => {
            let vulns = client.exploited_vulnerabilities().await?;
            println!("Exploited vulnerabilities ({} results):\n", vulns.len());
            for v in &vulns {
                let since = v
                    .exploited_since
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                println!(
                    "  {} (since {}) - {}",
                    v.id,
                    since,
                    truncate(&v.description, 60)
                );
            }
        }
        "critical" => {
            let vulns = client.critical_vulnerabilities().await?;
            println!("Critical vulnerabilities ({} results):\n", vulns.len());
            for v in &vulns {
                println!(
                    "  {} (CVSS {:.1}) - {}",
                    v.id,
                    v.base_score,
                    truncate(&v.description, 80)
                );
            }
        }
        "search" => {
            let query = args.get(2).expect("Usage: lookup search <query>");
            let params = SearchParams {
                text: Some(query.clone()),
                ..Default::default()
            };
            let result = client.search(&params).await?;
            println!(
                "Search results for '{}' ({} of {} total):\n",
                query,
                result.items.len(),
                result.total
            );
            for v in &result.items {
                println!(
                    "  {} (CVSS {:.1}) - {}",
                    v.id,
                    v.base_score,
                    truncate(&v.description, 80)
                );
            }
        }
        "id" => {
            let id = args.get(2).expect("Usage: lookup id <EUVD-ID>");
            let v = client.get_by_id(id).await?;
            println!("{}", v.id);
            println!(
                "  Score:       {:.1} ({})",
                v.base_score,
                v.base_score_version.as_deref().unwrap_or("n/a")
            );
            println!("  Published:   {}", v.date_published);
            println!("  Updated:     {}", v.date_updated);
            println!("  Assigner:    {}", v.assigner);
            println!("  EPSS:        {:.4}", v.epss);
            if !v.aliases.is_empty() {
                println!("  Aliases:     {}", v.aliases.join(", "));
            }
            println!("  Description: {}", v.description);
            if !v.enisa_id_advisory.is_empty() {
                println!("\n  Advisories ({}):", v.enisa_id_advisory.len());
                for rel in &v.enisa_id_advisory {
                    let a = &rel.advisory;
                    let source = a
                        .source
                        .as_ref()
                        .map(|s| s.name.as_str())
                        .unwrap_or("unknown");
                    println!("    {} [{}]", a.id, source);
                    println!("      {}", truncate(&a.description, 70));
                }
            }
        }
        _ => {
            eprintln!("Usage: lookup <command> [args]");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  latest              List latest vulnerabilities");
            eprintln!("  exploited           List exploited vulnerabilities");
            eprintln!("  critical            List critical vulnerabilities");
            eprintln!("  search <query>      Search vulnerabilities by text");
            eprintln!("  id <EUVD-ID>        Look up a specific vulnerability");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.len() <= max {
        s
    } else {
        format!("{}...", &s[..max])
    }
}
