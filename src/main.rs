use std::process::ExitCode;

use clap::Parser;
use dmarccheck::validate::{validate_dkim, validate_dmarc, validate_spf, RecordStatus};
use hickory_resolver::TokioAsyncResolver;

#[derive(Parser)]
#[command(
    name = "dmarccheck",
    about = "Validates a domain's SPF/DKIM/DMARC DNS records are present and correctly formed"
)]
struct Cli {
    domain: String,
    /// DKIM selector to check (e.g. "google", "selector1"). Skipped if omitted —
    /// DKIM selectors aren't discoverable from DNS alone.
    #[arg(long)]
    selector: Option<String>,
}

async fn txt_records(resolver: &TokioAsyncResolver, name: &str) -> Vec<String> {
    match resolver.txt_lookup(name).await {
        Ok(lookup) => lookup.iter().map(|txt| txt.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

fn report(label: &str, status: &RecordStatus) -> bool {
    match status {
        RecordStatus::Missing => {
            println!("{label}: MISSING");
            false
        }
        RecordStatus::Invalid(reason) => {
            println!("{label}: INVALID — {reason}");
            false
        }
        RecordStatus::Valid(record) => {
            println!("{label}: ok — {record}");
            true
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dmarccheck: could not read system DNS config: {e}");
            return ExitCode::FAILURE;
        }
    };

    let spf_txt = txt_records(&resolver, &cli.domain).await;
    let spf = validate_spf(&spf_txt);
    let spf_ok = report("SPF", &spf);

    let dmarc_name = format!("_dmarc.{}", cli.domain);
    let dmarc_txt = txt_records(&resolver, &dmarc_name).await;
    let dmarc = validate_dmarc(&dmarc_txt);
    let dmarc_ok = report("DMARC", &dmarc);

    let mut dkim_ok = true;
    if let Some(selector) = &cli.selector {
        let dkim_name = format!("{selector}._domainkey.{}", cli.domain);
        let dkim_txt = txt_records(&resolver, &dkim_name).await;
        let dkim = validate_dkim(&dkim_txt);
        dkim_ok = report(&format!("DKIM ({selector})"), &dkim);
    } else {
        println!("DKIM: skipped — pass --selector <name> to check a specific selector");
    }

    if spf_ok && dmarc_ok && dkim_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
