//! Gateway load-test tool for zhtp-daemon
//!
//! Measures throughput and latency against any HTTP endpoint exposed by the
//! daemon (e.g. /healthz, /metrics, /api/v1/status).
//!
//! # Usage
//! ```bash
//! cargo run --bin gateway_load_test -- \
//!     --url http://127.0.0.1:7840/healthz \
//!     --concurrency 50 \
//!     --duration 30
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let args = parse_args();
    println!(
        "🔥 Gateway Load Test\n  URL: {}\n  Concurrency: {}\n  Duration: {}s\n",
        args.url, args.concurrency, args.duration_secs
    );

    let client = reqwest::blocking::Client::new();
    let total_requests = Arc::new(AtomicU64::new(0));
    let success_requests = Arc::new(AtomicU64::new(0));
    let failed_requests = Arc::new(AtomicU64::new(0));
    let latencies: Arc<std::sync::Mutex<Vec<u64>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..args.concurrency {
        let client = client.clone();
        let url = args.url.clone();
        let total = Arc::clone(&total_requests);
        let success = Arc::clone(&success_requests);
        let failed = Arc::clone(&failed_requests);
        let lats = Arc::clone(&latencies);
        let deadline = start + Duration::from_secs(args.duration_secs);

        handles.push(std::thread::spawn(move || {
            while Instant::now() < deadline {
                let req_start = Instant::now();
                let result = client.get(&url).timeout(Duration::from_secs(5)).send();
                let latency_us = req_start.elapsed().as_micros() as u64;

                total.fetch_add(1, Ordering::Relaxed);
                match result {
                    Ok(resp) if resp.status().is_success() => {
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(resp) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        eprintln!("  non-2xx: {}", resp.status());
                    }
                    Err(e) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        eprintln!("  error: {}", e);
                    }
                }
                lats.lock().unwrap().push(latency_us);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start.elapsed().as_secs_f64();
    let total = total_requests.load(Ordering::Relaxed);
    let success = success_requests.load(Ordering::Relaxed);
    let failed = failed_requests.load(Ordering::Relaxed);

    let mut latencies = latencies.lock().unwrap();
    latencies.sort_unstable();

    let p50 = percentile(&latencies, 0.50);
    let p95 = percentile(&latencies, 0.95);
    let p99 = percentile(&latencies, 0.99);
    let min = latencies.first().copied().unwrap_or(0);
    let max = latencies.last().copied().unwrap_or(0);

    println!("\n📊 Results");
    println!("  Duration:     {:.2} s", elapsed);
    println!("  Total:        {}", total);
    println!("  Success:      {}", success);
    println!("  Failed:       {}", failed);
    println!("  RPS:          {:.0}", total as f64 / elapsed);
    println!("  Latency min:  {:.2} ms", min as f64 / 1000.0);
    println!("  Latency p50:  {:.2} ms", p50 as f64 / 1000.0);
    println!("  Latency p95:  {:.2} ms", p95 as f64 / 1000.0);
    println!("  Latency p99:  {:.2} ms", p99 as f64 / 1000.0);
    println!("  Latency max:  {:.2} ms", max as f64 / 1000.0);
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

struct Args {
    url: String,
    concurrency: u64,
    duration_secs: u64,
}

fn parse_args() -> Args {
    let mut url = "http://127.0.0.1:7840/healthz".to_string();
    let mut concurrency = 50u64;
    let mut duration_secs = 30u64;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--url" => url = args.next().expect("--url requires a value"),
            "--concurrency" => concurrency = args.next().expect("--concurrency requires a value").parse().expect("invalid number"),
            "--duration" => duration_secs = args.next().expect("--duration requires a value").parse().expect("invalid number"),
            _ => {}
        }
    }

    Args { url, concurrency, duration_secs }
}
