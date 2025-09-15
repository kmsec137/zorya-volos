use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::SystemTime;

pub type PanicReachSet = Arc<HashSet<u64>>;
pub type PanicReachRanges = Arc<BTreeMap<u64, u64>>; // start -> end

pub fn precompute_panic_reach(
    binary_path: &str,
) -> Result<(PanicReachSet, PanicReachRanges), Box<dyn Error>> {
    let out_file = "results/panic_reachable.txt";
    let xref_file = "results/xref_addresses.txt";
    // Run the Python precompute if output is missing/empty, or xrefs are newer, or forced via env
    let mut need_run = !Path::new(out_file).exists()
        || fs::metadata(out_file).map(|m| m.len() == 0).unwrap_or(true);

    if !need_run && Path::new(out_file).exists() && Path::new(xref_file).exists() {
        if let (Ok(out_meta), Ok(xref_meta)) = (fs::metadata(out_file), fs::metadata(xref_file)) {
            if let (Ok(out_m), Ok(xref_m)) = (out_meta.modified(), xref_meta.modified()) {
                if xref_m > out_m {
                    need_run = true;
                }
            }
        }
    }

    if !need_run {
        if let Ok(force) = std::env::var("PANIC_REACH_FORCE") {
            let force = force == "1" || force.to_lowercase() == "true";
            if force {
                need_run = true;
            }
        }
    }
    if need_run {
        let status = Command::new("python3")
            .arg("scripts/precompute_panic_reach.py")
            .arg(binary_path)
            .status()?;
        if !status.success() {
            return Err("precompute_panic_reach.py failed".into());
        }
    }

    // Load the set and ranges from file
    let mut set = HashSet::new();
    let mut ranges = BTreeMap::new();
    if let Ok(content) = fs::read_to_string(out_file) {
        for line in content.lines() {
            let s = line.trim();
            if s.is_empty() {
                continue;
            }
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let start_hex = parts[0].strip_prefix("0x").unwrap_or(parts[0]);
            if let Ok(start) = u64::from_str_radix(start_hex, 16) {
                set.insert(start);
                if parts.len() >= 2 {
                    let end_hex = parts[1].strip_prefix("0x").unwrap_or(parts[1]);
                    if let Ok(end) = u64::from_str_radix(end_hex, 16) {
                        ranges.insert(start, end);
                    }
                }
            }
        }
    }
    Ok((Arc::new(set), Arc::new(ranges)))
}

pub fn is_panic_reachable_addr(
    addr: u64,
    starts: &PanicReachSet,
    ranges: &PanicReachRanges,
) -> bool {
    if starts.contains(&addr) {
        return true;
    }
    // range-aware: find greatest start <= addr and check end >= addr
    if let Some((&s, &e)) = ranges.range(..=addr).next_back() {
        return addr >= s && addr <= e;
    }
    false
}
