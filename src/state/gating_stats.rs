use std::sync::atomic::{AtomicU64, Ordering};

static GATED_BY_REACH: AtomicU64 = AtomicU64::new(0);
static ALLOWED_BY_XREF_FALLBACK: AtomicU64 = AtomicU64::new(0);

pub fn inc_gated_by_reach() {
    GATED_BY_REACH.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_allowed_by_xref_fallback() {
    ALLOWED_BY_XREF_FALLBACK.fetch_add(1, Ordering::Relaxed);
}

pub fn get_gated_by_reach() -> u64 {
    GATED_BY_REACH.load(Ordering::Relaxed)
}

pub fn get_allowed_by_xref_fallback() -> u64 {
    ALLOWED_BY_XREF_FALLBACK.load(Ordering::Relaxed)
}

pub fn reset() {
    GATED_BY_REACH.store(0, Ordering::Relaxed);
    ALLOWED_BY_XREF_FALLBACK.store(0, Ordering::Relaxed);
}
