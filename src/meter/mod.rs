//! Per-license-key usage metering.
//!
//! This exposes a file-backed, offline-enforceable usage counter keyed by the
//! license-key hash. It is gated behind the `meter` cargo feature.

pub mod usage;

pub use usage::UsageMeter;

#[cfg(test)]
mod tests {
    use super::usage::{UsageMeter, UsageStats};
    use crate::clock::MockClock;
    use chrono::{TimeZone, Utc};
    use std::collections::HashMap;

    #[test]
    fn test_usage_stats_increment_and_rollover() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut stats = UsageStats::new();
        stats.increment(&clock);
        stats.increment(&clock);
        assert_eq!(stats.daily_count, 2);
        assert_eq!(stats.monthly_count, 2);
        assert_eq!(stats.lifetime_count, 2);

        let next_day = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 16, 12, 0, 0).unwrap());
        stats.increment(&next_day);
        assert_eq!(stats.daily_count, 1);
        assert_eq!(stats.monthly_count, 3);
        assert_eq!(stats.lifetime_count, 3);
    }

    #[test]
    fn test_per_key_store() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut store = HashMap::new();
        store
            .entry("key-a".to_string())
            .or_insert_with(UsageStats::new)
            .increment(&clock);
        store
            .entry("key-b".to_string())
            .or_insert_with(UsageStats::new)
            .increment(&clock);
        assert_eq!(store.get("key-a").unwrap().monthly_count, 1);
        assert_eq!(store.get("key-b").unwrap().monthly_count, 1);
    }

    #[test]
    fn test_meter_roundtrip_dir_helpers() {
        // Smoke check that the module wiring compiles and the public surface exists.
        let _ = UsageMeter::with_namespace;
    }
}
