//! Usage counter implementation with deterministic rollover.
//!
//! Tracks daily and monthly usage counts with automatic rollover
//! based on UTC dates via the Clock trait.

use crate::clock::Clock;
use crate::GatewardenError;
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Usage statistics with daily and monthly counters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UsageStats {
    /// Current day's usage count.
    pub daily_count: u64,

    /// Current month's usage count.
    pub monthly_count: u64,

    /// Date of the current daily count (YYYY-MM-DD).
    pub daily_date: Option<String>,

    /// Month of the current monthly count (YYYY-MM).
    pub monthly_period: Option<String>,

    /// Total lifetime usage count.
    pub lifetime_count: u64,
}

impl UsageStats {
    /// Create new empty usage stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment usage, handling rollovers based on clock.
    pub fn increment(&mut self, clock: &dyn Clock) {
        let now = clock.now_utc();
        let today = format_date(&now);
        let this_month = format_month(&now);

        // Check for daily rollover
        if self.daily_date.as_ref() != Some(&today) {
            self.daily_count = 0;
            self.daily_date = Some(today);
        }

        // Check for monthly rollover
        if self.monthly_period.as_ref() != Some(&this_month) {
            self.monthly_count = 0;
            self.monthly_period = Some(this_month);
        }

        self.daily_count += 1;
        self.monthly_count += 1;
        self.lifetime_count += 1;
    }

    /// Get the current daily count, applying rollover if needed.
    pub fn get_daily_count(&self, clock: &dyn Clock) -> u64 {
        let now = clock.now_utc();
        let today = format_date(&now);

        if self.daily_date.as_ref() == Some(&today) {
            self.daily_count
        } else {
            0
        }
    }

    /// Get the current monthly count, applying rollover if needed.
    pub fn get_monthly_count(&self, clock: &dyn Clock) -> u64 {
        let now = clock.now_utc();
        let this_month = format_month(&now);

        if self.monthly_period.as_ref() == Some(&this_month) {
            self.monthly_count
        } else {
            0
        }
    }
}

/// Format a DateTime as YYYY-MM-DD for daily tracking.
fn format_date(dt: &DateTime<Utc>) -> String {
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month(), dt.day())
}

/// Format a DateTime as YYYY-MM for monthly tracking.
fn format_month(dt: &DateTime<Utc>) -> String {
    format!("{:04}-{:02}", dt.year(), dt.month())
}

/// File-based usage meter store.
pub struct UsageMeter {
    /// Path to the usage stats file.
    path: PathBuf,
    /// Current usage stats.
    stats: UsageStats,
}

impl UsageMeter {
    /// Create a new usage meter at the given path.
    pub fn new(path: PathBuf) -> Result<Self, GatewardenError> {
        let stats = if path.exists() {
            let json = fs::read_to_string(&path)
                .map_err(|e| GatewardenError::MeterIO(format!("Failed to read meter: {}", e)))?;
            serde_json::from_str(&json)
                .map_err(|e| GatewardenError::MeterIO(format!("Failed to parse meter: {}", e)))?
        } else {
            UsageStats::new()
        };

        Ok(Self { path, stats })
    }

    /// Create a usage meter with a namespace under data_dir.
    pub fn with_namespace(namespace: &str) -> Result<Self, GatewardenError> {
        let base_dir = dirs::data_dir()
            .ok_or_else(|| GatewardenError::MeterIO("Could not find data directory".to_string()))?;

        let dir = base_dir.join(namespace);
        fs::create_dir_all(&dir)
            .map_err(|e| GatewardenError::MeterIO(format!("Failed to create dir: {}", e)))?;

        let path = dir.join("usage.json");
        Self::new(path)
    }

    /// Increment usage and persist.
    pub fn increment(&mut self, clock: &dyn Clock) -> Result<(), GatewardenError> {
        self.stats.increment(clock);
        self.save()
    }

    /// Get current daily count.
    pub fn daily_count(&self, clock: &dyn Clock) -> u64 {
        self.stats.get_daily_count(clock)
    }

    /// Get current monthly count.
    pub fn monthly_count(&self, clock: &dyn Clock) -> u64 {
        self.stats.get_monthly_count(clock)
    }

    /// Get lifetime count.
    pub fn lifetime_count(&self) -> u64 {
        self.stats.lifetime_count
    }

    /// Get a copy of the raw stats.
    pub fn stats(&self) -> &UsageStats {
        &self.stats
    }

    /// Save stats to disk.
    fn save(&self) -> Result<(), GatewardenError> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| GatewardenError::MeterIO(format!("Failed to create dir: {}", e)))?;
        }

        let json = serde_json::to_string_pretty(&self.stats)
            .map_err(|e| GatewardenError::MeterIO(format!("Failed to serialize: {}", e)))?;

        // Atomic write via temp + rename
        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, &json)
            .map_err(|e| GatewardenError::MeterIO(format!("Failed to write temp: {}", e)))?;
        fs::rename(&temp_path, &self.path)
            .map_err(|e| GatewardenError::MeterIO(format!("Failed to rename: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use chrono::TimeZone;
    use tempfile::TempDir;

    #[test]
    fn test_usage_stats_increment() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut stats = UsageStats::new();

        stats.increment(&clock);
        assert_eq!(stats.daily_count, 1);
        assert_eq!(stats.monthly_count, 1);
        assert_eq!(stats.lifetime_count, 1);

        stats.increment(&clock);
        assert_eq!(stats.daily_count, 2);
        assert_eq!(stats.monthly_count, 2);
        assert_eq!(stats.lifetime_count, 2);
    }

    #[test]
    fn test_usage_stats_daily_rollover() {
        let clock1 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut stats = UsageStats::new();

        stats.increment(&clock1);
        stats.increment(&clock1);
        assert_eq!(stats.daily_count, 2);

        // Next day
        let clock2 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 16, 12, 0, 0).unwrap());
        stats.increment(&clock2);
        assert_eq!(stats.daily_count, 1);
        assert_eq!(stats.monthly_count, 3); // Same month
        assert_eq!(stats.lifetime_count, 3);
    }

    #[test]
    fn test_usage_stats_monthly_rollover() {
        let clock1 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 31, 23, 59, 0).unwrap());
        let mut stats = UsageStats::new();

        stats.increment(&clock1);
        assert_eq!(stats.daily_count, 1);
        assert_eq!(stats.monthly_count, 1);

        // Next month
        let clock2 = MockClock::new(Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap());
        stats.increment(&clock2);
        assert_eq!(stats.daily_count, 1); // New day
        assert_eq!(stats.monthly_count, 1); // Reset for new month
        assert_eq!(stats.lifetime_count, 2);
    }

    #[test]
    fn test_usage_stats_year_rollover() {
        let clock1 = MockClock::new(Utc.with_ymd_and_hms(2024, 12, 31, 23, 59, 0).unwrap());
        let mut stats = UsageStats::new();

        stats.increment(&clock1);

        // New year
        let clock2 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap());
        stats.increment(&clock2);
        assert_eq!(stats.daily_count, 1);
        assert_eq!(stats.monthly_count, 1);
        assert_eq!(stats.lifetime_count, 2);
    }

    #[test]
    fn test_get_counts_with_rollover() {
        let clock1 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut stats = UsageStats::new();

        stats.increment(&clock1);
        stats.increment(&clock1);

        // Query on same day - should see counts
        assert_eq!(stats.get_daily_count(&clock1), 2);
        assert_eq!(stats.get_monthly_count(&clock1), 2);

        // Query on next day - daily should be 0 (rollover)
        let clock2 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 16, 12, 0, 0).unwrap());
        assert_eq!(stats.get_daily_count(&clock2), 0);
        assert_eq!(stats.get_monthly_count(&clock2), 2); // Same month

        // Query in next month - monthly should be 0
        let clock3 = MockClock::new(Utc.with_ymd_and_hms(2025, 2, 1, 12, 0, 0).unwrap());
        assert_eq!(stats.get_daily_count(&clock3), 0);
        assert_eq!(stats.get_monthly_count(&clock3), 0);
    }

    #[test]
    fn test_usage_meter_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("usage.json");
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());

        // Create and increment
        {
            let mut meter = UsageMeter::new(path.clone()).unwrap();
            meter.increment(&clock).unwrap();
            meter.increment(&clock).unwrap();
        }

        // Reload and verify
        {
            let meter = UsageMeter::new(path).unwrap();
            assert_eq!(meter.daily_count(&clock), 2);
            assert_eq!(meter.monthly_count(&clock), 2);
            assert_eq!(meter.lifetime_count(), 2);
        }
    }

    #[test]
    fn test_usage_meter_daily_rollover() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("usage.json");

        // Day 1
        let clock1 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        {
            let mut meter = UsageMeter::new(path.clone()).unwrap();
            meter.increment(&clock1).unwrap();
            meter.increment(&clock1).unwrap();
        }

        // Day 2
        let clock2 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 16, 12, 0, 0).unwrap());
        {
            let mut meter = UsageMeter::new(path).unwrap();
            meter.increment(&clock2).unwrap();
            assert_eq!(meter.daily_count(&clock2), 1);
            assert_eq!(meter.monthly_count(&clock2), 3);
            assert_eq!(meter.lifetime_count(), 3);
        }
    }

    #[test]
    fn test_usage_meter_monthly_rollover() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("usage.json");

        // January
        let clock1 = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 31, 23, 59, 0).unwrap());
        {
            let mut meter = UsageMeter::new(path.clone()).unwrap();
            meter.increment(&clock1).unwrap();
            meter.increment(&clock1).unwrap();
        }

        // February
        let clock2 = MockClock::new(Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap());
        {
            let mut meter = UsageMeter::new(path).unwrap();
            meter.increment(&clock2).unwrap();
            assert_eq!(meter.daily_count(&clock2), 1);
            assert_eq!(meter.monthly_count(&clock2), 1);
            assert_eq!(meter.lifetime_count(), 3);
        }
    }
}
