//! Per-license-key usage counter implementation with deterministic rollover.
//!
//! Tracks daily / monthly / lifetime usage counts **per license key** (keyed by
//! the license-key hash) with automatic, clock-driven rollover. This is the
//! building block behind `LicenseManager::record_use`: it lets Gatewarden enforce
//! a usage cap locally and offline, independently of Keygen's server-side counter.

use crate::clock::Clock;
use crate::GatewardenError;
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Usage statistics for a single license key.
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

    /// Increment usage, handling rollovers based on the clock.
    pub fn increment(&mut self, clock: &dyn Clock) {
        let now = clock.now_utc();
        let today = format_date(&now);
        let this_month = format_month(&now);

        if self.daily_date.as_ref() != Some(&today) {
            self.daily_count = 0;
            self.daily_date = Some(today);
        }

        if self.monthly_period.as_ref() != Some(&this_month) {
            self.monthly_count = 0;
            self.monthly_period = Some(this_month);
        }

        self.daily_count += 1;
        self.monthly_count += 1;
        self.lifetime_count += 1;
    }

    /// Current daily count, applying rollover if the day changed.
    pub fn get_daily_count(&self, clock: &dyn Clock) -> u64 {
        let today = format_date(&clock.now_utc());
        if self.daily_date.as_ref() == Some(&today) {
            self.daily_count
        } else {
            0
        }
    }

    /// Current monthly count, applying rollover if the month changed.
    pub fn get_monthly_count(&self, clock: &dyn Clock) -> u64 {
        let this_month = format_month(&clock.now_utc());
        if self.monthly_period.as_ref() == Some(&this_month) {
            self.monthly_count
        } else {
            0
        }
    }
}

fn format_date(dt: &DateTime<Utc>) -> String {
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month(), dt.day())
}

fn format_month(dt: &DateTime<Utc>) -> String {
    format!("{:04}-{:02}", dt.year(), dt.month())
}

/// On-disk shape: a map from license-key hash to that key's [`UsageStats`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MeterStore {
    per_key: HashMap<String, UsageStats>,
}

/// File-backed, per-license-key usage meter store.
pub struct UsageMeter {
    path: PathBuf,
    store: MeterStore,
}

impl UsageMeter {
    /// Open (or initialize) a meter at the given path.
    pub fn new(path: PathBuf) -> Result<Self, GatewardenError> {
        let store = if path.exists() {
            let json = fs::read_to_string(&path)
                .map_err(|e| GatewardenError::MeterIO(format!("Failed to read meter: {}", e)))?;
            serde_json::from_str(&json)
                .map_err(|e| GatewardenError::MeterIO(format!("Failed to parse meter: {}", e)))?
        } else {
            MeterStore::default()
        };

        Ok(Self { path, store })
    }

    /// Open a meter under `dirs::data_dir()/<namespace>/usage.json`.
    pub fn with_namespace(namespace: &str) -> Result<Self, GatewardenError> {
        let base_dir = dirs::data_dir()
            .ok_or_else(|| GatewardenError::MeterIO("Could not find data directory".to_string()))?;

        let dir = base_dir.join(namespace);
        fs::create_dir_all(&dir)
            .map_err(|e| GatewardenError::MeterIO(format!("Failed to create dir: {}", e)))?;

        Self::new(dir.join("usage.json"))
    }

    /// Increment the counter for `key_hash` and persist.
    pub fn increment(&mut self, key_hash: &str, clock: &dyn Clock) -> Result<(), GatewardenError> {
        self.store
            .per_key
            .entry(key_hash.to_string())
            .or_default()
            .increment(clock);
        self.save()
    }

    /// Current daily count for `key_hash` (rollover-aware).
    pub fn daily_count(&self, key_hash: &str, clock: &dyn Clock) -> u64 {
        self.store
            .per_key
            .get(key_hash)
            .map(|s| s.get_daily_count(clock))
            .unwrap_or(0)
    }

    /// Current monthly count for `key_hash` (rollover-aware).
    pub fn monthly_count(&self, key_hash: &str, clock: &dyn Clock) -> u64 {
        self.store
            .per_key
            .get(key_hash)
            .map(|s| s.get_monthly_count(clock))
            .unwrap_or(0)
    }

    /// Lifetime count for `key_hash`.
    pub fn lifetime_count(&self, key_hash: &str) -> u64 {
        self.store
            .per_key
            .get(key_hash)
            .map(|s| s.lifetime_count)
            .unwrap_or(0)
    }

    /// Save the store to disk (atomic temp + rename).
    fn save(&self) -> Result<(), GatewardenError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| GatewardenError::MeterIO(format!("Failed to create dir: {}", e)))?;
        }

        let json = serde_json::to_string_pretty(&self.store)
            .map_err(|e| GatewardenError::MeterIO(format!("Failed to serialize: {}", e)))?;

        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, &json)
            .map_err(|e| GatewardenError::MeterIO(format!("Failed to write temp: {}", e)))?;
        fs::rename(&temp_path, &self.path)
            .map_err(|e| GatewardenError::MeterIO(format!("Failed to rename: {}", e)))?;

        Ok(())
    }
}
