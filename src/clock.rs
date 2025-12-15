//! Deterministic clock abstraction for testable time-dependent logic.

use chrono::{DateTime, Utc};

/// Clock trait for deterministic time in tests.
pub trait Clock: Send + Sync {
    /// Get the current UTC time.
    fn now_utc(&self) -> DateTime<Utc>;
}

/// System clock using actual wall time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Mock clock for deterministic testing.
#[cfg(any(test, feature = "test-seams"))]
#[derive(Debug, Clone)]
pub struct MockClock {
    now: DateTime<Utc>,
}

#[cfg(any(test, feature = "test-seams"))]
impl MockClock {
    /// Create a mock clock frozen at the given time.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { now }
    }

    /// Create a mock clock from an RFC 3339 string.
    pub fn from_rfc3339(s: &str) -> Self {
        Self {
            now: DateTime::parse_from_rfc3339(s)
                .expect("valid RFC 3339")
                .with_timezone(&Utc),
        }
    }

    /// Advance the clock by a duration.
    pub fn advance(&mut self, duration: chrono::Duration) {
        self.now = self.now + duration;
    }
}

#[cfg(any(test, feature = "test-seams"))]
impl Clock for MockClock {
    fn now_utc(&self) -> DateTime<Utc> {
        self.now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn system_clock_returns_time() {
        let clock = SystemClock;
        let now = clock.now_utc();
        // Just verify it doesn't panic and returns something reasonable
        assert!(now.year() >= 2024);
    }

    #[test]
    fn mock_clock_is_deterministic() {
        let clock = MockClock::from_rfc3339("2025-01-15T12:00:00Z");
        assert_eq!(clock.now_utc().to_rfc3339(), "2025-01-15T12:00:00+00:00");
        assert_eq!(clock.now_utc().to_rfc3339(), "2025-01-15T12:00:00+00:00");
    }

    #[test]
    fn mock_clock_advances() {
        let mut clock = MockClock::from_rfc3339("2025-01-15T12:00:00Z");
        clock.advance(chrono::Duration::hours(1));
        assert_eq!(clock.now_utc().to_rfc3339(), "2025-01-15T13:00:00+00:00");
    }
}
