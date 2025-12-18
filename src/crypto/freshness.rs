//! Response freshness enforcement (replay attack prevention).

use crate::clock::Clock;
use crate::GatewardenError;
use chrono::{DateTime, Utc};

/// Maximum age of a response before it's considered stale (5 minutes).
pub const MAX_RESPONSE_AGE_SECONDS: i64 = 5 * 60;

/// Maximum future tolerance for response dates (60 seconds).
pub const MAX_FUTURE_TOLERANCE_SECONDS: i64 = 60;

/// Parse an RFC 2822 date string (HTTP Date header format).
///
/// Example: "Wed, 09 Jun 2021 16:08:15 GMT"
pub fn parse_rfc2822_date(date_str: &str) -> Result<DateTime<Utc>, GatewardenError> {
    DateTime::parse_from_rfc2822(date_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            GatewardenError::ProtocolError(format!("Invalid date header: {} ({})", date_str, e))
        })
}

/// Check that a response is fresh (not a replay attack).
///
/// # Arguments
/// * `response_date` - The parsed Date header from the response
/// * `clock` - Clock implementation for current time
///
/// # Errors
/// * `ResponseTooOld` - Response is older than 5 minutes (replay attack)
/// * `ResponseFromFuture` - Response date is more than 60s in the future (clock tampering)
pub fn check_freshness<C: Clock + ?Sized>(
    response_date: DateTime<Utc>,
    clock: &C,
) -> Result<(), GatewardenError> {
    let now = clock.now_utc();
    let age_seconds = (now - response_date).num_seconds();

    // Reject stale responses (replay attack)
    if age_seconds > MAX_RESPONSE_AGE_SECONDS {
        return Err(GatewardenError::ResponseTooOld { age_seconds });
    }

    // Reject future responses (clock tampering)
    if age_seconds < -MAX_FUTURE_TOLERANCE_SECONDS {
        return Err(GatewardenError::ResponseFromFuture);
    }

    Ok(())
}

/// Combined parse and check freshness.
pub fn check_date_freshness<C: Clock + ?Sized>(
    date_header: &str,
    clock: &C,
) -> Result<DateTime<Utc>, GatewardenError> {
    let response_date = parse_rfc2822_date(date_header)?;
    check_freshness(response_date, clock)?;
    Ok(response_date)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;

    #[test]
    fn test_parse_rfc2822_valid() {
        let date = parse_rfc2822_date("Wed, 09 Jun 2021 16:08:15 GMT").unwrap();
        assert_eq!(date.to_rfc3339(), "2021-06-09T16:08:15+00:00");
    }

    #[test]
    fn test_parse_rfc2822_invalid() {
        let result = parse_rfc2822_date("not a date");
        assert!(matches!(result, Err(GatewardenError::ProtocolError(_))));
    }

    #[test]
    fn test_freshness_valid() {
        let clock = MockClock::from_rfc3339("2021-06-09T16:10:00Z").unwrap();
        let response_date = parse_rfc2822_date("Wed, 09 Jun 2021 16:08:15 GMT").unwrap();

        // Response is ~105 seconds old, within 5 minute window
        let result = check_freshness(response_date, &clock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_freshness_stale() {
        let clock = MockClock::from_rfc3339("2021-06-09T16:20:00Z").unwrap();
        let response_date = parse_rfc2822_date("Wed, 09 Jun 2021 16:08:15 GMT").unwrap();

        // Response is ~12 minutes old, exceeds 5 minute window
        let result = check_freshness(response_date, &clock);
        assert!(matches!(
            result,
            Err(GatewardenError::ResponseTooOld { .. })
        ));
    }

    #[test]
    fn test_freshness_exactly_5_minutes() {
        let clock = MockClock::from_rfc3339("2021-06-09T16:13:15Z").unwrap();
        let response_date = parse_rfc2822_date("Wed, 09 Jun 2021 16:08:15 GMT").unwrap();

        // Response is exactly 5 minutes old (300 seconds) - should still be valid
        let result = check_freshness(response_date, &clock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_freshness_just_over_5_minutes() {
        let clock = MockClock::from_rfc3339("2021-06-09T16:13:16Z").unwrap();
        let response_date = parse_rfc2822_date("Wed, 09 Jun 2021 16:08:15 GMT").unwrap();

        // Response is 301 seconds old - should be rejected
        let result = check_freshness(response_date, &clock);
        assert!(matches!(
            result,
            Err(GatewardenError::ResponseTooOld { .. })
        ));
    }

    #[test]
    fn test_freshness_future_within_tolerance() {
        let clock = MockClock::from_rfc3339("2021-06-09T16:07:30Z").unwrap();
        let response_date = parse_rfc2822_date("Wed, 09 Jun 2021 16:08:15 GMT").unwrap();

        // Response is 45 seconds in the future - within 60s tolerance
        let result = check_freshness(response_date, &clock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_freshness_future_exceeds_tolerance() {
        let clock = MockClock::from_rfc3339("2021-06-09T16:06:00Z").unwrap();
        let response_date = parse_rfc2822_date("Wed, 09 Jun 2021 16:08:15 GMT").unwrap();

        // Response is 135 seconds in the future - exceeds 60s tolerance
        let result = check_freshness(response_date, &clock);
        assert!(matches!(result, Err(GatewardenError::ResponseFromFuture)));
    }

    #[test]
    fn test_check_date_freshness_combined() {
        let clock = MockClock::from_rfc3339("2021-06-09T16:10:00Z").unwrap();
        let result = check_date_freshness("Wed, 09 Jun 2021 16:08:15 GMT", &clock);
        assert!(result.is_ok());
    }
}
