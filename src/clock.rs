use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Trait abstracting system time measurement for testability.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Default system clock implementation backed by `std::time::SystemTime::now()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Converts a `SystemTime` instance to a (seconds, nanoseconds) tuple since UNIX epoch.
pub fn system_time_to_unix(time: SystemTime) -> (i64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, duration.subsec_nanos()),
        Err(err) => {
            let duration = err.duration();
            (-(duration.as_secs() as i64), duration.subsec_nanos())
        }
    }
}

/// Creates a `SystemTime` instance from a (seconds, nanoseconds) tuple since UNIX epoch.
pub fn unix_to_system_time(secs: i64, nsecs: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, nsecs)
    }
}

pub fn default_epoch() -> SystemTime {
    UNIX_EPOCH
}

/// Formats a `SystemTime` as `<unix_secs>.<nanos>s (YYYY-MM-DD HH:MM:SS)` in local civil time.
pub fn format_local_civil_time(time: SystemTime) -> String {
    let (secs, nsecs) = system_time_to_unix(time);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let time_t = secs as libc::time_t;
    let res = unsafe { libc::localtime_r(&time_t, &mut tm) };
    if !res.is_null() {
        format!(
            "{}.{:09}s ({:04}-{:02}-{:02} {:02}:{:02}:{:02})",
            secs,
            nsecs,
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    } else {
        format!("{}.{:09}s (unknown time)", secs, nsecs)
    }
}

/// Parses a human-readable or unix timestamp string into `SystemTime`.
/// Supports unix seconds (`1755424800`), decimals (`1755424800.5`),
/// ISO 8601 / RFC 3339 (`2026-08-17T10:00:00Z`), `2026-08-17 10:00:00`, and `2026-08-17`.
pub fn parse_timestamp(input: &str) -> Result<SystemTime, String> {
    let trimmed = input.trim();
    if let Ok(secs_f) = trimmed.parse::<f64>() {
        let secs = secs_f.floor() as i64;
        let nsecs = ((secs_f - secs_f.floor()) * 1_000_000_000.0) as u32;
        return Ok(unix_to_system_time(secs, nsecs));
    }

    let formats = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"];

    for fmt_str in &formats {
        let c_fmt = std::ffi::CString::new(*fmt_str).unwrap();
        let c_input = std::ffi::CString::new(trimmed.trim_end_matches('Z')).unwrap();
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let res = unsafe { libc::strptime(c_input.as_ptr(), c_fmt.as_ptr(), &mut tm) };
        if !res.is_null() {
            let time_t = unsafe { libc::timegm(&mut tm) };
            if time_t != -1 {
                return Ok(UNIX_EPOCH + Duration::from_secs(time_t as u64));
            }
        }
    }

    Err(format!(
        "Invalid timestamp '{}'. Expected unix seconds or ISO date (e.g. '2026-08-17T10:00:00Z')",
        input
    ))
}

pub mod serde_system_time {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        system_time_to_unix(*time).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (sec, nsec) = <(i64, u32)>::deserialize(deserializer)?;
        Ok(unix_to_system_time(sec, nsec))
    }
}

pub mod serde_system_time_opt {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let opt_tuple = time.map(system_time_to_unix);
        opt_tuple.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_tuple = <Option<(i64, u32)>>::deserialize(deserializer)?;
        Ok(opt_tuple.map(|(sec, nsec)| unix_to_system_time(sec, nsec)))
    }
}

/// Fixed-time clock for deterministic tests - e.g. asserting exact timestamps survive
/// a crash/recovery cycle, which a real wall clock can't do reliably (real time keeps
/// moving between the write and the check).
#[derive(Debug, Clone, Copy)]
pub struct MockClock(pub SystemTime);

impl Clock for MockClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// Shared, advanceable clock for deterministic multi-instance tests where several
/// independent components need to observe the *same* simulated time (unlike
/// `MockClock`, whose value is fixed at construction and never changes). Cloning
/// shares the same underlying time - advancing through any clone advances it for all
/// of them.
#[derive(Debug, Clone)]
pub struct AdvancingClock(Arc<Mutex<SystemTime>>);

impl AdvancingClock {
    pub fn new(start: SystemTime) -> Self {
        Self(Arc::new(Mutex::new(start)))
    }

    /// Advances the simulated time by `duration` and returns the new value.
    pub fn advance(&self, duration: Duration) -> SystemTime {
        let mut guard = self.0.lock().unwrap();
        *guard += duration;
        *guard
    }
}

impl Clock for AdvancingClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_system_clock_now() {
        let clock = SystemClock;
        let now = clock.now();
        assert!(now >= UNIX_EPOCH);
    }

    #[test]
    fn test_mock_clock() {
        let fixed_time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mock = MockClock(fixed_time);
        assert_eq!(mock.now(), fixed_time);

        let (secs, nsecs) = system_time_to_unix(fixed_time);
        assert_eq!(secs, 1_700_000_000);
        assert_eq!(nsecs, 0);
        assert_eq!(unix_to_system_time(secs, nsecs), fixed_time);
    }

    #[test]
    fn test_advancing_clock_shared_across_clones() {
        let start = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = AdvancingClock::new(start);
        let handle_a = clock.clone();
        let handle_b = clock.clone();

        assert_eq!(handle_a.now(), start);
        assert_eq!(handle_b.now(), start);

        handle_a.advance(Duration::from_secs(5));

        // Advancing through one handle is visible through every other handle too.
        assert_eq!(handle_a.now(), start + Duration::from_secs(5));
        assert_eq!(handle_b.now(), start + Duration::from_secs(5));
        assert_eq!(clock.now(), start + Duration::from_secs(5));
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TimestampTestWrapper {
        #[serde(with = "serde_system_time")]
        time: SystemTime,
        #[serde(with = "serde_system_time_opt")]
        opt_some: Option<SystemTime>,
        #[serde(default, with = "serde_system_time_opt")]
        opt_none: Option<SystemTime>,
    }

    #[test]
    fn test_serde_system_time_round_trip() {
        let post_epoch = UNIX_EPOCH + Duration::new(1_720_000_000, 123_456_789);
        let pre_epoch = UNIX_EPOCH - Duration::new(100_000, 500);

        let test_obj = TimestampTestWrapper {
            time: post_epoch,
            opt_some: Some(pre_epoch),
            opt_none: None,
        };

        let bytes = crate::wire::serialize(&test_obj).unwrap();
        let deserialized: TimestampTestWrapper = crate::wire::deserialize(&bytes).unwrap();
        assert_eq!(test_obj, deserialized);
    }

    #[test]
    fn test_format_local_civil_time() {
        let time = unix_to_system_time(1786953681, 901426641);
        let formatted = format_local_civil_time(time);
        assert!(formatted.starts_with("1786953681.901426641s ("));
        assert!(formatted.ends_with(')'));
        // Verify format inside parentheses is YYYY-MM-DD HH:MM:SS
        let civil_part = &formatted[formatted.find('(').unwrap() + 1..formatted.len() - 1];
        assert_eq!(civil_part.len(), 19);
        assert_eq!(&civil_part[4..5], "-");
        assert_eq!(&civil_part[7..8], "-");
        assert_eq!(&civil_part[10..11], " ");
        assert_eq!(&civil_part[13..14], ":");
        assert_eq!(&civil_part[16..17], ":");
    }
}
