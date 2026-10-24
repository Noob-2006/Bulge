//! Small helpers every bulge crate needs, in one place: hex, clocks, private
//! files (mode 600, atomic, locked read-modify-write), secret files, a
//! single-instance lock, and the search terms the full-text indexes use.
//!
//! Each was written several times before; the copies had drifted (some wrote
//! a key and chmod-ed it afterwards, leaving it readable for a moment; some
//! read keys without checking their permissions).

pub mod fs;
pub mod search;

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse hex (either case) of exactly `N` bytes.
pub fn unhex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let text = text.trim();
    if text.len() != N * 2 || !text.is_ascii() {
        return Err(format!("expected {} hex characters", N * 2));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| "not hex".to_string())?;
    }
    Ok(out)
}

/// `N` random bytes from the OS.
pub fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| format!("random: {e}"))?;
    Ok(out)
}

/// Seconds since the Unix epoch (0 if the clock is before it).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}

/// The user's home directory (`HOME`, else `USERPROFILE` on Windows).
pub fn home_dir() -> Result<std::path::PathBuf, String> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(std::path::PathBuf::from).ok_or_else(|| "neither HOME nor USERPROFILE is set".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex(&bytes), "0001abff");
        assert_eq!(unhex::<4>("0001ABff").unwrap(), bytes);
        assert!(unhex::<4>("0001ab").is_err());
        assert!(unhex::<2>("zz00").is_err());
        assert!(unhex::<2>("é0").is_err());
        assert!(now_ms() / 1000 >= now_secs().saturating_sub(1));
    }
}
