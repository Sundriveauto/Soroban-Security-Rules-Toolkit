//! Stable finding fingerprints.

/// 64-bit FNV-1a. Chosen for being tiny, dependency-free and stable across
/// platforms and Rust versions (unlike `std`'s `DefaultHasher`).
pub fn fnv1a64(parts: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for b in part.bytes().chain(std::iter::once(0x1f)) {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// Collapses runs of whitespace so formatting-only changes keep fingerprints stable.
pub fn normalize(snippet: &str) -> String {
    snippet.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Fingerprint independent of the line number, so findings survive code moving
/// up or down. `occurrence` disambiguates identical lines in one function.
pub fn fingerprint(rule_id: &str, file: &str, function: Option<&str>, snippet: &str, occurrence: usize) -> String {
    let occ = occurrence.to_string();
    let norm = normalize(snippet);
    format!("{:016x}", fnv1a64(&[rule_id, file, function.unwrap_or(""), &norm, &occ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_whitespace_insensitive() {
        let a = fingerprint("SG-001", "src/lib.rs", Some("f"), "  a.set(&k,  &v);", 0);
        let b = fingerprint("SG-001", "src/lib.rs", Some("f"), "a.set(&k, &v);", 0);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert_ne!(a, fingerprint("SG-001", "src/lib.rs", Some("f"), "a.set(&k, &v);", 1));
        // Known value guards against accidental algorithm changes.
        assert_eq!(fnv1a64(&[]), 0xcbf2_9ce4_8422_2325);
    }
}
