//! Browser console WebAssembly demo.
//!
//! Compiled to `wasm32-unknown-unknown` without any bindings generator: the
//! module exports a plain C-ABI function the page calls through the standard
//! `WebAssembly` JS API after streaming compilation. The console runs the
//! same sieve in JavaScript and compares both the counts and the timings.

/// Counts the primes less than or equal to `limit` with a sieve of
/// Eratosthenes. The browser caps `limit`; an allocation failure for an
/// absurd value simply traps the instance.
#[no_mangle]
pub extern "C" fn count_primes(limit: u32) -> u32 {
    let limit = limit as usize;
    if limit < 2 {
        return 0;
    }
    let mut composite = vec![0u8; limit + 1];
    let mut count = 0u32;
    for n in 2..=limit {
        if composite[n] != 0 {
            continue;
        }
        count += 1;
        // usize is 32-bit on wasm32, so guard the n² starting point.
        if let Some(start) = n.checked_mul(n) {
            let mut multiple = start;
            while multiple <= limit {
                composite[multiple] = 1;
                multiple += n;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_primes_at_known_points() {
        assert_eq!(count_primes(0), 0);
        assert_eq!(count_primes(1), 0);
        assert_eq!(count_primes(2), 1);
        assert_eq!(count_primes(10), 4);
        assert_eq!(count_primes(100), 25);
        assert_eq!(count_primes(1_000_000), 78_498);
    }
}
