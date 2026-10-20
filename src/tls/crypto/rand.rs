//! Randomness from the kernel's CSPRNG through `/dev/urandom`.
//!
//! `getrandom(2)` would avoid the file descriptor, but calling it needs
//! `unsafe`, which this crate forbids (ADR-001). On Linux `/dev/urandom`
//! draws from the same pool and, since 5.6, does not return before the
//! pool is initialized. The file is opened once and kept, so a process
//! that later runs out of descriptors or enters a chroot still has it.

use std::fs::File;
use std::io::{self, Read};
use std::sync::OnceLock;

static URANDOM: OnceLock<File> = OnceLock::new();

pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    let f = match URANDOM.get() {
        Some(f) => f,
        None => {
            let f = File::open("/dev/urandom")?;
            URANDOM.get_or_init(|| f)
        }
    };
    (&*f).read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }
}
