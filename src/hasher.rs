use std::hash::{BuildHasher, Hasher};

/*
 * Our input data is a SHA1 hash. Rehashing this, especially with a non-cryptographic hash, is not
 * going to improve matters. We are truncating the SHA1 hash to 8 bytes (which is the only possible
 * size here) and call it a day.
 */

const HASH_LEN: usize = 8;

#[derive(Clone, Copy, Default)]
pub struct U64TruncateBuildHasher;

pub struct U64TruncateHasher {
    buf: [u8; HASH_LEN],
    len: usize,
}

impl Default for U64TruncateHasher {
    #[inline]
    fn default() -> Self {
        Self {
            buf: [0u8; HASH_LEN],
            len: 0,
        }
    }
}

impl Hasher for U64TruncateHasher {
    #[inline]
    fn finish(&self) -> u64 {
        u64::from_be_bytes(self.buf)
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // FIXME: This is a hack to prevent write_length_prefix() from filling up our buffer with
        //   the known fixed length of our input SHA1 hash. I could not find a way to prevent that
        //   through other means.
        if bytes.len() != 20 {
            return;
        }
        let remaining = HASH_LEN - self.len;
        let n = remaining.min(bytes.len());
        if n > 0 {
            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
        }
    }
}

impl BuildHasher for U64TruncateBuildHasher {
    type Hasher = U64TruncateHasher;

    #[inline]
    fn build_hasher(&self) -> U64TruncateHasher {
        U64TruncateHasher::default()
    }
}
