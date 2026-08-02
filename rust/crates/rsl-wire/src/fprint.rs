//! Rabin-64 fingerprint — a direct port of `src/common/src/msn_fprint.cpp`.
//!
//! The polynomial is `0xa795d0f29b4dcdf8` and the fingerprint of the empty
//! string equals the polynomial itself (see `FPRINT empty` in the golden
//! corpus). This is the checksum function RSL runs over every message body.
//!
//! Only the little-endian slice-by-8 path is ported; the C++ big-endian path is
//! a byte-swapped mirror that produces identical results, so we guard against
//! big-endian targets at compile time rather than carrying dead code.

#[cfg(not(target_endian = "little"))]
compile_error!(
    "rsl-wire only ports the little-endian Rabin-64 path; \
     the C++ big-endian path is an unported byte-swapped mirror"
);

/// The Rabin polynomial, `the_poly` in `msn_fprint.cpp`. Also the fingerprint
/// of the empty string (`fp->empty = poly`).
pub const POLY: u64 = 0xa795d0f2_9b4dcdf8;

/// Precomputed `bybyte[8][256]` slice-by-8 tables.
///
/// `bybyte[b][i]` is `i * X^(64 + 8*b) mod poly`, built exactly as `initbybyte`
/// does. `bybyte[0]` doubles as the per-byte table used by the tail loop.
struct Tables {
    bybyte: [[u64; 256]; 8],
}

impl Tables {
    /// Port of `initbybyte` + the polynomial setup in `msn_fprint_init`.
    const fn new(poly: u64) -> Tables {
        // poly[0] = 0, poly[1] = polynomial.
        let poly_tab = [0u64, poly];
        let mut bybyte = [[0u64; 256]; 8];

        let mut f = poly;
        let mut b = 0;
        while b != 8 {
            bybyte[b][0] = 0;
            // for (i = 0x80; i != 0; i >>= 1) { bybyte[b][i] = f; f = poly[f&1]^(f>>1); }
            let mut i = 0x80;
            while i != 0 {
                bybyte[b][i] = f;
                f = poly_tab[(f & 1) as usize] ^ (f >> 1);
                i >>= 1;
            }
            // for (i = 1; i != 256; i <<= 1) { xf = bybyte[b][i]; for (k=1;k!=i;k++) bybyte[b][i+k]=xf^bybyte[b][k]; }
            let mut i = 1;
            while i != 256 {
                let xf = bybyte[b][i];
                let mut k = 1;
                while k != i {
                    bybyte[b][i + k] = xf ^ bybyte[b][k];
                    k += 1;
                }
                i <<= 1;
            }
            b += 1;
        }
        Tables { bybyte }
    }
}

/// The default fingerprint tables, built from [`POLY`] at compile time.
static TABLES: Tables = Tables::new(POLY);

/// Fingerprint of `data`, seeded with the empty-string fingerprint (`POLY`).
///
/// Equivalent to `msn_fprint_of(fp, data, len)` /
/// `FingerPrint64::GetFingerPrint(data, length)`.
pub fn fingerprint(data: &[u8]) -> u64 {
    fingerprint_with(POLY, data)
}

/// Continue a fingerprint from `init` over `data`.
///
/// Equivalent to `msn_fprint_of(fp, init, data, len)` /
/// `FingerPrint64::GetFingerPrint(init, data, length)`. Used to chain across the
/// multiple buffers of a `Vote` (`Vote::CalculateChecksum`).
pub fn fingerprint_with(init: u64, data: &[u8]) -> u64 {
    let t = &TABLES.bybyte;
    let mut fp = init;

    // Slice-by-8 over aligned 8-byte chunks. The C++ code first advances to an
    // 8-byte address boundary; that is a pure performance optimization and the
    // computed value is independent of where the chunk boundary falls, so we
    // chunk from the start.
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        // init ^= *(u64*)p;  (little-endian load)
        let x = u64::from_le_bytes(chunk.try_into().unwrap()) ^ fp;
        fp = t[7][(x & 0xff) as usize]
            ^ t[6][((x >> 8) & 0xff) as usize]
            ^ t[5][((x >> 16) & 0xff) as usize]
            ^ t[4][((x >> 24) & 0xff) as usize]
            ^ t[3][((x >> 32) & 0xff) as usize]
            ^ t[2][((x >> 40) & 0xff) as usize]
            ^ t[1][((x >> 48) & 0xff) as usize]
            ^ t[0][(x >> 56) as usize];
    }

    // Tail: init = (init >> 8) ^ bybyte[0][(init & 0xff) ^ *p++];
    for &byte in chunks.remainder() {
        fp = (fp >> 8) ^ t[0][((fp & 0xff) as u8 ^ byte) as usize];
    }

    fp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-at-a-time reference: the tail-loop step applied to every byte. The
    /// slice-by-8 fast path must agree with this for all inputs.
    fn fingerprint_byte_at_a_time(init: u64, data: &[u8]) -> u64 {
        let t = &TABLES.bybyte;
        let mut fp = init;
        for &byte in data {
            fp = (fp >> 8) ^ t[0][((fp & 0xff) as u8 ^ byte) as usize];
        }
        fp
    }

    #[test]
    fn empty_is_poly() {
        assert_eq!(fingerprint(b""), POLY);
        assert_eq!(fingerprint(b""), 0xa795d0f2_9b4dcdf8);
    }

    #[test]
    fn slice_by_8_matches_byte_at_a_time() {
        for len in 0..300usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            assert_eq!(
                fingerprint_with(POLY, &data),
                fingerprint_byte_at_a_time(POLY, &data),
                "mismatch at len {len}"
            );
        }
    }
}
