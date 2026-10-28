//! CSPRNG: ChaCha20 with fast key erasure, seeded by the host and mixed with
//! the CPU's RNDR when available.

use spin::Mutex;

use crate::arch;

struct Rng {
    key: [u32; 8],
}

static RNG: Mutex<Rng> = Mutex::new(Rng { key: [0; 8] });

pub fn init(seed: &[u8; 32]) {
    let mut rng = RNG.lock();
    for (i, k) in rng.key.iter_mut().enumerate() {
        *k = u32::from_le_bytes(seed[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 0..4 {
        if let Some(v) = arch::hw_random() {
            rng.key[i * 2] ^= v as u32;
            rng.key[i * 2 + 1] ^= (v >> 32) as u32;
        }
    }
    // Stir once so the raw seed never sits in memory.
    let mut scratch = [0u8; 32];
    rng.fill(&mut scratch);
}

/// Mix fresh entropy in (a run restored from a snapshot gets some, so it
/// doesn't repeat what every other run from the snapshot draws).
pub fn reseed(entropy: &[u8; 32]) {
    let mut rng = RNG.lock();
    for (i, k) in rng.key.iter_mut().enumerate() {
        *k ^= u32::from_le_bytes(entropy[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let mut scratch = [0u8; 32];
    rng.fill(&mut scratch);
}

pub fn fill(out: &mut [u8]) {
    RNG.lock().fill(out);
}

impl Rng {
    fn fill(&mut self, out: &mut [u8]) {
        // Block 0 replaces the key; later blocks become output.
        let first = block(&self.key, 0);
        let mut counter = 1u64;
        let mut written = 0;
        let tail = &first[32..];
        let n = tail.len().min(out.len());
        out[..n].copy_from_slice(&tail[..n]);
        written += n;
        while written < out.len() {
            let b = block(&self.key, counter);
            counter += 1;
            let n = b.len().min(out.len() - written);
            out[written..written + n].copy_from_slice(&b[..n]);
            written += n;
        }
        for (i, k) in self.key.iter_mut().enumerate() {
            *k = u32::from_le_bytes(first[i * 4..i * 4 + 4].try_into().unwrap());
        }
    }
}

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn block(key: &[u32; 8], counter: u64) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    s[4..12].copy_from_slice(key);
    s[12] = counter as u32;
    s[13] = (counter >> 32) as u32;
    let init = s;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}
