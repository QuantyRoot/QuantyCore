//! AES-128 and AES-256 encryption (FIPS 197), bitsliced.
//!
//! Table based AES leaks the key through the cache, because the S-box is
//! indexed by key dependent bytes. Here four blocks are processed at once
//! as eight 64-bit bit planes: plane `b` holds bit `b` of all 64 bytes, at
//! bit index `16 * block + byte`. The S-box is the 113 gate circuit of
//! Boyar and Peralta, so every byte goes through the same instructions
//! whatever its value. Only encryption is built; GCM and the TLS key
//! schedule never decrypt with AES.

use super::ct;

type Planes = [u64; 8];

/// Transposes an 8x8 bit matrix held one row per byte: bit `j` of byte
/// `i` moves to bit `i` of byte `j` (Hacker's Delight, 7-3).
fn transpose8(mut x: u64) -> u64 {
    let t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
    x ^= t ^ (t << 7);
    let t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
    x ^= t ^ (t << 14);
    let t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
    x ^= t ^ (t << 28);
    x
}

fn to_planes(bytes: &[u8; 64]) -> Planes {
    let mut p = [0u64; 8];
    for (g, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
        let y = transpose8(u64::from_le_bytes(*chunk));
        for (b, plane) in p.iter_mut().enumerate() {
            *plane |= ((y >> (8 * b)) & 0xff) << (8 * g);
        }
    }
    p
}

fn from_planes(p: &Planes, bytes: &mut [u8; 64]) {
    for (g, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut y = 0u64;
        for (b, plane) in p.iter().enumerate() {
            y |= ((plane >> (8 * g)) & 0xff) << (8 * b);
        }
        chunk.copy_from_slice(&transpose8(y).to_le_bytes());
    }
}

/// The AES S-box as a circuit (Boyar and Peralta, "A depth-16 circuit for
/// the AES S-box", 2011). `q[0]` is the least significant bit.
#[allow(clippy::many_single_char_names)]
fn sub_bytes(q: &mut Planes) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    *q = [s7, s6, s5, s4, s3, s2, s1, s0];
}

/// Within each block, byte `4 * col + row`. Row `r` rotates left by `r`
/// columns: the new column `c` takes the old column `c + r`.
fn shift_rows(q: &mut Planes) {
    const ROW: u64 = 0x1111_1111_1111_1111;
    for x in q.iter_mut() {
        let mut out = *x & ROW;
        for r in 1..4u32 {
            let m = ROW << r;
            let t = *x & m;
            // Columns that stay inside the block move down by r columns,
            // the first r wrap around to the top.
            let low_cols: u64 = (0..4 - r).fold(0, |a, c| a | (0xfu64 << (4 * c)));
            let low = low_cols * 0x0001_0001_0001_0001;
            out |= ((t >> (4 * r)) & m & low) | ((t << (16 - 4 * r)) & m & !low);
        }
        *x = out;
    }
}

/// Planes where row `r` of each column holds what was in row `r + k`.
fn rot_rows(x: u64, k: u32) -> u64 {
    let keep = 0x1111_1111_1111_1111u64 * ((1 << (4 - k)) - 1);
    ((x >> k) & keep) | ((x << (4 - k)) & !keep)
}

fn mix_columns(q: &mut Planes) {
    let r1 = q.map(|x| rot_rows(x, 1));
    let r2 = q.map(|x| rot_rows(x, 2));
    let r3 = q.map(|x| rot_rows(x, 3));
    let s: Planes = core::array::from_fn(|b| q[b] ^ r1[b]);
    // 2 * s in GF(2^8) with the polynomial 0x11b.
    let x2 = [
        s[7],
        s[0] ^ s[7],
        s[1],
        s[2] ^ s[7],
        s[3] ^ s[7],
        s[4],
        s[5],
        s[6],
    ];
    for b in 0..8 {
        q[b] = x2[b] ^ r1[b] ^ r2[b] ^ r3[b];
    }
}

fn add(q: &mut Planes, k: &Planes) {
    for (x, y) in q.iter_mut().zip(k) {
        *x ^= y;
    }
}

/// Applies the S-box to the four bytes of a key schedule word.
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let mut b = [0u8; 64];
    b[..4].copy_from_slice(&w);
    let mut p = to_planes(&b);
    sub_bytes(&mut p);
    from_planes(&p, &mut b);
    let out = [b[0], b[1], b[2], b[3]];
    ct::wipe(&mut b);
    ct::wipe_u64(&mut p);
    out
}

#[derive(Clone)]
pub struct Aes {
    rounds: Vec<Planes>,
}

impl Aes {
    /// AES-128 or AES-256, from the key length. Panics on any other.
    pub fn new(key: &[u8]) -> Aes {
        let nk = match key.len() {
            16 => 4,
            32 => 8,
            n => panic!("AES key of {n} bytes"),
        };
        let nr = nk + 6;
        let mut w: Vec<[u8; 4]> = key.as_chunks::<4>().0.to_vec();
        let mut rcon = 1u8;
        for i in nk..4 * (nr + 1) {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t.rotate_left(1);
                t = sub_word(t);
                t[0] ^= rcon;
                rcon = (rcon << 1) ^ (0x1b * (rcon >> 7));
            } else if nk > 6 && i % nk == 4 {
                t = sub_word(t);
            }
            let prev = w[i - nk];
            w.push(core::array::from_fn(|j| prev[j] ^ t[j]));
        }
        let rounds = w
            .as_chunks::<4>()
            .0
            .iter()
            .map(|rk| {
                let mut b = [0u8; 64];
                for (i, byte) in b.iter_mut().enumerate() {
                    *byte = rk[(i % 16) / 4][i % 4];
                }
                let p = to_planes(&b);
                ct::wipe(&mut b);
                p
            })
            .collect();
        for word in w.iter_mut() {
            ct::wipe(word);
        }
        Aes { rounds }
    }

    /// Encrypts four 16-byte blocks in place.
    pub fn encrypt4(&self, blocks: &mut [u8; 64]) {
        let mut q = to_planes(blocks);
        add(&mut q, &self.rounds[0]);
        let last = self.rounds.len() - 1;
        for k in &self.rounds[1..last] {
            sub_bytes(&mut q);
            shift_rows(&mut q);
            mix_columns(&mut q);
            add(&mut q, k);
        }
        sub_bytes(&mut q);
        shift_rows(&mut q);
        add(&mut q, &self.rounds[last]);
        from_planes(&q, blocks);
        ct::wipe_u64(&mut q);
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut b = [0u8; 64];
        b[..16].copy_from_slice(block);
        self.encrypt4(&mut b);
        block.copy_from_slice(&b[..16]);
        ct::wipe(&mut b);
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        for r in self.rounds.iter_mut() {
            ct::wipe_u64(r);
        }
    }
}

impl std::fmt::Debug for Aes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Aes({} rounds)", self.rounds.len() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The S-box circuit against the S-box computed from its definition,
    /// multiplicative inverse in GF(2^8) followed by the affine map, for
    /// every input. Done the slow way on purpose, independent of the
    /// circuit.
    #[test]
    fn sbox_circuit_matches_the_definition() {
        fn mul(mut a: u8, mut b: u8) -> u8 {
            let mut p = 0;
            while b != 0 {
                if b & 1 != 0 {
                    p ^= a;
                }
                a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
                b >>= 1;
            }
            p
        }
        for chunk in 0..4 {
            let mut b: [u8; 64] = core::array::from_fn(|i| (chunk * 64 + i) as u8);
            let mut p = to_planes(&b);
            sub_bytes(&mut p);
            from_planes(&p, &mut b);
            for (i, &got) in b.iter().enumerate() {
                let x = (chunk * 64 + i) as u8;
                let inv = (1..=255u8).find(|&y| mul(x, y) == 1).unwrap_or(0);
                let want = inv
                    ^ inv.rotate_left(1)
                    ^ inv.rotate_left(2)
                    ^ inv.rotate_left(3)
                    ^ inv.rotate_left(4)
                    ^ 0x63;
                assert_eq!(got, want, "S({x:#04x})");
            }
        }
    }

    // FIPS 197 C.1 and C.3, encrypted in each of the four lanes, so a
    // permutation that mixes up lanes is seen.
    #[test]
    fn fips_197_in_every_lane() {
        let plain = hex("00112233445566778899aabbccddeeff");
        for (key, want) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let aes = Aes::new(&hex(key));
            for lane in 0..4 {
                let mut b = [0u8; 64];
                b[16 * lane..16 * lane + 16].copy_from_slice(&plain);
                aes.encrypt4(&mut b);
                assert_eq!(b[16 * lane..16 * lane + 16], hex(want)[..], "lane {lane}");
            }
        }
    }
}
