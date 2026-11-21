//! Keccak-f[1600] 置换与 SHA3/SHAKE（fips202）。

/// Keccak-f[1600] 轮常数。
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// rho 旋转偏移（按 pi 置换顺序）。
const ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// pi 置换（目标 lane 索引）。
const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Keccak-f[1600] 置换。
pub fn keccak_f1600(state: &mut [u64; 25]) {
    let mut bc = [0u64; 5];
    for &rc in RC.iter() {
        // theta
        for i in 0..5 {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                state[j + i] ^= t;
            }
        }
        // rho + pi
        let mut t = state[1];
        for i in 0..24 {
            let j = PILN[i];
            let tmp = state[j];
            state[j] = t.rotate_left(ROT[i]);
            t = tmp;
        }
        // chi
        for j in (0..25).step_by(5) {
            for i in 0..5 {
                bc[i] = state[j + i];
            }
            for i in 0..5 {
                state[j + i] = bc[i] ^ ((!bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
            }
        }
        // iota
        state[0] ^= rc;
    }
}

/// 可增量吸收/挤出的 Keccak 海绵。
pub struct Keccak {
    state: [u64; 25],
    rate: usize,
    pos: usize,
}

impl Keccak {
    pub fn new(rate: usize) -> Self {
        Self {
            state: [0u64; 25],
            rate,
            pos: 0,
        }
    }

    fn absorb_byte(&mut self, b: u8) {
        let byte_pos = self.pos;
        let lane = byte_pos / 8;
        let shift = (byte_pos % 8) * 8;
        self.state[lane] ^= (b as u64) << shift;
        self.pos += 1;
        if self.pos == self.rate {
            keccak_f1600(&mut self.state);
            self.pos = 0;
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        for &b in data {
            self.absorb_byte(b);
        }
    }

    /// 结束吸收并施加域分隔 padding（`delim` = 0x06 for SHA3, 0x1F for SHAKE）。
    pub fn finalize(&mut self, delim: u8) {
        self.absorb_byte(delim);
        while self.pos != self.rate - 1 {
            self.absorb_byte(0);
        }
        self.absorb_byte(0x80);
    }

    /// 挤出 `out.len()` 字节。
    pub fn squeeze(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(self.rate) {
            for (i, byte) in chunk.iter_mut().enumerate() {
                let lane = i / 8;
                let shift = (i % 8) * 8;
                *byte = (self.state[lane] >> shift) as u8;
            }
            if chunk.len() == self.rate {
                keccak_f1600(&mut self.state);
            }
        }
    }
}

/// 一次性 SHAKE 输出。
fn shake(digest: &mut [u8], input: &[u8], rate: usize) {
    let mut k = Keccak::new(rate);
    k.absorb(input);
    k.finalize(0x1F);
    k.squeeze(digest);
}

/// SHA3-256。
pub fn sha3_256(digest: &mut [u8; 32], input: &[u8]) {
    let mut k = Keccak::new(136);
    k.absorb(input);
    k.finalize(0x06);
    k.squeeze(digest);
}

/// SHA3-512。
pub fn sha3_512(digest: &mut [u8; 64], input: &[u8]) {
    let mut k = Keccak::new(72);
    k.absorb(input);
    k.finalize(0x06);
    k.squeeze(digest);
}

/// SHAKE-128（rate 168）。
pub fn shake128(digest: &mut [u8], input: &[u8]) {
    shake(digest, input, 168);
}

/// SHAKE-256（rate 136）。
pub fn shake256(digest: &mut [u8], input: &[u8]) {
    shake(digest, input, 136);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn sha3_256_abc() {
        let mut d = [0u8; 32];
        sha3_256(&mut d, b"abc");
        assert_eq!(
            hex(&d),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn sha3_512_abc() {
        let mut d = [0u8; 64];
        sha3_512(&mut d, b"abc");
        assert_eq!(
            hex(&d),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }

    #[test]
    fn shake128_known() {
        let mut d = [0u8; 32];
        shake128(&mut d, b"");
        assert_eq!(
            hex(&d),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    #[test]
    fn shake256_known() {
        let mut d = [0u8; 32];
        shake256(&mut d, b"");
        assert_eq!(
            hex(&d),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }
}

// 你好:D
