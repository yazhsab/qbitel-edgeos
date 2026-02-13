// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Number Theoretic Transform (NTT) for polynomial multiplication.
//!
//! This module implements the NTT used in Kyber and Dilithium for
//! efficient polynomial multiplication in the ring Z_q[X]/(X^n + 1).
//!
//! The NTT transforms polynomials to a representation where multiplication
//! is element-wise, reducing complexity from O(n^2) to O(n log n).

use crate::field::{DilithiumFieldElement, KyberFieldElement, DILITHIUM_Q, KYBER_Q};

/// Polynomial degree for Kyber
pub const KYBER_N: usize = 256;

/// Polynomial degree for Dilithium
pub const DILITHIUM_N: usize = 256;

/// Precomputed zetas (twiddle factors) for Kyber NTT
/// zeta = 17 is a primitive 256th root of unity mod 3329
/// These are in bit-reversed order for in-place NTT (standard form, NOT Montgomery)
/// Computed as: zetas[i] = 17^(bit_rev_7(i)) mod 3329
pub static KYBER_ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// Precomputed inverse zetas for Kyber inverse NTT (standard form)
/// inv_zetas[i] = (zetas[i])^(-1) mod 3329 (multiplicative inverse)
pub static KYBER_ZETAS_INV: [u16; 128] = [
    1, 1600, 40, 749, 2481, 1432, 2699, 687, 1583, 2760, 69, 543, 2532, 3136, 1410, 2267,
    2508, 1355, 450, 936, 447, 2794, 1235, 1903, 1996, 1089, 3273, 283, 1853, 1990, 882, 3033,
    2419, 2102, 219, 855, 2681, 1848, 712, 682, 927, 1795, 461, 1891, 2877, 2522, 1894, 1010,
    1414, 2009, 3296, 464, 2697, 816, 1352, 2679, 1274, 1052, 1025, 2132, 1573, 76, 2998, 3040,
    1175, 2444, 394, 1219, 2300, 1455, 2117, 1607, 2443, 554, 1179, 2186, 2303, 2926, 2237, 525,
    735, 863, 2768, 1230, 2572, 556, 3010, 2266, 1684, 1239, 780, 2954, 109, 1292, 1031, 1745,
    2688, 3061, 992, 2596, 941, 892, 1021, 2390, 642, 1868, 2377, 1482, 1540, 540, 1678, 1626,
    279, 314, 1173, 2573, 3096, 48, 667, 1920, 2229, 1041, 2606, 1692, 680, 2746, 568, 3312,
];

/// Scaling factor for Kyber inverse NTT: 128^-1 mod 3329 = 3303
/// The NTT has 7 butterfly layers (len from 128 down to 2), and the
/// inverse NTT has 7 layers (len from 2 up to 128), requiring 2^7 = 128 scaling.
pub const KYBER_N_INV: u16 = 3303; // 128^-1 mod 3329

/// Precomputed zetas for Dilithium NTT (standard form, NOT Montgomery)
/// zeta = 1753 is a primitive 512th root of unity mod 8380417
/// These are in bit-reversed order for in-place NTT
/// Computed as: zetas[i] = pow(1753, bit_rev_8(i), q) for i in 0..256
pub static DILITHIUM_ZETAS: [u32; 256] = [
           1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
     7778734, 3542485, 2682288, 2129892, 3764867, 7375178,  557458, 7159240,
     5010068, 4317364, 2663378, 6705802, 4855975, 7946292,  676590, 7044481,
     5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
     3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
      394148,  928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
     3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
     5483103, 3192354,  556856, 3870317, 2917338, 1853806, 3345963, 1858416,
     3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
     2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
     1528066,  482649, 1148858, 5418153, 7814814,  169688, 2462444, 5046034,
     4213992, 4892034, 1987814, 5183169, 1736313,  235407, 5130263, 3258457,
     5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
     7062739, 2461387, 3035980,  621164, 3901472, 7153756, 2925816, 3374250,
     1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
      348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
        1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
     1182243,   87208,  636927, 4415111, 4423672, 6084020, 5095502, 4663471,
     8352605,  822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
     6695264, 4969849, 2678278, 4611469, 4829411,  635956, 8129971, 5925040,
     4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
     3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
     2998219,  141835, 8291116, 2513018, 7025525,  613238, 7070156, 6161950,
     7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
     6757063, 2105286, 6006015, 6346610,  586241, 7200804,  527981, 5637006,
     6903432, 1994046, 2491325, 6987258,  507927, 7192532, 7655613, 6545891,
     5346675, 8041997, 2647994, 3009748, 5767564, 4148469,  749577, 4357667,
     3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
     3994671, 8368538, 7009900, 3020393, 3363542,  214880,  545376, 7609976,
     3105558, 7277073,  508145, 7826699,  860144, 3430436,  140244, 6866265,
     6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
     8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
];

/// Polynomial in NTT domain for Kyber
#[derive(Clone, Debug)]
pub struct KyberPoly {
    /// Polynomial coefficients
    pub coeffs: [KyberFieldElement; KYBER_N],
}

impl Default for KyberPoly {
    fn default() -> Self {
        Self {
            coeffs: [KyberFieldElement::ZERO; KYBER_N],
        }
    }
}

impl KyberPoly {
    /// Create a new zero polynomial
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from coefficient array
    pub fn from_coeffs(coeffs: [u16; KYBER_N]) -> Self {
        let mut poly = Self::new();
        for i in 0..KYBER_N {
            poly.coeffs[i] = KyberFieldElement::new(coeffs[i]);
        }
        poly
    }

    /// Forward NTT (Cooley-Tukey, in-place, bit-reversed order)
    pub fn ntt(&mut self) {
        let mut k = 1usize;
        let mut len = 128usize;

        while len >= 2 {
            let mut start = 0usize;
            while start < KYBER_N {
                let zeta = KyberFieldElement::new(KYBER_ZETAS[k]);
                k += 1;

                for j in start..(start + len) {
                    let t = zeta * self.coeffs[j + len];
                    self.coeffs[j + len] = self.coeffs[j] - t;
                    self.coeffs[j] = self.coeffs[j] + t;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// Inverse NTT (Gentleman-Sande, in-place)
    ///
    /// Uses the same zetas table as the forward NTT, accessed in reverse order.
    /// The butterfly computes:
    ///   t = a[j]
    ///   a[j] = t + a[j+len]
    ///   a[j+len] = zeta * (a[j+len] - t)
    /// Then scales all coefficients by 128^-1 mod q.
    pub fn inv_ntt(&mut self) {
        let mut k = 127usize;
        let mut len = 2usize;

        while len <= 128 {
            let mut start = 0usize;
            while start < KYBER_N {
                let zeta = KyberFieldElement::new(KYBER_ZETAS[k]);
                k = k.wrapping_sub(1);

                for j in start..(start + len) {
                    let t = self.coeffs[j];
                    self.coeffs[j] = t + self.coeffs[j + len];
                    self.coeffs[j + len] = zeta * (self.coeffs[j + len] - t);
                }
                start += 2 * len;
            }
            len <<= 1;
        }

        // Multiply by 128^-1 mod q
        let f = KyberFieldElement::new(KYBER_N_INV);
        for coeff in self.coeffs.iter_mut() {
            *coeff = *coeff * f;
        }
    }

    /// Pointwise multiplication in NTT domain (base case multiplication)
    ///
    /// After the NTT, each pair of coefficients (a[2i], a[2i+1]) represents
    /// an element in a degree-1 quotient ring Z_q[X]/(X^2 - zeta^(2*br(i)+1)).
    /// The basemul multiplies two such elements and reduces modulo the quadratic.
    pub fn pointwise_mul(&self, other: &Self) -> Self {
        let mut result = Self::new();

        // In NTT domain, we have 128 pairs of coefficients.
        // Each pair lives in Z_q[X]/(X^2 - zeta_{2i+1}).
        // The zeta for pair i is KYBER_ZETAS[64 + i] but we must stay in bounds.
        // The correct approach: use the zeta that was used in the last NTT butterfly
        // for each pair. These are the zetas at tree-level 7 (len=1 would be, but
        // NTT stops at len=2, so the basemul uses zetas from the implicit final layer).
        //
        // Per the reference implementation, the zetas for basemul are:
        // zetas[64 + i] for i = 0..64 (first half)
        // But since our zetas table has 128 entries and the last level uses indices
        // 64..128, we need to handle both halves correctly.
        for i in 0..64 {
            // First basemul pair uses zeta
            let zeta = KyberFieldElement::new(KYBER_ZETAS[64 + i]);

            let a0 = self.coeffs[4 * i];
            let a1 = self.coeffs[4 * i + 1];
            let b0 = other.coeffs[4 * i];
            let b1 = other.coeffs[4 * i + 1];

            // (a0*b0 + a1*b1*zeta, a0*b1 + a1*b0)
            result.coeffs[4 * i] = a0 * b0 + a1 * b1 * zeta;
            result.coeffs[4 * i + 1] = a0 * b1 + a1 * b0;

            // Second basemul pair uses -zeta
            let neg_zeta = -zeta;

            let a2 = self.coeffs[4 * i + 2];
            let a3 = self.coeffs[4 * i + 3];
            let b2 = other.coeffs[4 * i + 2];
            let b3 = other.coeffs[4 * i + 3];

            result.coeffs[4 * i + 2] = a2 * b2 + a3 * b3 * neg_zeta;
            result.coeffs[4 * i + 3] = a2 * b3 + a3 * b2;
        }

        result
    }

    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..KYBER_N {
            result.coeffs[i] = self.coeffs[i] + other.coeffs[i];
        }
        result
    }

    /// Subtract two polynomials
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..KYBER_N {
            result.coeffs[i] = self.coeffs[i] - other.coeffs[i];
        }
        result
    }

    /// Reduce all coefficients
    pub fn reduce(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            *coeff = KyberFieldElement::barrett_reduce(coeff.value() as u32);
        }
    }

    /// Convert to bytes (little-endian, 12 bits per coefficient)
    pub fn to_bytes(&self) -> [u8; 384] {
        let mut bytes = [0u8; 384];
        for i in 0..128 {
            let a = self.coeffs[2 * i].value();
            let b = self.coeffs[2 * i + 1].value();

            bytes[3 * i] = a as u8;
            bytes[3 * i + 1] = ((a >> 8) | (b << 4)) as u8;
            bytes[3 * i + 2] = (b >> 4) as u8;
        }
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 384]) -> Self {
        let mut poly = Self::new();
        for i in 0..128 {
            let a = (bytes[3 * i] as u16) | ((bytes[3 * i + 1] as u16 & 0x0F) << 8);
            let b = ((bytes[3 * i + 1] as u16) >> 4) | ((bytes[3 * i + 2] as u16) << 4);

            poly.coeffs[2 * i] = KyberFieldElement::new(a);
            poly.coeffs[2 * i + 1] = KyberFieldElement::new(b);
        }
        poly
    }

    /// Compress polynomial to d bits per coefficient
    /// Returns (buffer, actual_length) where buffer is a fixed-size array
    /// Max size is 256*12/8 = 384 bytes for d=12
    pub fn compress(&self, d: u32) -> ([u8; 384], usize) {
        let total_bits = KYBER_N * d as usize;
        let total_bytes = (total_bits + 7) / 8;
        let mut bytes = [0u8; 384];

        let mut bit_pos = 0usize;
        for coeff in self.coeffs.iter() {
            let compressed = coeff.compress(d);
            // Pack bits
            for bit in 0..d {
                if (compressed >> bit) & 1 == 1 {
                    bytes[bit_pos / 8] |= 1 << (bit_pos % 8);
                }
                bit_pos += 1;
            }
        }

        (bytes, total_bytes)
    }

    /// Decompress polynomial from d bits per coefficient
    pub fn decompress(bytes: &[u8], d: u32) -> Self {
        let mut poly = Self::new();
        let mut bit_pos = 0usize;

        for coeff in poly.coeffs.iter_mut() {
            let mut value = 0u16;
            for bit in 0..d {
                if (bytes[bit_pos / 8] >> (bit_pos % 8)) & 1 == 1 {
                    value |= 1 << bit;
                }
                bit_pos += 1;
            }
            *coeff = KyberFieldElement::decompress(value, d);
        }

        poly
    }
}

impl zeroize::Zeroize for KyberPoly {
    fn zeroize(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            coeff.zeroize();
        }
    }
}

/// Polynomial for Dilithium
#[derive(Clone, Debug)]
pub struct DilithiumPoly {
    /// Polynomial coefficients
    pub coeffs: [DilithiumFieldElement; DILITHIUM_N],
}

impl Default for DilithiumPoly {
    fn default() -> Self {
        Self {
            coeffs: [DilithiumFieldElement::ZERO; DILITHIUM_N],
        }
    }
}

impl DilithiumPoly {
    /// Create a new zero polynomial
    pub fn new() -> Self {
        Self::default()
    }

    /// Forward NTT for Dilithium
    pub fn ntt(&mut self) {
        let mut k = 0usize;
        let mut len = 128usize;

        while len > 0 {
            let mut start = 0usize;
            while start < DILITHIUM_N {
                k += 1;
                let zeta = DilithiumFieldElement::new(DILITHIUM_ZETAS[k]);

                for j in start..(start + len) {
                    let t = zeta * self.coeffs[j + len];
                    self.coeffs[j + len] = self.coeffs[j] - t;
                    self.coeffs[j] = self.coeffs[j] + t;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// Inverse NTT for Dilithium
    pub fn inv_ntt(&mut self) {
        const DILITHIUM_N_INV: u32 = 8347681; // 256^-1 mod 8380417

        let mut k = 256usize;
        let mut len = 1usize;

        while len < DILITHIUM_N {
            let mut start = 0usize;
            while start < DILITHIUM_N {
                k -= 1;
                let zeta = DilithiumFieldElement::new(
                    (DILITHIUM_Q - DILITHIUM_ZETAS[k]) % DILITHIUM_Q,
                );

                for j in start..(start + len) {
                    let t = self.coeffs[j];
                    self.coeffs[j] = t + self.coeffs[j + len];
                    self.coeffs[j + len] = zeta * (t - self.coeffs[j + len]);
                }
                start += 2 * len;
            }
            len <<= 1;
        }

        // Multiply by n^-1
        let n_inv = DilithiumFieldElement::new(DILITHIUM_N_INV);
        for coeff in self.coeffs.iter_mut() {
            *coeff = *coeff * n_inv;
        }
    }

    /// Pointwise multiplication
    pub fn pointwise_mul(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..DILITHIUM_N {
            result.coeffs[i] = self.coeffs[i] * other.coeffs[i];
        }
        result
    }

    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..DILITHIUM_N {
            result.coeffs[i] = self.coeffs[i] + other.coeffs[i];
        }
        result
    }

    /// Subtract two polynomials
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..DILITHIUM_N {
            result.coeffs[i] = self.coeffs[i] - other.coeffs[i];
        }
        result
    }

    /// Check if all coefficients are within bound
    pub fn check_norm(&self, bound: u32) -> bool {
        for coeff in self.coeffs.iter() {
            let centered = coeff.to_centered().abs() as u32;
            if centered >= bound {
                return false;
            }
        }
        true
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 768] {
        // 3 bytes (24 bits) per coefficient: 256 * 3 = 768 bytes
        let mut bytes = [0u8; 768];
        for (i, coeff) in self.coeffs.iter().enumerate() {
            let val = coeff.value();
            bytes[i * 3] = val as u8;
            bytes[i * 3 + 1] = (val >> 8) as u8;
            bytes[i * 3 + 2] = (val >> 16) as u8;
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut poly = Self::new();
        for i in 0..DILITHIUM_N.min(bytes.len() / 3) {
            let val = (bytes[i * 3] as u32)
                | ((bytes[i * 3 + 1] as u32) << 8)
                | ((bytes[i * 3 + 2] as u32) << 16);
            poly.coeffs[i] = DilithiumFieldElement::new(val);
        }
        poly
    }
}

impl zeroize::Zeroize for DilithiumPoly {
    fn zeroize(&mut self) {
        for coeff in self.coeffs.iter_mut() {
            coeff.zeroize();
        }
    }
}

/// Generate NTT tables at compile time (helper for testing)
pub fn generate_kyber_zetas() -> [u16; 128] {
    const ZETA: u16 = 17; // Primitive 256th root of unity

    let mut zetas = [0u16; 128];
    let mut power = 1u32;

    // Compute powers of zeta in bit-reversed order
    for i in 0..128 {
        let br = bit_reverse_7(i as u8) as usize;
        zetas[br] = power as u16;
        power = (power * ZETA as u32) % KYBER_Q as u32;
    }

    zetas
}

/// 7-bit bit reversal for Kyber NTT
fn bit_reverse_7(x: u8) -> u8 {
    let mut result = 0u8;
    let mut input = x;
    for _ in 0..7 {
        result = (result << 1) | (input & 1);
        input >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_inverse() {
        let mut poly = KyberPoly::new();
        for i in 0..KYBER_N {
            poly.coeffs[i] = KyberFieldElement::new(i as u16);
        }

        let original = poly.clone();

        poly.ntt();
        poly.inv_ntt();

        for i in 0..KYBER_N {
            assert_eq!(poly.coeffs[i].value(), original.coeffs[i].value());
        }
    }

    #[test]
    fn test_polynomial_serialization() {
        let mut poly = KyberPoly::new();
        for i in 0..KYBER_N {
            poly.coeffs[i] = KyberFieldElement::new((i * 13) as u16 % KYBER_Q);
        }

        let bytes = poly.to_bytes();
        let recovered = KyberPoly::from_bytes(&bytes);

        for i in 0..KYBER_N {
            assert_eq!(poly.coeffs[i].value(), recovered.coeffs[i].value());
        }
    }
}
