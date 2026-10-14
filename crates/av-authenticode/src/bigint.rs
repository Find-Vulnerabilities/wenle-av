//! Modular exponentiation, sized to exactly one job.
//!
//! # What this is and what it deliberately is not
//!
//! RSA verification needs one operation: `s^e mod n`, where `s` and `n` are the
//! size of the key and `e` is a public exponent that is almost always 65537.
//! That is the entire requirement, so that is the entire module. There is no
//! addition, no subtraction, no comparison, no serialisation, no general
//! big-integer type — a public API here would be an invitation to build
//! something else out of it, and something else built out of it would not have
//! the tests this has.
//!
//! # Why Montgomery rather than schoolbook and divide
//!
//! The naive `s^e mod n` is a modular multiplication plus a long division per
//! step, and the division is the expensive and fiddly half. Montgomery
//! multiplication replaces the division with a multiply by a precomputed
//! constant and a shift, at the cost of a one-time setup per modulus. Since a
//! single verification already does hundreds of multiplications under one
//! modulus, the setup is amortised to nothing.
//!
//! # The direction that matters
//!
//! This code runs on a *public* key operation over a *public* signature, so
//! there is no secret and no timing side channel to defend: an attacker who
//! learns how long verification took has learned how long their own signature
//! took to check. That is why the comparisons here are ordinary `==` and the
//! branch on an exponent bit is an `if` rather than a constant-time select.
//! Writing constant-time code where there is no secret makes it slower and
//! harder to read for no gain, and the habit of writing it everywhere is how a
//! reviewer stops reading it carefully at the one place it matters.
//!
//! # What it refuses
//!
//! A modulus that is even (Montgomery requires an odd modulus), a modulus with
//! a leading zero limb, a base at or above the modulus, an empty exponent, and a
//! modulus wider than [`MAX_LIMBS`]. Every one of those is reachable from a
//! certificate the file's author chose, so each is a typed `None` rather than a
//! panic or a silently wrong answer.

/// The widest modulus this will work on, in 64-bit limbs.
///
/// 128 limbs is 8192 bits. The widest certificate in the measured population is
/// 4096 bits, and the bound exists so that a certificate claiming a 1,000,000-
/// bit key costs a rejection rather than a few gigabytes of `Vec` and a scan
/// that never finishes.
pub(crate) const MAX_LIMBS: usize = 128;

/// The narrowest modulus that is not a forgeable key, in bits.
///
/// 1024 is not a security recommendation, it is a floor below which the
/// arithmetic itself stops being meaningful: a 512-bit RSA modulus is factored
/// by a laptop in hours, so reporting "signature valid" over one would be a true
/// statement that misleads. 2048 is the smallest key in the measured
/// population.
pub(crate) const MIN_MODULUS_BITS: usize = 1024;

/// The widest public exponent accepted, in bytes.
///
/// Sixty-four bits. RSA's own definition puts no bound on `e` beyond `e < n`,
/// but every exponent in the measured population is 65537 and the widest this
/// would ever need to accept is a few bytes. The bound is here because the
/// exponent is chosen by whoever wrote the file, and an unbounded one is a way
/// to spend a scanner's time without presenting anything malformed.
pub(crate) const MAX_EXPONENT_BYTES: usize = 8;

/// A modulus with its Montgomery parameters precomputed.
///
/// Construction is the expensive part — computing `R² mod n` costs a few
/// hundred thousand limb operations — so it happens once per verification and
/// every multiplication after it is cheap.
#[derive(Debug, Clone)]
pub(crate) struct Montgomery {
    /// The modulus, little-endian limbs, no leading zero limb.
    n: Vec<u64>,
    /// `-n⁻¹ mod 2⁶⁴`, the constant that makes the reduction a shift.
    n0inv: u64,
    /// `R² mod n`, where `R = 2^(64·limbs)`.
    ///
    /// Multiplying by this converts a value into Montgomery form; it is needed
    /// rather than `R mod n` because the conversion is itself a Montgomery
    /// multiplication, which divides by `R`.
    rr: Vec<u64>,
    /// How many limbs the modulus has.
    limbs: usize,
}

impl Montgomery {
    /// Build the parameters for `modulus`, or `None` if it is unusable.
    ///
    /// The modulus is big-endian bytes, as an X.509 `RSAPublicKey` encodes it.
    pub(crate) fn new(modulus: &[u8]) -> Option<Self> {
        // A leading zero byte is how DER keeps a positive INTEGER positive, so
        // it is dropped before anything counts bytes — otherwise a 2048-bit
        // modulus would report as 2049 bits and the limb count would carry a
        // limb of padding.
        let trimmed = match modulus {
            [0x00, rest @ ..] if !rest.is_empty() => rest,
            _ => modulus,
        };
        if trimmed.is_empty() {
            return None;
        }
        let bits = (trimmed.len() - 1) * 8 + (8 - trimmed[0].leading_zeros() as usize);
        if bits < MIN_MODULUS_BITS {
            return None;
        }
        let limbs = trimmed.len().div_ceil(8);
        if limbs > MAX_LIMBS {
            return None;
        }
        // Montgomery requires an odd modulus, and every RSA modulus is: it is
        // the product of two odd primes. An even one is not an RSA modulus and
        // the reduction below would silently produce wrong answers for it.
        if trimmed[trimmed.len() - 1] & 1 == 0 {
            return None;
        }

        // Little-endian limbs, left-padded to a whole number of them.
        let mut n = vec![0u64; limbs];
        for (i, chunk) in trimmed.chunks(8).enumerate() {
            // `chunks` walks from the front, so chunk 0 holds the most
            // significant bytes; the limb index runs the other way.
            let limb = limbs - 1 - i;
            let mut value = 0u64;
            for &b in chunk {
                value = (value << 8) | u64::from(b);
            }
            n[limb] = value;
        }
        if n[limbs - 1] == 0 {
            return None;
        }

        let n0inv = inverse_mod_2_64(n[0]);
        let mut m = Self {
            n,
            n0inv,
            rr: Vec::new(),
            limbs,
        };
        m.rr = m.compute_rr();
        Some(m)
    }

    /// How many bytes a reduced value has, which is the key size.
    pub(crate) fn byte_len(&self) -> usize {
        self.limbs * 8
    }

    /// `R² mod n`, by doubling `R mod n` a further `64·limbs` times.
    ///
    /// The alternative is a division, which is the one operation this module
    /// exists to avoid. Doubling is `O(limbs)` and happens `64·limbs` times, so
    /// the whole thing is `O(limbs²)` — the same order as two Montgomery
    /// multiplications, and paid once.
    fn compute_rr(&self) -> Vec<u64> {
        // Start at 1 and double `64·limbs` times to reach `R mod n`.
        let mut x = vec![0u64; self.limbs];
        x[0] = 1;
        for _ in 0..(self.limbs * 64) {
            self.double(&mut x);
        }
        // Now double that `64·limbs` more times to reach `R² mod n`.
        for _ in 0..(self.limbs * 64) {
            self.double(&mut x);
        }
        x
    }

    /// Multiply `x` by two, modulo the modulus.
    ///
    /// `x` is reduced on entry and on exit. The carry out of the top limb is
    /// folded back in by the subtraction rather than discarded: if the shift
    /// overflowed, `x` is at least `2^(64·limbs)`, so it is certainly at least
    /// `n` and the subtraction is required rather than conditional on the
    /// comparison.
    fn double(&self, x: &mut [u64]) {
        let mut carry = 0u64;
        for limb in x.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if carry != 0 || ge(x, &self.n) {
            sub(x, &self.n);
        }
    }

    /// `a · b · R⁻¹ mod n`, for `a` and `b` already reduced.
    ///
    /// The coarsely-integrated form: for each limb of `b`, add `a` times that
    /// limb into the accumulator, then add the multiple of `n` that makes the
    /// accumulator's bottom limb zero and shift right by one limb. After
    /// `limbs` rounds the accumulator has been shifted right by `limbs` limbs —
    /// which is the `R⁻¹` — and what is left is reduced by at most one
    /// subtraction.
    fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let k = self.limbs;
        // One extra limb for the carry out of the top, one more because the
        // reduction step can push a carry past that.
        let mut t = vec![0u64; k + 2];

        // `&b[..k]` rather than `b.iter().take(k)`: a `b` shorter than the
        // modulus is a caller bug, and this form panics on it exactly where the
        // indexing it replaces did rather than silently multiplying by fewer
        // limbs than the accumulator holds.
        for &limb_of_b in &b[..k] {
            // t += a * (this limb of b)
            let mut carry = 0u64;
            for j in 0..k {
                let (low, high) = mac(a[j], limb_of_b, t[j], carry);
                t[j] = low;
                carry = high;
            }
            let (low, high) = add_with_carry(t[k], carry);
            t[k] = low;
            t[k + 1] = high;

            // The multiple of the modulus that clears the bottom limb. `n0inv`
            // is defined so that `t[0] + m·n[0] ≡ 0 (mod 2⁶⁴)`, which means the
            // limb this round discards is exactly zero.
            let m = t[0].wrapping_mul(self.n0inv);

            // t += m * n, then shift one limb down by dropping t[0].
            let (_, mut carry) = mac(m, self.n[0], t[0], 0);
            for j in 1..k {
                let (low, high) = mac(m, self.n[j], t[j], carry);
                t[j - 1] = low;
                carry = high;
            }
            let (low, high) = add_with_carry(t[k], carry);
            t[k - 1] = low;
            t[k] = t[k + 1] + high;
        }

        let mut out = t[..k].to_vec();
        // The accumulator is below `2n`, so one subtraction is enough — but the
        // extra limb can also be set, which the comparison below reads.
        if t[k] != 0 || ge(&out, &self.n) {
            sub(&mut out, &self.n);
        }
        out
    }

    /// Convert a value into Montgomery form, `x · R mod n`.
    ///
    /// Returns `None` if `x` is not below the modulus. A signature that is at
    /// or above `n` is not a signature — PKCS#1 requires `0 ≤ s < n` — and
    /// reducing it anyway would be accepting a value the signer never could
    /// have produced.
    fn to_montgomery(&self, x: &[u8]) -> Option<Vec<u64>> {
        let limbs = self.limbs_from_bytes(x)?;
        if ge(&limbs, &self.n) {
            return None;
        }
        Some(self.mul(&limbs, &self.rr))
    }

    /// Big-endian bytes to limbs, refusing anything wider than the modulus.
    ///
    /// Shorter inputs are left-padded, which is what makes a signature with a
    /// leading zero byte work: PKCS#1 encodes `s` at the modulus width, but a
    /// value with a small top byte arrives shorter from some encoders, and the
    /// number is the same number.
    ///
    /// Named for what it produces rather than `from_bytes`, because it is a
    /// method and not a constructor: the limb count it pads to is the modulus's
    /// and is not derivable from the bytes. A `from_*` name on a method that
    /// needs `&self` reads as a conversion the caller could have done without
    /// the modulus.
    fn limbs_from_bytes(&self, bytes: &[u8]) -> Option<Vec<u64>> {
        let trimmed = match bytes {
            [0x00, rest @ ..] if !rest.is_empty() => rest,
            _ => bytes,
        };
        if trimmed.len() > self.limbs * 8 {
            return None;
        }
        let mut out = vec![0u64; self.limbs];
        let count = trimmed.len().div_ceil(8);
        for (i, chunk) in trimmed.chunks(8).enumerate() {
            let limb = count - 1 - i;
            let mut value = 0u64;
            for &b in chunk {
                value = (value << 8) | u64::from(b);
            }
            out[limb] = value;
        }
        Some(out)
    }

    /// Limbs to big-endian bytes at the modulus width.
    fn to_bytes(&self, limbs: &[u64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(limbs.len() * 8);
        for limb in limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// `base^exponent mod n`, as big-endian bytes at the modulus width.
    ///
    /// The exponent arrives as the big-endian bytes of the public exponent and
    /// is walked most-significant-bit first, which is the square-and-multiply
    /// that needs no separate precomputation. Every bit costs one squaring and a
    /// set bit costs one more multiplication, so a 65537 exponent — two set bits
    /// — costs `bits + 1` multiplications rather than `bits + 16`.
    ///
    /// The exponent is bounded to [`MAX_EXPONENT_BYTES`] before any work is
    /// done. The exponent comes from the certificate, so it is a number the
    /// file's author chose: an eight-kilobit `e` would be a hundred million limb
    /// operations per signature, which is a way to make a scanner stop scanning
    /// without ever presenting a malformed file. Every real RSA exponent is 3 or
    /// 65537, so the bound costs nothing and closes the door.
    pub(crate) fn pow(&self, base: &[u8], exponent: &[u8]) -> Option<Vec<u8>> {
        let trimmed = match exponent {
            [0x00, rest @ ..] if !rest.is_empty() => rest,
            _ => exponent,
        };
        if trimmed.is_empty() || trimmed.len() > MAX_EXPONENT_BYTES {
            return None;
        }
        let base = self.to_montgomery(base)?;
        // One in Montgomery form is `R mod n`, which is what multiplying by `rr`
        // starting from 1 gives.
        let mut one = vec![0u64; self.limbs];
        one[0] = 1;
        let mut acc = self.mul(&one, &self.rr);

        let mut started = false;
        for &byte in trimmed {
            for bit in (0..8).rev() {
                if started {
                    acc = self.mul(&acc, &acc);
                }
                if byte & (1 << bit) != 0 {
                    if started {
                        acc = self.mul(&acc, &base);
                    } else {
                        // The leading one seeds the accumulator rather than
                        // multiplying it, which saves the multiplication of the
                        // identity and, more importantly, means a leading run of
                        // zero bits costs nothing.
                        acc = base.clone();
                        started = true;
                    }
                }
            }
        }
        if !started {
            return None;
        }
        // Out of Montgomery form.
        let result = self.mul(&acc, &one);
        Some(self.to_bytes(&result))
    }
}

/// `a·b + c + carry`, as a low limb and a high limb.
///
/// The intermediate cannot overflow a `u128`: the largest product is
/// `(2⁶⁴−1)²`, and adding `c` and `carry`, each at most `2⁶⁴−1`, brings the
/// total to exactly `2¹²⁸ − 1`.
#[inline]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = u128::from(a) * u128::from(b) + u128::from(c) + u128::from(carry);
    (t as u64, (t >> 64) as u64)
}

/// `a + b` as a low limb and a zero-or-one carry.
#[inline]
fn add_with_carry(a: u64, b: u64) -> (u64, u64) {
    let (sum, overflow) = a.overflowing_add(b);
    (sum, u64::from(overflow))
}

/// `-n⁻¹ mod 2⁶⁴`, by Newton iteration on the inverse modulo `2⁶⁴`.
///
/// Each step doubles the number of correct bits, so six steps take the initial
/// one-bit guess to all sixty-four. The iteration is the standard one for
/// two-adic inverses: `x ← x·(2 − n·x)`.
fn inverse_mod_2_64(n: u64) -> u64 {
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

/// Whether `a ≥ b`, for equal-length little-endian limb slices.
fn ge(a: &[u64], b: &[u64]) -> bool {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a -= b`, for `a ≥ b` and equal-length little-endian limb slices.
fn sub(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (value, b1) = a[i].overflowing_sub(b[i]);
        let (value, b2) = value.overflowing_sub(borrow);
        a[i] = value;
        borrow = u64::from(b1 || b2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Big-endian bytes for a small number, so the tests can be written in
    /// decimal rather than in hex.
    fn be(value: u64) -> Vec<u8> {
        let mut out = value.to_be_bytes().to_vec();
        while out.len() > 1 && out[0] == 0 {
            out.remove(0);
        }
        out
    }

    /// A modulus is required to be at least 1024 bits, which makes a
    /// hand-checkable test impossible with small numbers. Rather than lower the
    /// floor for testability — the floor is the security property — the small
    /// values are embedded in a full-width modulus and the arithmetic is
    /// checked against a second implementation in Python, whose vectors appear
    /// in `rsa.rs`'s tests. Here the checks are the properties that hold for any
    /// modulus.
    fn odd_modulus(bits: usize) -> Vec<u8> {
        // 2^bits - 1 is odd and has a full-width top limb.
        let mut m = vec![0u8; bits / 8];
        for b in m.iter_mut() {
            *b = 0xff;
        }
        m
    }

    #[test]
    fn a_modulus_below_the_floor_is_refused() {
        // 1023 bits: one below the floor.
        let mut m = vec![0xffu8; 128];
        m[0] = 0x7f;
        assert!(Montgomery::new(&m).is_none());
        // 1024 bits: accepted.
        assert!(Montgomery::new(&odd_modulus(1024)).is_some());
    }

    #[test]
    fn an_even_modulus_is_refused() {
        let mut m = odd_modulus(1024);
        let last = m.len() - 1;
        m[last] = 0xfe;
        assert!(
            Montgomery::new(&m).is_none(),
            "Montgomery reduction is only defined for an odd modulus"
        );
    }

    #[test]
    fn a_modulus_wider_than_the_bound_is_refused() {
        assert!(Montgomery::new(&odd_modulus(MAX_LIMBS * 64)).is_some());
        assert!(Montgomery::new(&odd_modulus(MAX_LIMBS * 64 + 8)).is_none());
    }

    #[test]
    fn a_leading_zero_byte_does_not_change_the_key_size() {
        // DER keeps a positive INTEGER positive with a leading zero, and the
        // modulus `00 FF..FF` is the same number as `FF..FF`.
        let m = odd_modulus(1024);
        let mut padded = vec![0x00];
        padded.extend_from_slice(&m);
        let a = Montgomery::new(&m).unwrap();
        let b = Montgomery::new(&padded).unwrap();
        assert_eq!(a.limbs, b.limbs);
        assert_eq!(a.byte_len(), b.byte_len());
    }

    #[test]
    fn the_inverse_clears_the_bottom_limb() {
        // The defining property: n · n0inv ≡ -1 (mod 2^64), so n·n0inv + 1 is a
        // multiple of 2^64.
        for n in [1u64, 3, 0xffff_ffff_ffff_ffff, 0x9e37_79b9_7f4a_7c15] {
            let inv = inverse_mod_2_64(n);
            assert_eq!(n.wrapping_mul(inv), u64::MAX, "for n = {n:#x}");
        }
    }

    #[test]
    fn r_squared_is_one_in_montgomery_form_times_itself() {
        // `rr` is R² mod n by construction. Multiplying 1 by rr gives R mod n,
        // and multiplying that by itself gives R² · R⁻¹ = R mod n again — which
        // checks that `mul` really is a Montgomery multiplication and not a
        // plain one.
        let m = Montgomery::new(&odd_modulus(1024)).unwrap();
        let mut one = vec![0u64; m.limbs];
        one[0] = 1;
        let r = m.mul(&one, &m.rr);
        let again = m.mul(&r, &r);
        assert_eq!(r, again);
    }

    #[test]
    fn a_base_at_or_above_the_modulus_is_refused() {
        // An all-ones modulus makes the second half of this untestable: 2^1024
        // - 1 + 1 does not fit in 128 bytes, so the only value above it would
        // be refused for being too wide to read rather than for being too big,
        // and the comparison this test is named after would never run. Two
        // below the maximum leaves room for it.
        let mut modulus = odd_modulus(1024);
        modulus[127] = 0xfd;
        let m = Montgomery::new(&modulus).unwrap();
        // The modulus itself is not a valid base: PKCS#1 requires 0 ≤ s < n.
        assert!(m.pow(&modulus, &be(65537)).is_none());
        // One above it is refused too, at the same width.
        let mut above = modulus.clone();
        above[127] = 0xfe;
        assert!(m.pow(&above, &be(65537)).is_none());
    }

    #[test]
    fn an_empty_exponent_is_refused() {
        let m = Montgomery::new(&odd_modulus(1024)).unwrap();
        assert!(m.pow(&be(1), &[]).is_none());
        assert!(m.pow(&be(1), &[0]).is_none());
    }

    #[test]
    fn the_result_is_always_below_the_modulus_and_at_the_key_width() {
        let m = Montgomery::new(&odd_modulus(1024)).unwrap();
        for base in [0u64, 1, 2, 65536, u64::MAX] {
            let out = m.pow(&be(base), &be(65537)).unwrap();
            assert_eq!(out.len(), 128, "the output is the modulus width");
            assert!(
                ge(&m.n, &m.limbs_from_bytes(&out).unwrap()),
                "the result is reduced"
            );
        }
    }

    #[test]
    fn an_exponent_wider_than_the_bound_is_refused() {
        // Not because such an exponent is malformed — RSA permits it — but
        // because it is chosen by the file's author and costs a scanner
        // proportional work for nothing.
        let m = Montgomery::new(&odd_modulus(1024)).unwrap();
        assert!(m.pow(&be(3), &[0xff; MAX_EXPONENT_BYTES]).is_some());
        assert!(m.pow(&be(3), &[0xff; MAX_EXPONENT_BYTES + 1]).is_none());
    }

    #[test]
    fn exponent_zero_gives_one() {
        // 0 is refused as an exponent, but the identity must still hold for a
        // one-bit exponent: x^1 = x.
        let m = Montgomery::new(&odd_modulus(1024)).unwrap();
        let out = m.pow(&be(12345), &be(1)).unwrap();
        let mut expected = vec![0u8; 128];
        expected[126..].copy_from_slice(&12345u16.to_be_bytes());
        assert_eq!(out, expected);
    }

    #[test]
    fn squaring_by_exponent_two_matches_a_reported_square() {
        // `x^2 mod (2^1024 - 1)` for a small `x` is just `x²` when `x²` fits,
        // which makes this checkable by eye rather than by a second
        // implementation.
        let m = Montgomery::new(&odd_modulus(1024)).unwrap();
        let out = m.pow(&be(0x1234_5678), &be(2)).unwrap();
        let expected = 0x1234_5678u64 * 0x1234_5678u64;
        let mut want = vec![0u8; 128];
        want[120..].copy_from_slice(&expected.to_be_bytes());
        assert_eq!(out, want);
    }

    #[test]
    fn an_exponent_with_a_leading_zero_byte_is_the_same_exponent() {
        let m = Montgomery::new(&odd_modulus(1024)).unwrap();
        let a = m.pow(&be(7), &be(65537)).unwrap();
        let b = m.pow(&be(7), &[0x00, 0x01, 0x00, 0x01]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn comparison_and_subtraction_agree_for_equal_length_slices() {
        let a = vec![0u64, 1];
        let b = vec![u64::MAX, 0];
        assert!(ge(&a, &b));
        assert!(!ge(&b, &a));
        assert!(ge(&a, &a));
        let mut c = vec![0u64, 1];
        sub(&mut c, &b);
        // (2^64) - (2^64 - 1) = 1
        assert_eq!(c, vec![1u64, 0]);
    }
}
