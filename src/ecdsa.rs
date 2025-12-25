use crate::curve::{N, Point, generator};
use crate::scalar::Scalar;
use crypto_bigint::U256;
use rfc6979::HmacDrbg;
use sha2::Sha256;

/// ECDSA signature with recovery id
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
    pub v: u8, // recovery_id: 0 or 1 (Ethereum legacy: 27 or 28)
}

impl Signature {
    pub fn new(r: Scalar, s: Scalar, v: u8) -> Self {
        Self { r, s, v }
    }

    /// Check if r, s are in [1, n-1]
    pub fn is_valid(&self) -> bool {
        let r = self.r.retrieve();
        let s = self.s.retrieve();
        let zero = U256::ZERO;
        let n = U256::from_be_hex(N);

        r > zero && r < n && s > zero && s < n
    }

    /// Normalize to low-s form. If s > n/2, replace with n - s and flip v.
    pub fn normalize(&self) -> Self {
        let n = U256::from_be_hex(N);
        let half_n = n.wrapping_shr(1);
        let s_val = self.s.retrieve();

        if s_val > half_n {
            let new_s = Scalar::new(&n.wrapping_sub(&s_val));
            Self {
                r: self.r.clone(),
                s: new_s,
                v: self.v ^ 1,
            }
        } else {
            self.clone()
        }
    }

    /// Get Ethereum legacy v value (27 or 28)
    pub fn v_legacy(&self) -> u8 {
        27 + self.v
    }

    /// Get EIP-155 v value
    pub fn v_eip155(&self, chain_id: u64) -> u64 {
        35 + chain_id * 2 + self.v as u64
    }
}

/// Generate deterministic k using RFC6979
fn generate_k_rfc6979(priv_key: &Scalar, msg_hash: &[u8; 32]) -> Scalar {
    let priv_bytes = priv_key.retrieve().to_be_bytes();
    let n = U256::from_be_hex(N);
    let mut drbg = HmacDrbg::<Sha256>::new(&priv_bytes, msg_hash, &[]);

    loop {
        let mut k_bytes = [0u8; 32];
        drbg.fill_bytes(&mut k_bytes);
        let k_val = U256::from_be_slice(&k_bytes);

        if k_val > U256::ZERO && k_val < n {
            return Scalar::new(&k_val);
        }
    }
}

/// ECDSA sign with provided nonce k
pub fn sign(priv_key: &Scalar, msg_hash: &Scalar, k: &Scalar) -> Option<Signature> {
    let g = generator();
    let r_point = g * k.retrieve();

    let r_x = r_point.x()?;
    let r_y = r_point.y()?;

    // recovery_id: 1 if y is odd, 0 otherwise
    let is_y_odd = r_y.to_be_bytes()[31] & 1 == 1;
    let recovery_id: u8 = if is_y_odd { 1 } else { 0 };

    let r = Scalar::new(&r_x);
    if r.retrieve() == U256::ZERO {
        return None;
    }

    // s = k^(-1) * (z + r * d) mod n
    let k_inv_opt = k.invert();
    if k_inv_opt.is_none().into() {
        return None;
    }
    let k_inv = k_inv_opt.unwrap();

    let r_times_d = r.clone() * priv_key.clone();
    let z_plus_rd = msg_hash.clone() + r_times_d;
    let s = k_inv * z_plus_rd;

    if s.retrieve() == U256::ZERO {
        return None;
    }

    Some(Signature::new(r, s, recovery_id).normalize())
}

/// ECDSA sign with RFC6979 deterministic k
pub fn sign_hash(priv_key: &Scalar, msg_hash: &[u8; 32]) -> Option<Signature> {
    let k = generate_k_rfc6979(priv_key, msg_hash);
    let msg_scalar = Scalar::new(&U256::from_be_slice(msg_hash));
    sign(priv_key, &msg_scalar, &k)
}

/// ECDSA verify signature
pub fn verify(pub_key: &Point, msg_hash: &Scalar, sig: &Signature) -> bool {
    if !sig.is_valid() || pub_key.is_infinity() {
        return false;
    }

    let r = &sig.r;
    let s = &sig.s;
    let z = msg_hash;

    let s_inv_opt = s.invert();
    if s_inv_opt.is_none().into() {
        return false;
    }
    let s_inv = s_inv_opt.unwrap();

    let u1 = z.clone() * s_inv.clone();
    let u2 = r.clone() * s_inv;

    let g = generator();
    let r_point = g * u1.retrieve() + pub_key.clone() * u2.retrieve();

    if r_point.is_infinity() {
        return false;
    }

    match r_point.x() {
        Some(x) => Scalar::new(&x).retrieve() == r.retrieve(),
        None => false,
    }
}

/// Derive public key from private key
pub fn public_key_from_private(priv_key: &Scalar) -> Point {
    generator() * priv_key.retrieve()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn test_sign_and_verify() {
        let priv_key = Scalar::new(&U256::from_u64(12345));
        let pub_key = public_key_from_private(&priv_key);

        let msg_hash = Scalar::new(&U256::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ));

        let k = Scalar::new(&U256::from_u64(98765));

        let sig = sign(&priv_key, &msg_hash, &k).expect("sign failed");
        assert!(verify(&pub_key, &msg_hash, &sig), "verify failed");
    }

    #[test]
    fn test_verify_fails_with_wrong_message() {
        let priv_key = Scalar::new(&U256::from_u64(12345));
        let pub_key = public_key_from_private(&priv_key);

        let msg_hash = Scalar::new(&U256::from_u64(1));
        let k = Scalar::new(&U256::from_u64(98765));

        let sig = sign(&priv_key, &msg_hash, &k).expect("sign failed");

        let wrong_msg = Scalar::new(&U256::from_u64(2));
        assert!(!verify(&pub_key, &wrong_msg, &sig), "should fail");
    }

    #[test]
    fn test_verify_fails_with_wrong_pubkey() {
        let priv_key = Scalar::new(&U256::from_u64(12345));
        let _pub_key = public_key_from_private(&priv_key);

        let msg_hash = Scalar::new(&U256::from_u64(1));
        let k = Scalar::new(&U256::from_u64(98765));

        let sig = sign(&priv_key, &msg_hash, &k).expect("sign failed");

        let wrong_priv = Scalar::new(&U256::from_u64(54321));
        let wrong_pub = public_key_from_private(&wrong_priv);
        assert!(!verify(&wrong_pub, &msg_hash, &sig), "should fail");
    }

    #[test]
    fn test_signature_normalization() {
        let n = U256::from_be_hex(N);
        let half_n = n.wrapping_shr(1);

        // Create signature with s > n/2
        let high_s = half_n.wrapping_add(&U256::from_u64(1000));
        let r = Scalar::new(&U256::from_u64(12345));
        let s = Scalar::new(&high_s);

        let sig = Signature::new(r.clone(), s, 0);
        let normalized = sig.normalize();

        assert!(normalized.s.retrieve() <= half_n, "s should be <= n/2");
        assert_eq!(normalized.v, 1, "v should be flipped");
    }

    #[test]
    fn test_known_vector() {
        // priv_key = 1, so pub_key = G
        let priv_key = Scalar::new(&U256::from_u64(1));
        let pub_key = public_key_from_private(&priv_key);

        let g = generator();
        assert_eq!(pub_key.x(), g.x());
        assert_eq!(pub_key.y(), g.y());

        let msg_hash = Scalar::new(&U256::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ));

        let k = Scalar::new(&U256::from_u64(2));

        let sig = sign(&priv_key, &msg_hash, &k).expect("sign failed");
        assert!(verify(&pub_key, &msg_hash, &sig), "known vector failed");

        // r = x-coord of 2*G mod n
        let expected_r =
            U256::from_be_hex("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5");
        assert_eq!(sig.r.retrieve(), expected_r);
    }

    #[test]
    fn test_multiple_signatures() {
        let priv_key = Scalar::new(&U256::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000ABCDEF",
        ));
        let pub_key = public_key_from_private(&priv_key);

        for i in 1..=5 {
            let msg_hash = Scalar::new(&U256::from_u64(i * 1000));
            let k = Scalar::new(&U256::from_u64(i * 7777 + 1));

            let sig = sign(&priv_key, &msg_hash, &k).expect("sign failed");
            assert!(verify(&pub_key, &msg_hash, &sig), "sig {} failed", i);
        }
    }

    #[test]
    fn test_sign_hash_rfc6979() {
        let priv_key = Scalar::new(&U256::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000012345",
        ));
        let pub_key = public_key_from_private(&priv_key);

        let msg_hash: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xDE, 0xAD, 0xBE, 0xEF,
        ];

        let sig = sign_hash(&priv_key, &msg_hash).expect("RFC6979 sign failed");

        let msg_scalar = Scalar::new(&U256::from_be_slice(&msg_hash));
        assert!(verify(&pub_key, &msg_scalar, &sig), "RFC6979 verify failed");

        assert!(sig.v <= 1, "v should be 0 or 1");
        assert!(
            sig.v_legacy() == 27 || sig.v_legacy() == 28,
            "v_legacy should be 27 or 28"
        );
    }

    #[test]
    fn test_rfc6979_deterministic() {
        let priv_key = Scalar::new(&U256::from_u64(12345));
        let msg_hash: [u8; 32] = [0xAB; 32];

        let sig1 = sign_hash(&priv_key, &msg_hash).expect("sign1 failed");
        let sig2 = sign_hash(&priv_key, &msg_hash).expect("sign2 failed");

        // Same privkey + msg should produce same signature
        assert_eq!(sig1.r.retrieve(), sig2.r.retrieve(), "r mismatch");
        assert_eq!(sig1.s.retrieve(), sig2.s.retrieve(), "s mismatch");
        assert_eq!(sig1.v, sig2.v, "v mismatch");
    }

    #[test]
    fn test_v_eip155() {
        let priv_key = Scalar::new(&U256::from_u64(1));
        let msg_hash = Scalar::new(&U256::from_u64(1));
        let k = Scalar::new(&U256::from_u64(2));

        let sig = sign(&priv_key, &msg_hash, &k).expect("sign failed");

        // Ethereum mainnet chain_id = 1
        let v_mainnet = sig.v_eip155(1);
        assert!(
            v_mainnet == 37 || v_mainnet == 38,
            "mainnet v should be 37 or 38"
        );

        // v_eip155 = 35 + chain_id * 2 + recovery_id
        assert_eq!(v_mainnet, 35 + 1 * 2 + sig.v as u64, "EIP-155 v calc error");
    }
}
