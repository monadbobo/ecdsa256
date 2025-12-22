use crypto_bigint::{U256, const_monty_form, const_monty_params, modular::ConstMontyParams};

const N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

const_monty_params!(Secp256k1N, U256, N);
const_monty_form!(Scalar, Secp256k1N);

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn test_scalar_inverse() {
        let two = Scalar::new(&U256::from_u64(2));
        let inv_two = two.invert().unwrap();
        let one = two * inv_two;

        assert_eq!(one.retrieve(), U256::from_u64(1));
    }

    #[test]
    fn test_scalar_mod_n() {
        let n_plus_one = U256::from_be_hex(N).wrapping_add(&U256::from_u64(1));
        let s = Scalar::new(&n_plus_one);

        assert_eq!(s.retrieve(), U256::from_u64(1));
    }
}
