use crypto_bigint::{U256, const_monty_form, const_monty_params, modular::ConstMontyParams};

const P: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

const_monty_params!(Coordinate, U256, P);

const_monty_form!(Fe, Coordinate);

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_ecdsa_256_field() {
        let x =
            U256::from_be_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        let a = Fe::new(&x);
        let y =
            U256::from_be_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        let b = Fe::new(&y);
        let seven = U256::from_u64(7);
        let three = U256::from_u64(3);
        let x3 = a.pow(&three); // x^3
        let rhs = x3.add(&Fe::new(&seven)); // x^3 + 7
        let two = U256::from_u64(2);
        let lhs = b.pow(&two); // y^2
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_basic_inverse() {
        let a = U256::from_u64(3);
        let fe_a = Fe::new(&a);
        let fe_a_inv = fe_a.invert().unwrap();
        let one = fe_a.mul(&fe_a_inv);
        assert_eq!(one, Fe::new(&U256::from_u64(1)));
    }
}
