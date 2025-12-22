use crate::field::{Coordinate, Fe};
use crypto_bigint::{U256, modular::ConstMontyParams};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub cords: Option<(Fe, Fe)>,
}

impl Point {
    pub fn double(&self) -> Self {
        self.clone() + self.clone()
    }
}

impl core::ops::Add for Point {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        match other {
            Point { cords: None } => self,
            Point {
                cords: Some((ox, oy)),
            } => match self {
                Point { cords: None } => other,
                Point {
                    cords: Some((sx, sy)),
                } => {
                    if sx == ox {
                        if sy == oy {
                            let three = U256::from_u64(3);
                            let two = U256::from_u64(2);

                            let numerator = sx.pow(&two).mul(&Fe::new(&three));
                            let denominator = sy.mul(&Fe::new(&two));

                            let m = numerator * denominator.invert().unwrap();
                            let rx = m.pow(&two).sub(&sx.mul(&Fe::new(&two)));
                            let ry = m * (sx - rx) - sy;
                            Point {
                                cords: Some((rx, ry)),
                            }
                        } else {
                            Point { cords: None }
                        }
                    } else {
                        let m = (oy - sy) * ((ox - sx).invert().unwrap());
                        let rx = m.pow(&U256::from_u64(2)).sub(&sx).sub(&ox);
                        let ry = m.mul(&sx.sub(&rx)).sub(&sy);
                        Point {
                            cords: Some((rx, ry)),
                        }
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::U256;

    use crate::{curve::Point, field::Fe};

    #[test]
    fn test_point_addition() {
        let x1 =
            U256::from_be_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        let y1 =
            U256::from_be_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        let p1 = Point {
            cords: Some((Fe::new(&x1), Fe::new(&y1))),
        };

        let p2 = p1.clone();
        let p3 = p1 + p2;
        let expected_x =
            U256::from_be_hex("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5");
        let expected_y =
            U256::from_be_hex("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A");
        let expected_x_fe = Fe::new(&expected_x);
        let expected_y_fe = Fe::new(&expected_y);
        assert_eq!(p3.cords.as_ref().unwrap().0, expected_x_fe);
        println!("expected_y_fe: {:?}", expected_y_fe.retrieve());
        println!("cords_y: {:?}", p3.cords.as_ref().unwrap().1.retrieve());
        assert_eq!(p3.cords.unwrap().1.retrieve(), expected_y_fe.retrieve());
    }
}
