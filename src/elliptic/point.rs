
use ::BigInt;

/// A simple Point defined by x and y
#[derive(PartialEq)]
#[derive(Debug)]
pub struct Point  {
    pub x: BigInt,
    pub y: BigInt
}

#[cfg(test)]
mod tests {
    use super::Point;
    use super::BigInt;

    #[test]
    fn equality_test() {
        let p1 = Point { x: BigInt::one(), y: BigInt::zero() };
        let p2 = Point { x: BigInt::one(), y: BigInt::zero()};
        assert_eq!(p1, p2);

        let p3 = Point { x: BigInt::zero(), y: BigInt::one() };
        assert_ne!(p1, p3);
    }
}
