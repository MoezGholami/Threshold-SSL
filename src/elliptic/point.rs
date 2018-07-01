
use ::BigInteger as BigInt;
use std::fmt;

/// A simple Point defined by x and y
pub struct Point  {
    pub x: BigInt,
    pub y: BigInt
}

impl PartialEq for Point {
    fn eq(&self, other: &Point) -> bool {
        self.x == other.x && self.y == other.y
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(x: {}, y: {})", self.x, self.y)
    }
}

impl fmt::Debug for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(x: {}, y: {})", self.x, self.y)
    }
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
