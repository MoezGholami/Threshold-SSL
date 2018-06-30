
use ::BigInteger as BigInt;

pub trait Hash {
    fn create_hash(big_ints: Vec<&BigInt>) -> BigInt;
}
