
use ::BigInt;

pub trait Commitment {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt, blinding_factor: &BigInt) -> BigInt;

    fn create_commitment(
        message: &BigInt) -> (BigInt, BigInt);
}
