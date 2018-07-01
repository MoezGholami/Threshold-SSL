use ::BigInteger as BigInt;

use super::traits::Commitment;
use super::ring::digest::{Context, SHA256};
use std::borrow::Borrow;

pub struct HashCommitment;

impl Commitment for HashCommitment {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt, blinding_factor: &BigInt) -> BigInt
    {
        let mut digest = Context::new(&SHA256);
        let bytes_message: Vec<u8> = message.into();
        digest.update(&bytes_message);

        let bytes_blinding_factor: Vec<u8> = blinding_factor.into();
        digest.update(&bytes_blinding_factor);

        BigInt::from(digest.finish().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use ::BigInteger as BigInt;
    use super::Commitment;
    use super::HashCommitment;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_commitment_test() {
        let commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &BigInt::one(), &BigInt::zero());

        println!("{}", commitment);
    }
}
