
use paillier::*;


use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use cryptography_utils::BigInt;
use cryptography_utils::FE;
use cryptography_utils::GE;


pub struct EcKeyPair{
    u: FE,
    pub y: GE,
}

impl EcKeyPair{

    pub fn create() -> EcKeyPair{
        let u : FE = ECScalar::new_random();
        let g : GE = ECPoint::generator();
        let y = g * &u;
        EcKeyPair{
            u,
            y,
        }

    }
}
