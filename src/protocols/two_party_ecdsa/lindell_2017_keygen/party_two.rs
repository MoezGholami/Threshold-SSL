use ::BigInteger as BigInt;

use ::Point;
use ::EC;
use ::PK;
use ::SK;

const R_BYTES_SIZE : usize = 32;

use elliptic::curves::traits::*;

use arithmetic::traits::Modulo;
use arithmetic::traits::Samplable;

use cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptographic_primitives::commitments::traits::Commitment;

use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

use cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptographic_primitives::proofs::ProofError;

#[derive(Debug)]
pub struct FirstMsgCommitment {
    dLog_proof : DLogProof
}

impl FirstMsgCommitment {
    pub fn create(ec_context: &EC) -> DLogProof {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context).to_big_uint();

        DLogProof::prove(&ec_context, &pk, &sk)
    }
}
