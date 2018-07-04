
use ::BigInt;

use ::EC;
use ::PK;

const R_BYTES_SIZE : usize = 32;

use elliptic::curves::traits::*;

use arithmetic::traits::Samplable;

use cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptographic_primitives::proofs::ProofError;

use cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptographic_primitives::commitments::traits::Commitment;

// TODO: remove the next line when unit test will be done
#[allow(dead_code)]
#[derive(Debug)]
pub struct FirstMsgCommitments {
    pub pk_commitment : BigInt,
    pk_commitment_blind_factor : BigInt,

    pub zk_pok_commitment : BigInt,
    zk_pok_blind_factor : BigInt,

    d_log_proof : DLogProof
}

impl FirstMsgCommitments {
    pub fn create(ec_context: &EC) -> FirstMsgCommitments {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context);

        let d_log_proof = DLogProof::prove(&ec_context, &pk, &sk);

        let pk_commitment_blind_factor = BigInt::sample(R_BYTES_SIZE);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.to_point().x, &pk_commitment_blind_factor);

        let zk_pok_blind_factor = BigInt::sample(R_BYTES_SIZE);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.to_point().x, &zk_pok_blind_factor);

        FirstMsgCommitments {
            pk_commitment,
            pk_commitment_blind_factor,

            zk_pok_commitment,
            zk_pok_blind_factor,

            d_log_proof
        }
    }
}

#[derive(Debug)]
pub struct SecondMsgClientProofVerification {
    pub d_log_proof_result : Result<(), ProofError>
}

impl SecondMsgClientProofVerification {
    pub fn verify(ec_context: &EC, proof: &DLogProof) -> SecondMsgClientProofVerification {
        SecondMsgClientProofVerification {
            d_log_proof_result: DLogProof::verify(ec_context, proof)
        }
    }
}
