
use cryptography_utils::BigInt;

use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;

const SECURITY_BITS : usize = 256;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::arithmetic::traits::Samplable;

use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;

// TODO: remove the next line when unit test will be done
#[allow(dead_code)]
#[derive(Debug)]
pub struct FirstMsg{
    pub public_share: PK,
    secret_share : SK,
    pub pk_commitment : BigInt,
     pk_commitment_blind_factor : BigInt,

    pub zk_pok_commitment : BigInt,
    zk_pok_blind_factor : BigInt,

    d_log_proof : DLogProof
}

impl FirstMsg {
    pub fn create_commitments(ec_context: &EC) -> FirstMsg {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context);

        let d_log_proof = DLogProof::prove(&ec_context, &pk, &sk);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.to_point().x, &pk_commitment_blind_factor);

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.to_point().x, &zk_pok_blind_factor);

        FirstMsg{
            public_share: pk,
            secret_share: sk,
            pk_commitment,
            pk_commitment_blind_factor,

            zk_pok_commitment,
            zk_pok_blind_factor,

            d_log_proof
        }
    }
}

#[derive(Debug)]
pub struct SecondMsg {
    pub d_log_proof_result : Result<(), ProofError>,
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: PK,
    pub d_log_proof: DLogProof
}

impl SecondMsg {
    pub fn verify_and_decommit(ec_context: &EC, first_message: &FirstMsg , proof: &DLogProof) -> SecondMsg {
        SecondMsg {
            d_log_proof_result: DLogProof::verify(ec_context, proof),
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor,
            zk_pok_blind_factor: first_message.zk_pok_blind_factor,
            public_share: first_message.public_share,
            d_log_proof : first_message.d_log_proof
        }
    }
}
