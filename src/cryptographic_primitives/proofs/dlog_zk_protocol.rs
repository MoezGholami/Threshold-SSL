
use ::BigInteger as BigInt;

use ::Point;
use ::EC;
use ::PK;
use ::SK;

use super::ProofError;

use arithmetic::traits::Modulo;

use elliptic::curves::traits::*;

use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

#[derive(Debug)]
pub struct DLogProof {
    pub pk : PK,
    pub pk_t_rand_commitment : PK,
    pub challenge_response : BigInt
}

pub trait ProveDLog {
    fn prove(ec_context: &EC, pk: &PK, sk: &BigInt) -> DLogProof;

    fn verify(ec_context: &EC, proof: &DLogProof) -> Result<(), ProofError>;
}

impl ProveDLog for DLogProof {
    fn prove(ec_context: &EC, pk: &PK, sk: &BigInt) -> DLogProof {
        let mut pk_t_rand_commitment = PK::to_key(&ec_context, &EC::get_base_point());
        let sk_t_rand_commitment = pk_t_rand_commitment.randomize(&ec_context).to_big_uint();

        let challenge = HSha256::create_hash(
            vec![&pk_t_rand_commitment.to_point().x, &EC::get_base_point().x, &pk.to_point().x]);

        let challenge_response = BigInt::mod_sub(
            &sk_t_rand_commitment, &BigInt::mod_mul(
                &challenge, &sk, &EC::get_q()),
            &EC::get_q());

        DLogProof {
            pk : *pk,
            pk_t_rand_commitment,
            challenge_response
        }
    }

    fn verify(ec_context: &EC, proof: &DLogProof) -> Result<(), ProofError> {
        let challenge = HSha256::create_hash(
            vec![
                &proof.pk_t_rand_commitment.to_point().x,
                &EC::get_base_point().x,
                &proof.pk.to_point().x]);

        let mut pk_challenge = proof.pk.clone();
        pk_challenge.mul_assign(ec_context, &SK::from_big_uint(ec_context, &challenge));

        let mut pk_verifier = PK::to_key(ec_context, &EC::get_base_point());
        pk_verifier.mul_assign(
            ec_context, &SK::from_big_uint(ec_context, &proof.challenge_response));

        let pk_verifier = pk_verifier.combine(ec_context, &pk_challenge);

        if pk_verifier.unwrap() == proof.pk_t_rand_commitment {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}
