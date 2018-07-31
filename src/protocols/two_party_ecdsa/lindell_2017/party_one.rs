
use cryptography_utils::BigInt;

use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;

const SECURITY_BITS: usize = 256;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use super::*;
use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use paillier::*;
use std::cmp;

impl PartyOneKeyGenFirstMsg {
    pub fn create_commitments(ec_context: &EC) -> PartyOneKeyGenFirstMsg {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());

        //in Lindell's protocol range proof works only for x1<q/3
        let sk = SK::from_big_int(
            ec_context,
            &BigInt::sample_below(&EC::get_q().div_floor(&BigInt::from(3))),
        );
        pk.mul_assign(ec_context, &sk).expect("Assignment expected");

        let d_log_proof = DLogProof::prove(&ec_context, &pk, &sk);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.to_point().x,
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.to_point().x,
            &zk_pok_blind_factor,
        );

        PartyOneKeyGenFirstMsg {
            public_share: pk,
            secret_share: sk,
            pk_commitment,
            pk_commitment_blind_factor,

            zk_pok_commitment,
            zk_pok_blind_factor,

            d_log_proof,
        }
    }
}

impl PartyOneKeyGenSecondMsg {
    pub fn verify_and_decommit(
        ec_context: &EC,
        first_message: &PartyOneKeyGenFirstMsg,
        proof: &DLogProof,
    ) -> Result<PartyOneKeyGenSecondMsg, ProofError> {
        DLogProof::verify(ec_context, proof)?;
        Ok(PartyOneKeyGenSecondMsg {
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor.clone(),
            zk_pok_blind_factor: first_message.zk_pok_blind_factor.clone(),
            public_share: first_message.public_share.clone(),
            d_log_proof: first_message.d_log_proof.clone(),
        })
    }
}

pub fn compute_pubkey(
    ec_context: &EC,
    local_share: &PartyOneKeyGenFirstMsg,
    other_share: &PartyTwoKeyGenFirstMsg,
) -> PK {
    let mut pubkey = other_share.public_share.clone();
    pubkey
        .mul_assign(ec_context, &local_share.secret_share)
        .expect("Failed to multiply and assign");

    return pubkey;
}

impl PartyOnePaillierKeyPair {
    pub fn generate_keypair_and_encrypted_share(
        keygen: &PartyOneKeyGenFirstMsg,
    ) -> PartyOnePaillierKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek);

        let encrypted_share = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(keygen.secret_share.to_big_int()),
            &randomness,
        ).0
        .into_owned();

        PartyOnePaillierKeyPair {
            ek,
            dk,
            encrypted_share,
            randomness: randomness.0,
        }
    }

    pub fn generate_range_proof(
        paillier_context: &PartyOnePaillierKeyPair,
        keygen: &PartyOneKeyGenFirstMsg,
    ) -> (EncryptedPairs, ChallengeBits, Proof) {
        let (encrypted_pairs, challenge, proof) = Paillier::prover(
            &paillier_context.ek,
            &EC::get_q(),
            &keygen.secret_share.to_big_int(),
            &paillier_context.randomness,
        );

        (encrypted_pairs, challenge, proof)
    }

    pub fn generate_proof_correct_key(
        paillier_context: &PartyOnePaillierKeyPair,
        challenge: &Challenge,
    ) -> Result<CorrectKeyProof, CorrectKeyProofError> {
        Paillier::prove(&paillier_context.dk, challenge)
    }
}

impl PartyOneSignature {
    pub fn compute(
        ec_context: &EC,
        keypair: &PartyOnePaillierKeyPair,
        partial_sig: &PartyTwoPartialSig,
        ephemeral_local_share: &PartyOneKeyGenFirstMsg,
        ephemeral_other_share: &PartyTwoKeyGenFirstMsg,
    ) -> PartyOneSignature {
        //compute r = k2* R1
        let mut r = ephemeral_other_share.public_share.clone();
        r.mul_assign(ec_context, &ephemeral_local_share.secret_share)
            .expect("Failed to multiply and assign");

        let rx = r.to_point().x.mod_floor(&EC::get_q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&EC::get_q())
            .unwrap();
        let s_tag = Paillier::decrypt(&keypair.dk, &RawCiphertext::from(&partial_sig.c3));
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.0, &EC::get_q());
        let s = cmp::min(s_tag_tag.clone(), &EC::get_q().clone() - s_tag_tag.clone());

        PartyOneSignature { s, r: rx }
    }
}

pub fn verify(
    ec_context: &EC,
    signature: &PartyOneSignature,
    pubkey: &PK,
    message: &BigInt,
) -> Result<(), ProofError> {
    let b = signature
        .s
        .invert(&EC::get_q())
        .unwrap()
        .mod_floor(&EC::get_q());
    let a = message.mod_floor(&EC::get_q());
    let u1 = BigInt::mod_mul(&a, &b, &EC::get_q());
    let u2 = BigInt::mod_mul(&signature.r, &b, &EC::get_q());
    // can be faster using shamir trick
    let mut point1 = PK::to_key(ec_context, &EC::get_base_point());

    point1
        .mul_assign(ec_context, &SK::from_big_int(ec_context, &u1))
        .expect("Failed to multiply and assign");

    let mut point2 = *pubkey;
    point2
        .mul_assign(ec_context, &SK::from_big_int(ec_context, &u2))
        .expect("Failed to multiply and assign");

    if signature.r == point1.combine(ec_context, &point2).unwrap().to_point().x {
        Ok(())
    } else {
        Err(ProofError)
    }
}
