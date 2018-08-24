use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::BigInt;
use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;

use paillier::*;

use super::structs::{Visibility, WBigInt, W, WPK, WSK};

//****************** Begin: Party Two structs ******************//

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: W<DLogProof>,
    pub public_share: WPK,
    secret_share: WSK,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaillierPublic {
    pub ek: W<EncryptionKey>,
    pub encrypted_secret_share: WBigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialSig {
    pub c3: WBigInt,
}

//****************** End: Party Two structs ******************//

impl KeyGenFirstMsg {
    pub fn create(ec_context: &EC) -> KeyGenFirstMsg {
        let mut pk = PK::to_key(&PK::get_base_point());
        let sk = SK::from_big_int(&BigInt::sample_below(&SK::get_q()));
        pk.mul_assign(ec_context, &sk)
            .expect("Failed to multiply and assign");
        KeyGenFirstMsg {
            d_log_proof: W {
                val: DLogProof::prove(&ec_context, &pk, &sk),
                visibility: Visibility::Public,
            },

            public_share: WPK {
                val: pk,
                visibility: Visibility::Public,
            },

            secret_share: WSK {
                val: sk,
                visibility: Visibility::Private,
            },
        }
    }

    pub fn create_with_fixed_secret_share(ec_context: &EC, sk: SK) -> KeyGenFirstMsg {
        let mut pk = PK::to_key(&PK::get_base_point());
        pk.mul_assign(ec_context, &sk)
            .expect("Failed to multiply and assign");
        KeyGenFirstMsg {
            d_log_proof: W {
                val: DLogProof::prove(&ec_context, &pk, &sk),
                visibility: Visibility::Public,
            },

            public_share: WPK {
                val: pk,
                visibility: Visibility::Public,
            },

            secret_share: WSK {
                val: sk,
                visibility: Visibility::Private,
            },
        }
    }
}

impl KeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        ec_context: &EC,
        party_one_pk_commitment: &WBigInt,
        party_one_zk_pok_commitment: &WBigInt,
        party_one_zk_pok_blind_factor: &WBigInt,
        party_one_public_share: &WPK,
        party_one_pk_commitment_blind_factor: &WBigInt,
        party_one_d_log_proof: &W<DLogProof>,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        let mut flag = true;
        match party_one_pk_commitment.val
            == HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_public_share.val.to_point().x,
                &party_one_pk_commitment_blind_factor.val,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_one_zk_pok_commitment.val
            == HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_d_log_proof.val.pk_t_rand_commitment.to_point().x,
                &party_one_zk_pok_blind_factor.val,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        DLogProof::verify(ec_context, &party_one_d_log_proof.val)?;
        Ok(KeyGenSecondMsg {})
    }
}

impl PaillierPublic {
    pub fn verify_range_proof(
        paillier_context: &PaillierPublic,
        challenge: &W<ChallengeBits>,
        encrypted_pairs: &W<EncryptedPairs>,
        proof: &W<Proof>,
    ) -> bool {
        Paillier::verifier(
            &paillier_context.ek.val,
            &challenge.val,
            &encrypted_pairs.val,
            &proof.val,
            &SK::get_q(),
            RawCiphertext::from(&paillier_context.encrypted_secret_share.val),
        ).is_ok()
    }
    pub fn generate_correct_key_challenge(
        paillier_context: &PaillierPublic,
    ) -> (W<Challenge>, W<VerificationAid>) {
        let (challenge, verification_aid) = Paillier::challenge(&paillier_context.ek.val);
        (
            W {
                val: challenge,
                visibility: Visibility::Public,
            },
            W {
                val: verification_aid,
                visibility: Visibility::Private,
            },
        )
    }

    pub fn verify_correct_key(
        proof: &W<CorrectKeyProof>,
        aid: &W<VerificationAid>,
    ) -> Result<(), CorrectKeyProofError> {
        Paillier::verify(&proof.val, &aid.val)
    }
}

impl PartialSig {
    pub fn compute(
        ec_context: &EC,
        ek: &W<EncryptionKey>,
        encrypted_secret_share: &WBigInt,
        local_share: &KeyGenFirstMsg,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_public_share: &WPK,
        message: &BigInt,
    ) -> PartialSig {
        //compute r = k2* R1
        let mut r = ephemeral_other_public_share.clone().val;
        r.mul_assign(ec_context, &ephemeral_local_share.secret_share.val)
            .expect("Failed to multiply and assign");

        let rx = r.to_point().x.mod_floor(&SK::get_q());
        let rho = BigInt::sample_below(&SK::get_q().pow(2));
        let k2_inv = &ephemeral_local_share
            .secret_share
            .val
            .to_big_int()
            .invert(&SK::get_q())
            .unwrap();
        let partial_sig = rho * &SK::get_q() + BigInt::mod_mul(&k2_inv, message, &SK::get_q());
        let c1 = Paillier::encrypt(&ek.val, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(
                &rx,
                &local_share.secret_share.val.to_big_int(),
                &SK::get_q(),
            ),
            &SK::get_q(),
        );
        let c2 = Paillier::mul(
            &ek.val,
            RawCiphertext::from(encrypted_secret_share.clone().val),
            RawPlaintext::from(v),
        );
        //c3:
        PartialSig {
            c3: WBigInt {
                val: Paillier::add(&ek.val, c2, c1).0.into_owned(),
                visibility: Visibility::Public,
            },
        }
    }
}
