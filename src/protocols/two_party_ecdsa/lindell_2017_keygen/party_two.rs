
use cryptography_utils::EC;
use cryptography_utils::PK;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;

#[derive(Debug)]
pub struct FirstMsgCommitment {
    d_log_proof : DLogProof
}

impl FirstMsgCommitment {
    pub fn create(ec_context: &EC) -> DLogProof {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context);

        DLogProof::prove(&ec_context, &pk, &sk)
    }
}
