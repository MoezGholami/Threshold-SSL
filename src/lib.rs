
pub mod elliptic;
pub use elliptic::point::Point as Point;

// TODO: When we will have more than one type of elliptic curve, add as features
pub use elliptic::curves::secp256_k1::EC as EC;
pub use elliptic::curves::secp256_k1::SK as SK;
pub use elliptic::curves::secp256_k1::PK as PK;

pub mod arithmetic;
// TODO: When we will have more than one type of big num library, add as features
pub use arithmetic::big_gmp::BigInteger as BigInteger;

pub mod cryptographic_primitives;

pub mod protocols;
