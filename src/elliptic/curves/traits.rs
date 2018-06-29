
use ::Point;
use ::BigInteger as BigInt;

pub trait CurveConstCodec {
    fn get_base_point() -> Point;
    fn get_q() -> BigInt;
}

/// Secret Key Codec: BigInt <> SecretKey
pub trait SecretKeyCodec<EC> {
    fn new_random(s: &EC) -> Self;
    fn from_big_uint(s: &EC, n: &BigInt) -> Self;

    fn to_big_uint(&self) -> BigInt;
}

/// Public Key Codec: Point <> PublicKey
pub trait PublicKeyCodec<EC, SK> {
    const KEY_SIZE: usize;
    const HEADER_MARKER: usize;

    fn randomize(&mut self, s : &EC) -> SK;
    fn to_point(&self) -> Point;

    fn from_key_slice(key: &[u8]) -> Point;
    fn to_key(s : &EC, p: &Point) -> Self;
    fn to_key_slice(p: &Point) -> Vec<u8>;
}
