
use super::gmp::mpz::Mpz;
use super::hex;

pub fn to_bytes(mpz: &Mpz) -> Vec<u8> {
    hex::decode(&mpz.to_str_radix(16)).unwrap()
}

pub type BigInteger = Mpz;
