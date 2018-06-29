
use super::gmp::mpz::Mpz;
use super::traits::{ Converter, Modulo };
use std::borrow::Borrow;

impl Converter for Mpz {
    fn to_vec(value: &Mpz) -> Vec<u8> {
        let bytes: Vec<u8> = value.borrow().into();
        bytes
    }
}

impl Modulo for Mpz {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.powm(exponent, modulus)
    }

    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) * b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.mod_floor(modulus);
        let b_m = b.mod_floor(modulus);

        if a_m >= b_m {
            (a_m - b_m).mod_floor(modulus)
        } else {
            (a + (b + modulus)).mod_floor(modulus)
        }
    }
}

pub type BigInteger = Mpz;
