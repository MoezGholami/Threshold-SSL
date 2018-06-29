
use super::gmp::mpz::Mpz;
use super::traits::{ Converter, Modulo, Samplable };
use super::rand::{OsRng, Rng};

use std::borrow::Borrow;

impl Converter for Mpz {
    fn to_vec(value: &Mpz) -> Vec<u8> {
        let bytes: Vec<u8> = value.borrow().into();
        bytes
    }
}

// TODO: write unit test
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

impl Samplable for Mpz {
    fn sample_below(upper: &Self) -> Self {
        assert!(upper > &Mpz::zero());

        let bits = upper.bit_length();
        loop {
            let n =  Self::sample(bits);
            if n < *upper {
                return n
            }
        }
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        lower + Self::sample_below(&(upper - lower))
    }

    fn sample(bit_size: usize) -> Self {
        let mut rng = OsRng::new().unwrap();
        let bytes = (bit_size - 1) / 8 + 1;
        let mut buf: Vec<u8> = vec![0; bytes];
        rng.fill_bytes(&mut buf);
        Self::from(&*buf) >> (bytes * 8 - bit_size)
    }
}


pub type BigInteger = Mpz;

#[cfg(test)]
mod tests {
    use super::Samplable;
    use super::Mpz;

    #[test]
    #[should_panic]
    fn sample_below_zero_test() {
        Mpz::sample_below(&Mpz::from(-1));
    }

    #[test]
    fn sample_below_test() {
        let upper_bound = Mpz::from(10);

        for _ in 1..100 {
            let r = Mpz::sample_below(&upper_bound);
            assert!(r < upper_bound);
        }
    }

    #[test]
    #[should_panic]
    fn invalid_range_test() {
        Mpz::sample_range(&Mpz::from(10), &Mpz::from(9));
    }

    #[test]
    fn sample_range_test() {
        let upper_bound = Mpz::from(10);
        let lower_bound = Mpz::from(5);

        for _ in 1..100 {
            let r = Mpz::sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    #[ignore]
    // GARY: THIS TEST IS FAILING, I SUSPECT THAT THE FUNCTION RETURN A RANDOM WITH A BIT LENGTH
    // BELOW OR EQUAL TO THE INPUT. @MORTEN TO CONFIRM
    fn sample_test() {
        let len = 100000;

        for _ in 1..100 {
            let r = Mpz::sample(len);
            assert_eq!(len, r.bit_length());
        }
    }
}
