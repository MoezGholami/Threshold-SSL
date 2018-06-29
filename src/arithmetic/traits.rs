
pub trait Converter {
    fn to_vec(n: &Self) -> Vec<u8>;
}

pub trait Modulo {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self;
    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self;
}

pub trait Samplable {
    fn sample_below(upper: &Self) -> Self;
    fn sample_range(lower: &Self, upper: &Self) -> Self;
    fn sample(bitsize: usize) -> Self;
}

