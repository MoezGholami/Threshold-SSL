
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate cryptography_utils;
extern crate paillier;

pub mod protocols;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
}
