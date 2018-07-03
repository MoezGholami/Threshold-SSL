
use std::fmt;
use std::iter;
use std::error::Error;

pub mod dlog_zk_protocol;

#[derive(Debug)]
pub struct ProofError;

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProofError")
    }
}

impl Error for ProofError {
    fn description(&self) -> &str {
        "Error while verifying"
    }
}
