use std::io::Error;
use fmt;

pub enum SrpErr {
    Io(Error),
    BadSequence,
    Rng,
    InvalidInitiate
}

impl fmt::Display for SrpErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &SrdError::Io(ref error) => error.fmt(f),
            &SrdError::BadSequence => write!(f, "Sequence error"),
            &SrdError::Rng => write!(f, "RNG error"),
            &SrdError::InvalidInitiate => write!(f, "Initiate message error"),
        }
    }
}

impl std::error::Error for SrpErr {
    fn description(&self) -> &str {
        match *self {
            SrdError::Io(ref error) => error.description(),
            SrdError::BadSequence => "Unexpected packet received",
            SrdError::Rng => "Couldn't generate random keys",
            SrdError::InvalidInitiate => "Couldn't initiate",    //FIXME add accurate description
        }
    }
}