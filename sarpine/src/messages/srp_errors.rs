use std::io::Error;
use std::fmt;
use hmac::crypto_mac::InvalidKeyLength;

#[derive(Debug)]
pub enum SrpErr {
    Io(Error),
    BadSequence,
    Rng,
    InvalidInitiate,
    UnknownMsgType,
    Proto(String),
    InvalidSignature,
    Internal(String),
    InvalidMac,
    InvalidKeySize
}

impl fmt::Display for SrpErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &SrpErr::Io(ref error) => error.fmt(f),
            &SrpErr::BadSequence => write!(f, "Sequence error"),
            &SrpErr::Rng => write!(f, "RNG error"),
            &SrpErr::InvalidInitiate => write!(f, "Initiate message error"),
            &SrpErr::UnknownMsgType => write!(f, "Unknown message type"),
            &SrpErr::Proto(ref desc) => write!(f, "Protocol error: {}", desc),
            &SrpErr::InvalidSignature => write!(f, "Signature error"),
            &SrpErr::Internal(ref desc) => write!(f, "Internal error: {}", desc),
            &SrpErr::InvalidMac => write!(f, "MAC error"),
            &SrpErr::InvalidKeySize => write!(f, "Key Size error"),
        }
    }
}

impl std::error::Error for SrpErr {
    fn description(&self) -> &str {
        match *self {
            SrpErr::Io(ref error) => error.description(),
            SrpErr::BadSequence => "Unexpected packet received",
            SrpErr::Rng => "Couldn't generate random keys",
            SrpErr::InvalidInitiate => "Couldn't initiate",    //FIXME add accurate description
            SrpErr::UnknownMsgType => "Unknown message type",
            SrpErr::Proto(_) => "Protocol error",
            SrpErr::InvalidSignature => "Packet signature is invalid",
            SrpErr::Internal(_) => "Internal error",
            SrpErr::InvalidMac => "Message authentication code is invalid",
            SrpErr::InvalidKeySize => "Key size must be 256, 512 or 1024",
        }
    }
}

impl From<Error> for SrpErr {
    fn from(error: Error) -> SrpErr {
        SrpErr::Io(error)
    }
}

impl From<InvalidKeyLength> for SrpErr {
    fn from(_error: InvalidKeyLength) -> SrpErr {
        SrpErr::InvalidKeySize
    }
}