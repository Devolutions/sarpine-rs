use std::io::{Read, Write, Error};
use srp_initiate::{SrpHeader, SrpInitiate};

pub trait Message {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error>
        where
            Self: Sized;
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error>;
}

pub enum SrpMessage {
    Initiate(SrpHeader, SrpInitiate),
    Offer(SrpHeader, SrpOffer),
    //Accept(SrdHeader, SrdAccept),
    //Confirm(SrdHeader, SrdConfirm),
    //Delegate(SrdHeader, SrdDelegate),
}

impl SrpMessage {
    pub fn seq_num(&self) -> u8 {
        match self {
            SrpMessage::Initiate(_, _) => 0,    //FIXME reserve 0 for un-initiated state?
            SrpMessage::Offer(_, _) => 1,
            //SrdMessage::Accept(hdr, _) => hdr.seq_num(),
            //SrdMessage::Confirm(hdr, _) => hdr.seq_num(),
            //SrdMessage::Delegate(hdr, _) => hdr.seq_num(),
        }
    }
}

/*
#[derive(Serialize)]
pub struct SrpHeader {
    pub signature: u32,
    pub msg_type: u8,
    pub version: u8,
    pub flags: u16
}

#[derive(Serialize)]
pub struct SrpInitiate<'a> {
    prime_size: u16,
    hash_type: u16,
    reserved: u32,
    pub I: SrpString<'a>,
    pub A: SrpBuffer<'a>
}

#[derive(Serialize)]
pub struct SrpOffer<'a> {
    pub header: SrpHeader,
    pub prime_size: u16,
    pub hash_type: u16,
    pub reserved: u32,
    pub s: SrpBuffer<'a>,
    pub B: SrpBuffer<'a>
}

#[derive(Serialize)]
pub struct SrpAccept<'a> {
    pub header: SrpHeader,
    pub M: SrpBuffer<'a>,
    #[serde(serialize_with = "custom_array_serializer")]
    pub mac: &'a [u8]
}

#[derive(Serialize)]
pub struct SrpConfirm<'a> {
    pub header: SrpHeader,
    pub HAMK: SrpBuffer<'a>,
    #[serde(serialize_with = "custom_array_serializer")]
    pub mac: &'a [u8]
}*/
