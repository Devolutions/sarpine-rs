use std::io::{Read, Write, Error};

use super::*;

pub trait Message {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, SrpErr>
        where
            Self: Sized;
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SrpErr>;
}

pub enum SrpMessage {
    Initiate(SrpHeader, SrpInitiate),
    Offer(SrpHeader, SrpOffer),
    Accept(SrpHeader, SrpAccept),
    Confirm(SrpHeader, SrpConfirm),
}

impl SrpMessage {
    pub fn seq_num(&self) -> u8 {
        match self {
            SrpMessage::Initiate(_, _) => 1,
            SrpMessage::Offer(_, _) => 2,
            SrpMessage::Accept(hdr, _) => 3,
            SrpMessage::Confirm(hdr, _) => 4,
        }
    }

    pub fn has_mac(&self) -> bool {
        match self {
            SrpMessage::Initiate(hdr, _) => hdr.has_mac(),
            SrpMessage::Offer(hdr, _) => hdr.has_mac(),
            SrpMessage::Accept(hdr, _) => hdr.has_mac(),
            SrpMessage::Confirm(hdr, _) => hdr.has_mac(),
        }
    }

    pub fn msg_type(&self) -> u8 {
        match self {
            SrpMessage::Initiate(hdr, _) => hdr.msg_type(),
            SrpMessage::Offer(hdr, _) => hdr.msg_type(),
            SrpMessage::Accept(hdr, _) => hdr.msg_type(),
            SrpMessage::Confirm(hdr, _) => hdr.msg_type(),
        }
    }
}

impl Message for SrpMessage {
    fn read_from<R: Read>(mut reader: &mut R) -> Result<Self, SrpErr>
        where
            Self: Sized,
    {
        let header = SrpHeader::read_from(&mut reader)?;
        match header.msg_type() {
            SRP_INITIATE_MSG_ID => {
                let initiate = SrpInitiate::read_from(&mut reader)?;
                Ok(SrpMessage::Initiate(header, initiate))  //.validate()?)  //TODO impl validate()
            }
            SRP_OFFER_MSG_ID => {
                let offer = SrpOffer::read_from(&mut reader)?;
                Ok(SrpMessage::Offer(header, offer))        //.validate()?)  //TODO impl validate()
            }
            SRP_ACCEPT_MSG_ID => {
                let accept = SrpAccept::read_from(&mut reader)?;
                Ok(SrpMessage::Accept(header, accept))      //.validate()?)  //TODO impl validate()
            }
            SRP_CONFIRM_MSG_ID => {
                let confirm = SrpConfirm::read_from(&mut reader)?;
                Ok(SrpMessage::Confirm(header, confirm))     //.validate()?) //TODO impl validate()
            }
            _ => Err(SrpErr::UnknownMsgType),
        }
    }

    fn write_to<W: Write>(&self, mut writer: &mut W) -> Result<(), SrpErr> {
        match self {
            SrpMessage::Initiate(hdr, initiate) => {
                hdr.write_to(&mut writer)?;
                initiate.write_to(&mut writer)?;
                Ok(())
            }
            SrpMessage::Offer(hdr, offer) => {
                hdr.write_to(&mut writer)?;
                offer.write_to(&mut writer)?;
                Ok(())
            }
            SrpMessage::Accept(hdr, accept) => {
                hdr.write_to(&mut writer)?;
                accept.write_to(&mut writer)?;
                Ok(())
            }
            SrpMessage::Confirm(hdr, confirm) => {
                hdr.write_to(&mut writer)?;
                confirm.write_to(&mut writer)?;
                Ok(())
            }
        }
    }
}