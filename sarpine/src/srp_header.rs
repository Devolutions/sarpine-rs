use crate::{srp_flags, now_const};
use srp_errors::SrpErr;
use std::io::{Read, Write};
use byteorder::{WriteBytesExt, LittleEndian, ReadBytesExt};
use srp_message::Message;

pub struct SrpHeader {
    subtype: u8,
    flags: u8,
    auth_type: u8,
    auth_flags: u8,
    token_size: u16,
}

impl SrdHeader {
    pub fn new(auth_type: u8, add_mac_flag: bool, token_size: usize) -> Self {
        let mut flags = 0;

        if add_mac_flag {
            flags |= SRD_FLAG_MAC;
        }

        SrpHeader {
            subtype: NOW_AUTHENTICATE_TOKEN_MSG_ID,
            flags,
            auth_type: NOW_AUTH_SRP_ID,
            auth_flags: flags,      //FIXME which flags to set for mac flag?
            token_size: token_size as u16,
        }
    }

    pub fn auth_type(&self) -> u8 {
        self.auth_type
    }

    pub fn signature(&self) -> u32 {
        self.signature
    }

    /*pub fn seq_num(&self) -> u8 {
        self.seq_num
    }

    pub fn has_cbt(&self) -> bool {
        self.flags & SRD_FLAG_CBT != 0
    }*/

    pub fn has_mac(&self) -> bool {
        self.flags & SRD_FLAG_MAC != 0
    }

    pub fn validate_flags(&self, mac_expected: bool) -> Result<(), SrpErr> {
        if !self.has_mac() && mac_expected {
            return Err(SrdError::Proto(format!(
                "SRD_FLAG_MAC must be set in message type {}",
                self.msg_type
            )));
        } else if self.has_mac() && !mac_expected {
            return Err(SrdError::Proto(format!(
                "SRD_FLAG_MAC must not be set in message type {}",
                self.msg_type
            )));
        }
        Ok(())
    }
}

impl Message for SrdHeader {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, SrpErr>
        where
            Self: Sized,
    {
        let signature = reader.read_u32::<LittleEndian>()?;
        if signature != SRD_SIGNATURE {
            return Err(SrdError::InvalidSignature);
        }

        let msg_type = reader.read_u8()?;
        let seq_num = reader.read_u8()?;
        let flags = reader.read_u16::<LittleEndian>()?;

        Ok(SrdHeader {
            signature,
            msg_type,
            seq_num,
            flags,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SrpErr> {
        writer.write_u32::<LittleEndian>(self.signature)?;
        writer.write_u8(self.msg_type)?;
        writer.write_u8(self.seq_num)?;
        writer.write_u16::<LittleEndian>(self.flags)?;
        Ok(())
    }
}