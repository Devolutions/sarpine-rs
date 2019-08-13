use std::io::{Read, Write, Error};
use byteorder::{WriteBytesExt, LittleEndian, ReadBytesExt, BigEndian};

use messages::{
    wayknow_const::*,
    SRP_FLAG_MAC,
    SrpErr,
    Message,
    SRP_SIGNATURE
};

pub struct SrpHeader {
    signature: u32,
    msg_type: u8,
    version: u8,
    flags: u16
}

impl SrpHeader {
    pub fn new(msg_type: u8, add_mac_flag: bool, token_size: usize) -> Self {
        let mut flags = 0;

        if add_mac_flag {
            flags |= SRP_FLAG_MAC;
        }

        SrpHeader {
            signature: 0x00505253,
            msg_type,
            version: 6, //FIXME version
            flags,
        }
    }

    pub fn signature(&self) -> u32 {
        self.signature
    }

    pub fn has_mac(&self) -> bool {
        self.flags & SRP_FLAG_MAC != 0
    }   //FIXME SRP_FLAG_MAC

    pub fn validate_flags(&self, mac_expected: bool) -> Result<(), SrpErr> {
        if !self.has_mac() && mac_expected {
            return Err(SrpErr::Proto(format!(
                "SRD_FLAG_MAC must be set in message type {}",
                self.msg_type
            )));
        } else if self.has_mac() && !mac_expected {
            return Err(SrpErr::Proto(format!(
                "SRD_FLAG_MAC must not be set in message type {}",
                self.msg_type
            )));
        }
        Ok(())
    }

    pub fn msg_type(&self) -> u8 {
        self.msg_type
    }
}

impl Message for SrpHeader {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, SrpErr>
        where
            Self: Sized,
    {
        let signature = reader.read_u32::<LittleEndian>()?;
        //println!("signature: {:02x?} vs {:02x?}", signature, SRP_SIGNATURE);
        if signature != SRP_SIGNATURE {
            return Err(SrpErr::InvalidSignature);
        }

        let msg_type = reader.read_u8()?;
        let version = reader.read_u8()?;
        let flags = reader.read_u16::<LittleEndian>()?;

        Ok(SrpHeader {
            signature,
            msg_type,
            version,
            flags,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SrpErr> {
        writer.write_u32::<LittleEndian>(self.signature)?;
        writer.write_u8(self.msg_type)?;
        writer.write_u8(self.version)?;
        writer.write_u16::<LittleEndian>(self.flags)?;
        Ok(())
    }
}