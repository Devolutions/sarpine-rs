use std::io::{Read, Write, Error};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use messages::srp_message::Message;
use messages::SrpErr;

pub struct SrpConfirm {
    pub HAMK: (u16, Vec<u8>),
    pub mac: Vec<u8>
}

impl SrpConfirm {
    pub fn size (&self) -> usize {
        return (2 + self.HAMK.0 + 2) as usize + self.mac.len()
    }
}

impl Message for SrpConfirm {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, SrpErr>
        where
            Self: Sized,
    {
        let mut hamk_size = reader.read_u16::<LittleEndian>()?;
        let mut hamk_data = vec![0u8; hamk_size as usize];
        reader.read_exact(&mut hamk_data)?;

        let mut mac_size = 4usize;   //FIXME calculate mac size dynamically
        let mut mac_data = vec![0u8; mac_size];
        reader.read_exact(&mut mac_data)?;

        Ok(SrpConfirm {
            HAMK: (hamk_size, hamk_data),
            mac: mac_data
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SrpErr> {
        writer.write_u16::<LittleEndian>(self.HAMK.0)?;
        writer.write_all(&self.HAMK.1)?;
        writer.write_all(&self.mac)?;

        Ok(())
    }
}
