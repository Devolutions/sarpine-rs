use std::io::{Read, Write, Error};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use messages::srp_message::Message;
use messages::SrpErr;

pub struct SrpOffer {
    prime_size: u16,
    hash_type: u16,
    reserved: u32,
    pub s: (u16, Vec<u8>),
    pub B: (u16, Vec<u8>)
}

impl Message for SrpOffer {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, SrpErr>
        where
            Self: Sized,
    {
        let prime_size = reader.read_u16::<LittleEndian>()?;
        let hash_type = reader.read_u16::<LittleEndian>()?;

        let reserved = reader.read_u32::<LittleEndian>()?;

        let mut s_size = reader.read_u16::<LittleEndian>()?;
        let mut s_data = vec![0u8; s_size as usize];
        reader.read_exact(&mut s_data)?;

        let mut B_size = reader.read_u16::<LittleEndian>()?;
        let mut B_data = vec![0u8; B_size as usize];
        reader.read_exact(&mut B_data)?;

        Ok(SrpOffer {
            prime_size,
            hash_type,
            reserved,
            s: (s_size, s_data),
            B: (B_size, B_data)
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SrpErr> {
        writer.write_u16::<LittleEndian>(self.prime_size)?;
        writer.write_u16::<LittleEndian>(self.hash_type)?;
        writer.write_u32::<LittleEndian>(self.reserved)?;
        writer.write_u16::<LittleEndian>(self.s.0)?;
        writer.write_all(&self.s.1)?;
        writer.write_u16::<LittleEndian>(self.B.0)?;
        writer.write_all(&self.B.1)?;

        Ok(())
    }
}
