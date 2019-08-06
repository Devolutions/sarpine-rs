use std::io::{Read, Write, Error};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::*;

pub struct SrpAccept {
    pub M: (u16, Vec<u8>)
}

impl SrpAccept {
    pub fn size (&self) -> usize {
        return (2 + self.M.0) as usize
    }
}

impl Message for SrpAccept {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, SrpErr>
        where
            Self: Sized,
    {
        let pub_m_len = reader.read_u16::<LittleEndian>()?;
        let mut pub_m_buf = vec![0u8; pub_m_len as usize];
        reader.read_exact(&mut pub_m_buf)?;

        Ok(SrpAccept {
            M: (pub_m_len, pub_m_buf),
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SrpErr> {
        writer.write_u16::<LittleEndian>(self.M.0)?;
        writer.write_all(&self.M.1)?;
        Ok(())
    }
}

//TODO tests