use std::io::{Read, Write, Error};
use srp_message::Message;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

pub struct SrpInitiate {
    prime_size: u16,
    hash_type: u16,
    reserved: u32,
    pub username: (u16, Vec<u8>),
    pub a_pub: (u16, Vec<u8>)
}

impl Message for SrpInitiate {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error>
        where
            Self: Sized,
    {
        let prime_size = reader.read_u16::<LittleEndian>()?;
        let hash_type = reader.read_u16::<LittleEndian>()?;
        let reserved = reader.read_u32::<LittleEndian>()?;

        let username_len = reader.read_u16::<LittleEndian>()?;
        let mut username_buf = vec![0u8; username_len as usize];
        reader.read_exact(&mut username_buf)?;

        let a_pub_size = reader.read_u16::<LittleEndian>()?;
        let mut a_pub_buf = vec![0u8; a_pub_size as usize];
        reader.read_exact(&mut a_pub_buf)?;

        Ok(SrpInitiate {
            prime_size,
            hash_type,
            reserved,
            username: (username_len, username_buf),
            a_pub: (a_pub_size, a_pub_buf)
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_u16::<LittleEndian>(self.prime_size)?;
        writer.write_u16::<LittleEndian>(self.hash_type)?;
        writer.write_u32::<LittleEndian>(self.reserved)?;
        writer.write_u16::<LittleEndian>(self.username.0)?;
        writer.write_all(&self.username.1)?;
        writer.write_u16::<LittleEndian>(self.a_pub.0)?;
        writer.write_all(&self.a_pub.1)?;
        Ok(())
    }
}

//TODO tests