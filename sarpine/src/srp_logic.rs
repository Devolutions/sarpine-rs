use num::BigUint;
use srp::client::{
    SrpClient,
    SrpClientVerifier,
    srp_private_key
};
use srp::groups::{
    G_2048,
    G_1024
};
use sha2::{
    Sha256,
    Digest
};
use rand::{
    Rng,
    AsByteSliceMut,
    thread_rng
};
use hmac::{Hmac, Mac};

use super::messages::*;
use std::io::Error;
use srp::server::{UserRecord, SrpServer};

// TODO finish adding relevant fields
pub struct Srp {
    username: String,
    password: String,
    a: Vec<u8>,
    mac_buf: Vec<Vec<u8>>,
    verifier: Option<SrpClientVerifier<Sha256>>,
    server: Option<SrpServer<Sha256>>,
    state: u8,
    salt: Vec<u8>,

    is_server: bool
}

impl Srp {
    fn new() -> Self {
        Srp{
            username: "wayk".to_string(),
            password: String::new(),
            a: Vec::new(),
            mac_buf: Vec::new(),
            verifier: None,
            server: None,

            state: 0,
            salt: Vec::new(),
            is_server: false
        }
    }

    fn read_msg(&mut self, buffer: &[u8]) -> Result<SrpMessage, SrpErr> {
        let mut reader = std::io::Cursor::new(buffer);
        let msg = SrpMessage::read_from(&mut reader)?;

        if msg.seq_num() != self.state {
            return Err(SrpErr::BadSequence);
        }
        self.state += 1;

        // Keep the message to calculate future mac value
        self.mac_buf.push(Vec::from(buffer));

        // Verify mac value right now. We can't validate mac value for accept msg since we need information from
        // the message to generate the integrety key. So only for this message type, it is verified later.
        //TODO
        /*if msg.has_mac() && msg.msg_type() != SRP_ACCEPT_MSG_ID {
            self.validate_mac(&msg)?;
        }*/

        // If CBT flag is set, we have to use CBT
        //TODO
        /*if msg.has_cbt() && !self.use_cbt {
            return Err(SrpErr::InvalidCert);
        }*/

        Ok(msg)
    }


    fn authenticate(&mut self, in_data: &[u8], out_data: &mut Vec<u8>) -> Result<(), SrpErr> {
        if !self.is_server {
            match self.state {
                // client-to-server -> SrpInitiate
                0 => self.client_authenticate_0(in_data, out_data)?,
                // client-to-server -> SrpAccept
                1 => self.client_authenticate_1(in_data, out_data)?,
                _ => return Err(SrpErr::BadSequence)
            }
        } else {
            match self.state {
                // server-to-client -> SrpOffer
                0 => self.server_authenticate_0(in_data, out_data)?,
                // server-to-client -> SrpConfirm
                1 => self.server_authenticate_1(in_data, out_data)?,
                _ => return Err(SrpErr::BadSequence)
            }
        }
        Ok(())
        //TODO match state
    }

    // client-to-server -> SrpInitiate
    fn client_authenticate_0(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) -> Result<(), SrpErr>  {
        let a = {
            let mut rand = [0u8;64];
            thread_rng().fill(&mut rand[..]);
            rand
        };
        self.a = a.to_vec();
        let client = SrpClient::<Sha256>::new(&a, &G_2048);
        let a_pub = client.get_a_pub();

        let payload = SrpInitiate {
            prime_size: 256,    //2048 bits
            hash_type: 0x12,    //SHA256
            reserved: 0,
            username: (self.username.len() as u16, self.username.clone().into_bytes()),
            a_pub: (a_pub.len() as u16, a_pub)
        };
        let header = SrpHeader::new(SRP_INITIATE_MSG_ID, false, payload.size());

        let mut out_msg = SrpMessage::Initiate(
            header,
            payload
        );

        self.write_msg(&mut out_msg, &mut out_data)?;

        Ok(())
    }

    // client-to-server -> SrpAccept
    fn client_authenticate_1(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) -> Result<(), SrpErr> {
        let input_msg = self.read_msg(in_data)?;
        match input_msg {
            SrpMessage::Offer(_hdr, offer) => {
                let username = self.username.clone();
                let password = self.password.clone();
                let a = self.a.clone();

                let client = SrpClient::<Sha256>::new(&a, &G_2048);
                let a_pub = client.get_a_pub();

                let private_key = srp_private_key::<Sha256>(
                    username.as_bytes(),
                    password.as_bytes(),
                    &offer.s.1
                ).to_owned();

                let verifier = client.process_reply(
                    private_key.as_ref(),
                    &offer.B.1,
                    &offer.s.1,
                    username.as_bytes()
                ).unwrap();

                let user_proof = verifier.get_proof();
                self.verifier = Some(verifier);

                //TODO! mac
                /*let mut hmac = Hmac::<Sha256>::new_varkey(&private_key).unwrap();
                hmac.input(&self.get_mac_data()
                    .map_err(|_| SrpErr::Internal("MAC can't be calculated".to_owned()))?);*/

                let payload = SrpAccept {
                    M: (user_proof.len() as u16, user_proof.to_vec())
                };
                let header = SrpHeader::new(SRP_ACCEPT_MSG_ID, true, payload.size());

                let mut out_msg = SrpMessage::Accept(
                    header,
                    payload
                );

                self.write_msg(&mut out_msg, &mut out_data)?;
            }
            _ => {
                return Err(SrpErr::BadSequence);
            }
        }
        Ok(())
    }

    // server-to-client -> SrpOffer
    fn server_authenticate_0(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) -> Result<(), SrpErr>  {
        let input_msg = self.read_msg(in_data)?;
        match input_msg {
            SrpMessage::Initiate(_hdr, initiate) => {
                let username = &self.username.clone().into_bytes();
                let password = &self.password.clone().into_bytes();
                let salt = {
                    let mut rand = [0u8; 64];
                    thread_rng().fill(&mut rand[..]);
                    rand
                };
                self.salt = salt.to_vec();
                let private_key = srp_private_key::<Sha256>(username, password, &salt);

                self.a = initiate.a_pub.1;
                let client = SrpClient::<Sha256>::new(&self.a, &G_2048);
                let pwd_verifier = client.get_password_verifier(&private_key);

                let user = UserRecord {
                    username,
                    salt: &salt,
                    verifier: &pwd_verifier,
                };

                let b = {
                    let mut rand = [0u8; 64];
                    thread_rng().fill(&mut rand[..]);
                    rand
                };

                let a_pub = client.get_a_pub();
                let server = SrpServer::<Sha256>::new(&user, &a_pub, &b, &G_2048).unwrap();

                let b_pub = server.get_b_pub();

                let payload = SrpOffer {
                    prime_size: 256,    //2048 bits
                    hash_type: 0x12,    //SHA256
                    reserved: 0,
                    s: (salt.len() as u16, salt.to_vec()),
                    B: (b_pub.len() as u16, b_pub)
                };
                let header = SrpHeader::new(SRP_OFFER_MSG_ID, false, payload.size());

                let mut out_msg = SrpMessage::Offer(
                    header,
                    payload
                );

                self.write_msg(&mut out_msg, &mut out_data)?;
            }
            _ => {
                return Err(SrpErr::BadSequence);
            }
        }
        Ok(())
    }

    // client-to-server -> SrpConfirm
    fn server_authenticate_1(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) -> Result<(), SrpErr>  {
        let input_msg = self.read_msg(in_data)?;
        match input_msg {
            SrpMessage::Accept(_hdr, accept) => {
                let server = self.server.take().unwrap();   //FIXME unwrap
                let HAMK = server.verify(&accept.M.1, &G_2048, &self.salt.clone(), self.username.as_bytes()).unwrap();

                let payload = SrpConfirm {
                    HAMK: (HAMK.len() as u16, HAMK.to_vec()),
                    mac: Vec::new()  //FIXME
                };
                let header = SrpHeader::new(SRP_CONFIRM_MSG_ID, false, payload.size());

                let mut out_msg = SrpMessage::Confirm(
                    header,
                    payload
                );

                self.write_msg(&mut out_msg, &mut out_data)?;
            }
            _ => {
                return Err(SrpErr::BadSequence);
            }
        }
        Ok(())
    }

    fn write_msg(&mut self, msg: &mut SrpMessage, out_buffer: &mut Vec<u8>) -> Result<(), SrpErr> {
        if msg.seq_num() != self.state {
            return Err(SrpErr::BadSequence);
        }

        // Keep messages to calculate future mac values.
        // Previous MAC values are not included in MAC calculations.
        let mut v = Vec::new();
        msg.write_to(&mut v)?;
        self.mac_buf.push(v);

        //TODO
        /*if msg.has_mac() {
            msg.set_mac(&self.compute_mac()?);  //FIXME return Result instead of ()?
        }*/

        msg.write_to(out_buffer)?;

        self.state += 1;

        Ok(())
    }
}