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
use std::borrow::Borrow;
use super::messages::*;
use std::io::{Error, Write};
use srp::server::{UserRecord, SrpServer};
use srp_logic::SrpState::Success;

pub struct Srp<'a> {
    username: String,
    password: String,
    a: Vec<u8>,
    mac_buf: Vec<Vec<u8>>,
    verifier: Option<SrpClientVerifier<Sha256>>,
    server: Option<SrpServer<Sha256>>,
    client: Option<SrpClient<'a, Sha256>>,
    state: u8,
    salt: Vec<u8>,
    is_server: bool,
    priv_key: [u8;32]
}

#[derive(Debug, PartialEq)]
pub enum SrpState {
    Continue,
    Success
}

impl Srp<'_> {
    pub fn new(is_server: bool, pwd: &str) -> Self {
        Srp{
            username: "wayk".to_string(),
            password: pwd.to_owned(),
            a: Vec::new(),
            mac_buf: Vec::new(),
            verifier: None,
            server: None,
            client: None,
            state: 0,
            salt: Vec::new(),
            is_server,
            priv_key: [0u8;32]
        }
    }

    fn read_msg(&mut self, buffer: &[u8]) -> Result<SrpMessage, SrpErr> {
        self.state += 1;

        let mut reader = std::io::Cursor::new(buffer);
        let msg = SrpMessage::read_from(&mut reader)?;

        if msg.seq_num() != self.state {
            return Err(SrpErr::BadSequence);
        }

        if msg.has_mac() {      // TODO "&& msg.msg_type() != srd_msg_id::SRD_ACCEPT_MSG_ID"?
            // Keep the message without the MAC at the end (32 bytes)
            let last_index = buffer.len() - 32; //FIXME modular len
            self.mac_buf.push(buffer[0..last_index].to_vec());
            self.validate_mac(&msg)?;//FIXME here should panic on 3d message
        } else {
            // Keep the message to calculate future MAC value
            self.mac_buf.push(Vec::from(buffer));
        }

        Ok(msg)
    }


    fn write_msg(&mut self, msg: &mut SrpMessage, out_buffer: &mut Vec<u8>) -> Result<(), SrpErr> {
        self.state += 1;
        if msg.seq_num() != self.state {
            return Err(SrpErr::BadSequence);
        }

        // Keep messages to calculate future mac values.
        // Previous MAC values are not included in MAC calculations.
        let mut v = Vec::new();
        msg.write_to(&mut v)?;

        if msg.has_mac() {
            self.mac_buf.push(v[..v.len()-32].to_vec());
            msg.set_mac(&self.compute_mac()?);
        } else {
            println!("got in here");
            self.mac_buf.push(v[..v.len()].to_vec());
        }

        msg.write_to(out_buffer)?;

        Ok(())
    }

    pub fn authenticate(&mut self, in_data: &[u8], out_data: &mut Vec<u8>) -> Result<SrpState, SrpErr> {
        if !self.is_server {
            match self.state {
                // client-to-server -> SrpInitiate
                0 => self.client_authenticate_0(in_data, out_data)?,
                // client-to-server -> SrpAccept
                1 => self.client_authenticate_1(in_data, out_data)?,
                // client verifies server
                3 => {
                    self.client_authenticate_2(in_data, out_data)?;
                    return Ok(SrpState::Success)
                },
                _ => return Err(SrpErr::BadSequence)
            }
        } else {
            match self.state {
                // server-to-client -> SrpOffer
                0 => self.server_authenticate_0(in_data, out_data)?,
                // server-to-client -> SrpConfirm
                2 => {
                    self.server_authenticate_1(in_data, out_data)?;
                    return Ok(SrpState::Success)
                },
                _ => return Err(SrpErr::BadSequence)
            }
        }
        Ok(SrpState::Continue)
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
        self.client = Some(client);

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

                let client = self.client.take().unwrap();       //SrpClient::<Sha256>::new(&a, &G_2048);
                //let a_pub = client.get_a_pub();

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

                /*--------------------------------------------------------------------------------*/
                // get_key() and verify_server() both consume verifier, but need to call both for MAC
                self.a = a.to_vec();
                let client = SrpClient::<Sha256>::new(&a, &G_2048);
                let verifier = client.process_reply(
                    private_key.as_ref(),
                    &offer.B.1,
                    &offer.s.1,
                    username.as_bytes()
                ).unwrap();
                let key = verifier.get_key();

                self.priv_key.clone_from_slice(&key);
                /*--------------------------------------------------------------------------------*/

                let payload = SrpAccept {
                    M: (user_proof.len() as u16, user_proof.to_vec()),
                    mac: [0u8;32].to_vec()
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

    // client verifies server
    fn client_authenticate_2(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) -> Result<(), SrpErr> {
        let input_msg = self.read_msg(in_data)?;
        match input_msg {
            SrpMessage::Confirm(_hdr, confirm) => {
                let verifier = self.verifier.take().unwrap();
                let user_key = verifier.verify_server(&confirm.HAMK.1).unwrap();
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

                let server = SrpServer::<Sha256>::new(&user, &self.a, &b, &G_2048).unwrap();
                self.priv_key.clone_from_slice(&server.get_key());

                let b_pub = server.get_b_pub();
                self.server = Some(server);

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
                    mac: [0u8;32].to_vec()
                };

                let header = SrpHeader::new(SRP_CONFIRM_MSG_ID, true, payload.size());

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

    fn compute_mac(&self) -> Result<Vec<u8>, SrpErr> {
        let mut hmac: Hmac<Sha256> = Hmac::new_varkey(&self.priv_key).unwrap();
        hmac.input(&self.get_mac_data()
            .map_err(|_| SrpErr::Internal("MAC can't be calculated".to_owned()))?);
        Ok(hmac.result().code().to_vec())
    }

    // Return previous messages without their MACs.
    fn get_mac_data(&self) -> Result<Vec<u8>, SrpErr> {
        let mut result = Vec::new();

        for message in &self.mac_buf {
            result.write(message.as_slice())?;
        }

        Ok(result)
    }

    fn validate_mac(&self, msg: &SrpMessage) -> Result<(), SrpErr> {
        if msg.has_mac() {
            let mut hmac = Hmac::<Sha256>::new_varkey(&self.priv_key)?;
            hmac.input(&self.get_mac_data()
                .map_err(|_| SrpErr::Internal("MAC can't be calculated".to_owned()))?);

            if let Some(mac) = msg.mac() {
                hmac.verify(mac).map_err(|_| SrpErr::InvalidMac)
            } else {
                Err(SrpErr::Internal(
                    "Msg should have a MAC but we can't get it".to_owned(),
                ))
            }
        } else {
            // No mac in the message => Nothing to verify
            Ok(())
        }
    }
}