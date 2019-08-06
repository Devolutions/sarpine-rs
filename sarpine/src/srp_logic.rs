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

use super::messages::*;
use std::io::Error;

// TODO finish adding relevant fields
pub struct Srp {
    username: String,
    a: Vec<u8>,
    mac_buf: Vec<Vec<u8>>,

    state: u8,

    is_server: bool
}

impl Srp {
    fn new() -> Self {
        Srp{
            username: String::new(),
            a: Vec::new(),
            mac_buf: Vec::new(),

            state: 0,

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
        if self.is_server {
            match self.state {
                0 => self.client_authenticate_0(in_data, out_data)?,
                1 => self.client_authenticate_1(in_data, out_data)?,
                _ => return Err(SrpErr::BadSequence)
            }
        } else {
            unimplemented!();
        }
        Ok(())
        //TODO match state
    }

    // Server initiate -> offer
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

    // Client offer -> accept
    fn client_authenticate_1(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) -> Result<(), SrpErr> {
        //Challenge
        let input_msg = self.read_msg(in_data)?;
        match input_msg {
            SrpMessage::Offer(_hdr, offer) => {
                // Server side

                /*// Verify server key_size
                if offer.key_size() != self.key_size {
                    return Err(SrpErr::Proto(
                        "The key the server received does not match what has been negotiated"
                            .to_owned()
                    ));
                }

                let server_ciphers = Cipher::from_flags(offer.ciphers);     //??

                self.generator = BigUint::from_bytes_be(&offer.generator);
                self.prime = BigUint::from_bytes_be(&offer.prime);

                let mut private_key_bytes = vec![0u8; self.key_size as usize];

                fill_random(&mut private_key_bytes)?;       //fil_bytes instead?

                self.private_key = BigUint::from_bytes_be(&private_key_bytes);

                let public_key = self.generator.modpow(&self.private_key, &self.prime);

                fill_random(&mut self.client_nonce)?;

                self.server_nonce = offer.nonce;
                self.secret_key = BigUint::from_bytes_be(&offer.public_key)
                    .modpow(&self.private_key, &self.prime)
                    .to_bytes_be();

                self.derive_keys();

                let key_size = offer.key_size();

                // Generate cbt
                let cbt_data = self.compute_cbt(&self.client_nonce)?;

                // Accept
                let mut common_ciphers = Vec::new();
                for c in &server_ciphers {
                    if self.supported_ciphers.contains(c) {
                        common_ciphers.push(*c);
                    }
                }

                self.cipher = Cipher::best_cipher(&common_ciphers)?;

                let mut out_msg = new_srd_accept_msg(
                    self.seq_num,
                    self.use_cbt,
                    self.cipher.flag(),
                    key_size,
                    public_key.to_bytes_be(),
                    self.client_nonce,
                    cbt_data,
                );

                self.write_msg(&mut out_msg, &mut out_data)?;

                Ok(())*/
            }
            _ => {
                return Err(SrpErr::BadSequence);
            }
        }
        Ok(())
    }

    // Client confirm -> delegate
    fn client_authenticate_2(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) -> Result<(), SrpErr> {
        //Challenge
        let input_msg = self.read_msg(in_data)?;
        match input_msg {
            SrpMessage::Offer(_hdr, offer) => { //FIXME
                let username = self.username.clone();
                let password = b"m83y6f".to_vec();  //FIXME user in
                let a = self.a.clone();

                let client = SrpClient::<Sha256>::new(&a, &G_2048);
                let a_pub = client.get_a_pub();

                let private_key = srp_private_key::<Sha256>(
                    username.as_bytes(),
                    password.as_slice(),
                    &offer.s.1
                ).to_owned();

                let verifier = client.process_reply(
                    private_key.as_ref(),
                    &offer.B.1,
                    &offer.s.1,
                    username.as_bytes()
                ).unwrap();

                let user_proof = verifier.get_proof();
                //Context::set_verifier(verifier);

                //let mut hmac = Hmac::<Sha256>::new_varkey(&private_key).unwrap();
                //TODO!
                //hmac.input(&self.get_mac_data()
                //   .map_err(|_| SrpErr::Internal("MAC can't be calculated".to_owned()))?);



                //FIXME
                /*NowAuthSrp::Srp3 (SrpAcceptMsg {
                    header: SrpHeader {
                        signature: 0x00505253,
                        msg_type: SRP_ACCEPT_MSG_ID,
                        version: 6,
                        flags: 0x0001
                    },
                    M: SrpBuffer{
                        size: user_proof.len() as u16,
                        data: user_proof.as_slice()
                    },
                    mac: //TODO
                });*/
                Ok(())

                /*// Verify server key_size
                if offer.key_size() != self.key_size {
                    return Err(SrpErr::Proto(
                        "The key the server received does not match what has been negotiated"
                            .to_owned()
                    ));
                }

                let server_ciphers = Cipher::from_flags(offer.ciphers);     //??

                self.generator = BigUint::from_bytes_be(&offer.generator);
                self.prime = BigUint::from_bytes_be(&offer.prime);

                let mut private_key_bytes = vec![0u8; self.key_size as usize];

                fill_random(&mut private_key_bytes)?;       //fil_bytes instead?

                self.private_key = BigUint::from_bytes_be(&private_key_bytes);

                let public_key = self.generator.modpow(&self.private_key, &self.prime);

                fill_random(&mut self.client_nonce)?;

                self.server_nonce = offer.nonce;
                self.secret_key = BigUint::from_bytes_be(&offer.public_key)
                    .modpow(&self.private_key, &self.prime)
                    .to_bytes_be();

                self.derive_keys();

                let key_size = offer.key_size();

                // Generate cbt
                let cbt_data = self.compute_cbt(&self.client_nonce)?;

                // Accept
                let mut common_ciphers = Vec::new();
                for c in &server_ciphers {
                    if self.supported_ciphers.contains(c) {
                        common_ciphers.push(*c);
                    }
                }

                self.cipher = Cipher::best_cipher(&common_ciphers)?;

                let mut out_msg = new_srd_accept_msg(
                    self.seq_num,
                    self.use_cbt,
                    self.cipher.flag(),
                    key_size,
                    public_key.to_bytes_be(),
                    self.client_nonce,
                    cbt_data,
                );

                self.write_msg(&mut out_msg, &mut out_data)?;

                Ok(())*/
            }
            _ => {
                return Err(SrpErr::BadSequence);
            }
        }
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