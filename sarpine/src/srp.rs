use crate::srp_errors;

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

    fn authenticate(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) {
        if self.is_server {
            match self.state {
                0 => server_authenticate_0(&in_data, &mut out_data)?,
                1 => self.server_authenticate_1(input_data, output_data)?,
                _ => return Err(SrpErr::BadSequence)
            }
        }
        //TODO match state
        //TODO match server or client
    }

    fn server_authenticate_0 (&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) {
        let a = {
            let mut rand = [0u8;64];
            thread_rng().fill(&mut rand[..]);
            rand
        };
        self.a = a; //FIXME might not work

        let username = self.username;   //TODO might be necessary to impl an extractor fn

        let client = SrpClient::<Sha256>::new(&a, &G_2048);
        let a_pub = client.get_a_pub();

        /*SrpInitiateMsg {
            header: SrpHeader {
                signature: 0x00505253,
                msg_type: SRP_INITIATE_MSG_ID,
                version: 6,
                flags: 0
            },
            prime_size: 256,
            hash_type: 0x12,
            reserved: 0,
            I: SrpString{
                len: username.len() as u16,
                data: &username
            },
            A: SrpBuffer{
                size: a_pub.len() as u16,
                data: &a_pub
            }
        };*/

        let out_msg = SrpInitiate {
            prime_size: 256,    //2048 bits
            hash_type: 0x12,    //SHA256
            reserved: 0,
            username: (self.username.len(), self.username),
            a_pub: (a_pub.len(), a_pub)
        };

        self.write_msg(out_msg, &mut out_data)?;

        //Context::set_a(a)?;
        //Context::set_state(State::Srp2)?;

        Ok(())
    }

    // Client offer -> accept
    fn client_authenticate_1(&mut self, in_data: &[u8], mut out_data: &mut Vec<u8>) -> Result<()> {
        //Challenge
        let input_msg = self.read_msg(in_data)?;
        match input_msg {
            SrpMessage::Offer(_hdr, offer) => {
                // Verify server key_size
                if offer.key_size() != self.key_size {
                    return Err(SrdError::Proto("Key size received in offer message is not equal to key size sent to server".to_owned()));
                }

                let server_ciphers = Cipher::from_flags(offer.ciphers);

                self.generator = BigUint::from_bytes_be(&offer.generator);
                self.prime = BigUint::from_bytes_be(&offer.prime);

                let mut private_key_bytes = vec![0u8; self.key_size as usize];

                fill_random(&mut private_key_bytes)?;

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

                Ok(())
            }
            _ => {
                return Err(SrdError::BadSequence);
            }
        }
    }

    fn write_msg(&mut self, msg: &mut SrdMessage, buffer: &mut Vec<u8>) -> Result<(), SrpErr> {
        if msg.auth_type() != NOW_AUTH_SRP_ID {
            return Err(SrdError::InvalidInitiate);
        }

        if msg.seq_num() != self.seq_num {
            return Err(SrdError::BadSequence);
        }

        // Keep the message to calculate future mac value.
        // The message doesn't contain the MAC since it is not calculated yet.
        // It is not a problem since MAC are not included in MAC calculation.
        let mut v = Vec::new();
        msg.write_to(&mut v)?;
        self.messages.push(v);

        if msg.has_mac() {
            msg.set_mac(&self.compute_mac()?)
                .expect("Should never happen, has_mac returned true");  //FIXME customize pnaic msg
        }

        //FIXME cleanup
        // Remove the last message to insert it again with the mac value.
        // (not really needed, just to keep exactly what it is sent).
        /*self.messages.pop();
        msg.write_to(buffer)?;
        self.messages.push(buffer.clone());*/

        self.seq_num += 1;

        Ok(())
    }
}