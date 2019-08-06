pub const SRP_FLAG_MAC: u16 = 0x01;
pub const SRP_SIGNATURE: u32 = 0x00505253;

pub const SRP_INITIATE_MSG_ID: u8 = 0x01;
pub const SRP_OFFER_MSG_ID: u8 = 0x02;
pub const SRP_ACCEPT_MSG_ID: u8 = 0x03;
pub const SRP_CONFIRM_MSG_ID: u8 = 0x04;

pub mod wayknow_const {
    pub const NOW_AUTHENTICATE_TOKEN_MSG_ID: u8 = 0x01;
    pub const NOW_AUTH_SRP_ID: u8 = 0x02;
}

mod srp_header;
mod srp_initiate;
mod srp_offer;
//mod srp_accept;       TODO
//mod srp_confirm;      TODO
mod srp_errors;
mod srp_message;

pub use self::srp_header::SrpHeader;
pub use self::srp_errors::SrpErr;
pub use self::srp_initiate::SrpInitiate;
pub use self::srp_message::{SrpMessage, Message};
pub use self::srp_offer::SrpOffer;
