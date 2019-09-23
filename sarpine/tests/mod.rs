extern crate sarpine;

use sarpine::srp_logic::Srp;
use sarpine::srp_logic::SrpState;

fn auth_test(user_pwd: &str) {
    let password = "password";

    let mut srp_client = Srp::new(false, user_pwd);
    let mut srp_server = Srp::new(true, password);

    let in_data = Vec::new();
    let mut srp_initiate = Vec::new();
    // client-to-server -> SrpInitiate
    srp_client.authenticate(&in_data, &mut srp_initiate).unwrap();
    println!("srp_initiate:    {:?}", srp_initiate);

    // server-to-client -> SrpOffer
    let mut srp_offer = Vec::new();
    srp_server.authenticate(&srp_initiate, &mut srp_offer).unwrap();
    println!("srp_offer:    {:?}", srp_offer);

    // client-to-server -> SrpAccept
    let mut srp_accept = Vec::new();
    srp_client.authenticate(&srp_offer, &mut srp_accept).unwrap();
    println!("srp_accept:    {:?}", srp_accept);

    // client-to-server -> SrpConfirm
    let mut srp_confirm =    Vec::new();
    srp_server.authenticate(&srp_accept, &mut srp_confirm).unwrap();
    println!("srp_confirm:   {:02x?}", srp_confirm);

    // client verifies server
    let mut ver = Vec::new();
    let auth_reuslt = srp_client.authenticate(&srp_confirm, &mut ver).unwrap();
    assert_eq!(auth_reuslt, SrpState::Success, "failed to authenticate");
}

#[test]
fn good_password() {
    auth_test("password");
}

#[test]
#[should_panic]
fn bad_password() {
    auth_test("paSsword");
}