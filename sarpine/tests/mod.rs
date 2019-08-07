extern crate srp;
extern crate sha2;
extern crate rand;
extern crate sarpine;

use sarpine::srp_logic::Srp;

fn auth_test(clt_pwd: &str, srv_pwd: &str) {
    let mut srp_client = Srp::new(false, clt_pwd);
    let mut srp_server = Srp::new(true, srv_pwd);

    let in_data = Vec::new();
    let mut srp_initiate = Vec::new();
    // client-to-server -> SrpInitiate
    srp_client.authenticate(&in_data, &mut srp_initiate).unwrap();

    // server-to-client -> SrpOffer
    let mut srp_offer = Vec::new();
    srp_server.authenticate(&srp_initiate, &mut srp_offer).unwrap();

    // client-to-server -> SrpAccept
    let mut srp_accept = Vec::new();
    srp_client.authenticate(&srp_offer, &mut srp_accept).unwrap();

    // client-to-server -> SrpConfirm
    let mut srp_confirm = Vec::new();
    srp_server.authenticate(&srp_accept, &mut srp_confirm).unwrap();

    // client verifies server
    let mut ver = Vec::new();
    srp_client.authenticate(&srp_confirm, &mut ver).unwrap();
}

#[test]
fn good_password() {
    auth_test("password", "password");
}

#[test]
#[should_panic]
fn bad_password() {
    auth_test("password", "paSsword");
}