use neli::neli_enum;

pub const FAMILY_NAME: &str = "ksec";

#[neli_enum(serialized_type = "u8")]
pub enum KsecCommand {
    Unspec = 0,
    GetIDTEntries = 1,
}
impl neli::consts::genl::Cmd for KsecCommand {}

#[neli_enum(serialized_type = "u16")]
pub enum KsecAttribute {
    Unspec = 0,
    Msg = 1,
    U16 = 2,
    Bin = 3,
}
impl neli::consts::genl::NlAttrType for KsecAttribute {}

use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        socket::NlFamily,
    },
    genl::Genlmsghdr,
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};
use std::process;
use std::env;

fn send_netlink_message(cmd: KsecCommand) -> Nlmsghdr<u16, Genlmsghdr<KsecCommand, KsecAttribute>> {
    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic,
        Some(0),
        &[],
    )
    .unwrap();

    let family_id = sock.resolve_genl_family(FAMILY_NAME).unwrap();
    let attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::Msg,
            ECHO_MSG,
        )
        .unwrap(),
    );


    let gnmsghdr = Genlmsghdr::new(
        cmd,
        1,
        attrs,
    );

    let nlmsghdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        Some(process::id()),
        NlPayload::Payload(gnmsghdr),
    );

    sock.send(nlmsghdr).expect("Failed to send");

    let res: Nlmsghdr<u16, Genlmsghdr<KsecCommand, KsecAttribute>> =
        sock.recv().expect("Didn't receive a message").unwrap();

    return res;
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let cmd: KsecCommand;

    cmd = match args[1].as_str() {
        "getIDTEntries" => KsecCommand::GetIDTEntries,
        _ => KsecCommand::GetIDTEntries,
    };

    let res = send_netlink_message(cmd);
    let attr_handle = res.get_payload().unwrap().get_attr_handle();
    let attr = attr_handle
        .get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::Bin)
        .unwrap();

    println!("{}", String::from_utf8_lossy(attr));

    return;
}

