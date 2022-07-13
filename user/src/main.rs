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
    U8 = 2,
    Bin = 3,
}
impl neli::consts::genl::NlAttrType for KsecAttribute {}

use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};
use x86_64::VirtAddr;
use std::process;
use clap::Parser;
use x86_64::structures::idt::{Entry, HandlerFunc};

fn send_netlink_message(cmd: KsecCommand) -> Nlmsghdr<u16, Genlmsghdr<KsecCommand, KsecAttribute>> {
    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic,
        Some(0),
        &[],
    ).unwrap();

    let family_id = sock.resolve_genl_family(FAMILY_NAME).unwrap();

    let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::U8,
            1 as u8,
        ).unwrap(),
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

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    get_idt_entries: bool,
}

const N_IDT: usize = 1024;

fn main() {
    let args = Args::parse();

    if args.get_idt_entries {
        let res = send_netlink_message(KsecCommand::GetIDTEntries);
        let attr_handle = res.get_payload().unwrap().get_attr_handle();
        let attr = attr_handle
            .get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::Bin)
            .unwrap();

        let entries = unsafe { std::slice::from_raw_parts(attr.as_ptr() as *const Entry<HandlerFunc>, N_IDT) };
        for i in 0..N_IDT {
            if entries[i].handler_addr() != VirtAddr::new(0) {
                println!("{:?}", entries[i]);
            }
        }
    }

    return;
}

