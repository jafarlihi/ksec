use log::{info, warn};
extern crate pretty_env_logger;
#[macro_use] extern crate log;

use neli::neli_enum;

const FAMILY_NAME: &str = "ksec";

#[neli_enum(serialized_type = "u8")]
enum KsecCommand {
    Unspec = 0,
    IsKernelAddr = 1,
    IsModuleAddr = 2,
    GetIDTEntries = 3,
}
impl neli::consts::genl::Cmd for KsecCommand {}

#[neli_enum(serialized_type = "u16")]
enum KsecAttribute {
    Unspec = 0,
    Str = 1,
    Bin = 2,
    U64 = 3,
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
use procfs::process::MemoryMap;
use x86_64::{VirtAddr};
use x86_64::structures::idt::{Entry, HandlerFunc};
use std::process;
use clap::Parser;
use std::fmt;

extern crate procfs;

fn send_netlink_message(cmd: KsecCommand, attrs: GenlBuffer<KsecAttribute, Buffer>) -> Nlmsghdr<u16, Genlmsghdr<KsecCommand, KsecAttribute>> {
    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic,
        Some(0),
        &[],
    ).unwrap();

    let family_id = sock.resolve_genl_family(FAMILY_NAME).unwrap();
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

fn virtaddr_to_nlattr(va: VirtAddr) -> GenlBuffer<KsecAttribute, Buffer> {
    let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::U64,
            va.as_u64(),
        ).unwrap(),
    );
    return attrs;
}

enum AddrOwner {
    Unspec = 0,
    Kernel = 1,
    Module = 2,
    Process = 3,
}

impl fmt::Display for AddrOwner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddrOwner::Unspec => write!(f, "Unknown"),
            AddrOwner::Kernel => write!(f, "Kernel"),
            AddrOwner::Module => write!(f, "Module"),
            AddrOwner::Process => write!(f, "Process"),
        }
    }
}

fn get_virtaddr_owner(va: VirtAddr) -> (AddrOwner, Option<String>) {
    let attrs = virtaddr_to_nlattr(va);
    let res = send_netlink_message(KsecCommand::IsKernelAddr, attrs);
    let attr_handle = res.get_payload().unwrap().get_attr_handle();
    let attr = attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::U64).unwrap();
    if !attr.iter().any(|&v| v > 0) {
        let attrs = virtaddr_to_nlattr(va);
        let res = send_netlink_message(KsecCommand::IsModuleAddr, attrs);
        let attr_handle = res.get_payload().unwrap().get_attr_handle();
        let attr = attr_handle.get_attr_payload_as_with_len::<String>(KsecAttribute::Str).unwrap();
        if attr.is_empty() {
            for p in procfs::process::all_processes().unwrap() {
                let mmaps: Vec<MemoryMap> = p.as_ref().unwrap().maps().unwrap();
                for mmap in mmaps.iter() {
                    if va.as_u64() >= mmap.address.0 && va.as_u64() <= mmap.address.1 {
                        return (AddrOwner::Process, Some(String::from(p.unwrap().exe().unwrap().as_path().to_str().unwrap())));
                    }
                }
            }
            (AddrOwner::Unspec, None)
        } else {
            (AddrOwner::Module, Some(attr))
        }
    } else {
        (AddrOwner::Kernel, None)
    }
}

fn main() {
    pretty_env_logger::init();
    let args = Args::parse();

    if args.get_idt_entries {
        let attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
        let res = send_netlink_message(KsecCommand::GetIDTEntries, attrs);
        let attr_handle = res.get_payload().unwrap().get_attr_handle();
        let attr = attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::Bin).unwrap();

        let entries = unsafe { std::slice::from_raw_parts(attr.as_ptr() as *const Entry<HandlerFunc>, 256) };

        for i in 0..256 {
            let owner = get_virtaddr_owner(entries[i].handler_addr());
            if entries[i].handler_addr() != VirtAddr::new(0) {
                if matches!(owner.0, AddrOwner::Module) || matches!(owner.0, AddrOwner::Process) {
                    warn!("{}: {:?} -> {}", i, entries[i], owner.0.to_string())
                } else {
                    info!("{}: {:?} -> {}", i, entries[i], owner.0.to_string())
                }
                // TODO: Print process or module name
            }
        }
    }

    return;
}

