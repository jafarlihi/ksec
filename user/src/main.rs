use capstone::InsnGroupType::CS_GRP_BRANCH_RELATIVE;
use log::{info, warn};
extern crate pretty_env_logger;
extern crate log;
extern crate procfs;
extern crate proc_modules;
extern crate capstone;

use neli::neli_enum;
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
use x86_64::VirtAddr;
use x86_64::structures::idt::{Entry, HandlerFunc};
use std::process;
use clap::Parser;
use std::{fmt, str};
use proc_modules::ModuleIter;
use capstone::prelude::*;
use std::mem::transmute;

const FAMILY_NAME: &str = "ksec";

#[neli_enum(serialized_type = "u8")]
enum KsecCommand {
    Unspec = 0,
    IsKernelAddr = 1,
    IsModuleAddr = 2,
    GetIDTEntries = 3,
    GetSyscalls = 4,
    GetModules = 5,
    GetSymbolAddr = 6,
    Read = 7,
    AllocExecMem = 8,
    Hook = 9,
    GetShimAddr = 10,
    Kprobe = 11,
}
impl neli::consts::genl::Cmd for KsecCommand {}

#[neli_enum(serialized_type = "u16")]
enum KsecAttribute {
    Unspec = 0,
    Str = 1,
    U64_0 = 2,
    U64_1 = 3,
    U64_2 = 4,
    Bin_0 = 5,
    Bin_1 = 6,
    Bin_2 = 7,
    Bin_3 = 8,
}
impl neli::consts::genl::NlAttrType for KsecAttribute {}

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
    /// List interrupt descriptor table entries
    #[clap(short = 'i', long, value_parser)]
    get_idt_entries: bool,
    /// List syscalls
    #[clap(short = 's', long, value_parser)]
    get_syscalls: bool,
    /// List Linux Kernel Modules
    #[clap(short = 'm', long, value_parser)]
    get_modules: bool,
    /// Get address of a kernel symbol
    #[clap(short = 'a', long, value_parser, value_names=&["symbol"])]
    get_symbol_addr: Option<String>,
    /// Read content from an address
    #[clap(short = 'r', long, value_parser, number_of_values = 2, value_names=&["addr [hex with 0x]", "len"])]
    read: Option<Vec<String>>,
    /// Disassemble `read` command output
    #[clap(short = 'd', long, value_parser)]
    disassemble: bool,
    /// Hook an arbitrary kernel function with a custom method [experimental feature]
    #[clap(short = 'h', long, value_parser, value_names=&["hooked_function"])]
    hook: Option<String>,
    /// Hook an arbitrary kernel function with a kprobe [experimental feature]
    #[clap(short = 'k', long, value_parser, value_names=&["hooked_function"])]
    kprobe: Option<String>,
}

fn virtaddr_to_nlattr(va: VirtAddr) -> GenlBuffer<KsecAttribute, Buffer> {
    let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::U64_0,
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
    let attr = attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::U64_0).unwrap();
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

fn get_symbol_addr(symbol: String) -> [u8; 8] {
    let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::Str,
            symbol
        ).unwrap(),
    );
    let res = send_netlink_message(KsecCommand::GetSymbolAddr, attrs);
    let attr_handle = res.get_payload().unwrap().get_attr_handle();
    let attr = attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::U64_0).unwrap();

    let mut attr8 = [0u8; 8];
    attr8.clone_from_slice(&attr[0..8]);
    attr8
}

fn read_addr(addr: String, len: u64) -> Vec<u8> {
    let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::Str,
            addr,
        ).unwrap(),
    );
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::U64_0,
            len,
        ).unwrap(),
    );
    let res = send_netlink_message(KsecCommand::Read, attrs);
    let attr_handle = res.get_payload().unwrap().get_attr_handle();
    attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::Bin_0).unwrap().to_vec()
}

fn alloc_exec_mem() -> Vec<u8> {
    let attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    let res = send_netlink_message(KsecCommand::AllocExecMem, attrs);
    let attr_handle = res.get_payload().unwrap().get_attr_handle();
    attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::U64_0).unwrap().to_vec()
}

fn get_shim_addr(hooked: String) -> Vec<u8> {
    let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::Str,
            hooked,
        ).unwrap(),
    );
    let res = send_netlink_message(KsecCommand::GetShimAddr, attrs);
    let attr_handle = res.get_payload().unwrap().get_attr_handle();
    attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::U64_0).unwrap().to_vec()
}

const NR_SYSCALLS: usize = 449;

fn main() {
    pretty_env_logger::init();
    let args = Args::parse();

    if args.get_idt_entries {
        let attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
        let res = send_netlink_message(KsecCommand::GetIDTEntries, attrs);
        let attr_handle = res.get_payload().unwrap().get_attr_handle();
        let attr = attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::Bin_0).unwrap();

        let entries = unsafe { std::slice::from_raw_parts(attr.as_ptr() as *const Entry<HandlerFunc>, 256) };

        for i in 0..256 {
            let owner = get_virtaddr_owner(entries[i].handler_addr());
            if entries[i].handler_addr() != VirtAddr::new(0) {
                if matches!(owner.0, AddrOwner::Module) || matches!(owner.0, AddrOwner::Process) {
                    warn!("{}: {:?} -> {} (name: {})", i, entries[i], owner.0.to_string(), owner.1.unwrap());
                } else if matches!(owner.0, AddrOwner::Unspec) {
                    warn!("{}: {:?} -> {}", i, entries[i], owner.0.to_string())
                } else {
                    info!("{}: {:?} -> {}", i, entries[i], owner.0.to_string())
                }
            }
        }
    }

    if args.get_syscalls {
        let attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
        let res = send_netlink_message(KsecCommand::GetSyscalls, attrs);
        let attr_handle = res.get_payload().unwrap().get_attr_handle();
        let attr = attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::Bin_0).unwrap();

        let entries = unsafe { std::slice::from_raw_parts(attr.as_ptr() as *const u64, NR_SYSCALLS) };

        for i in 0..NR_SYSCALLS {
            let owner = get_virtaddr_owner(VirtAddr::new(entries[i]));
            if entries[i] != 0 {
                if matches!(owner.0, AddrOwner::Module) || matches!(owner.0, AddrOwner::Process) {
                    warn!("{}: {:X} -> {} (name: {})", i, entries[i], owner.0.to_string(), owner.1.unwrap());
                } else if matches!(owner.0, AddrOwner::Unspec) {
                    warn!("{}: {:X} -> {}", i, entries[i], owner.0.to_string())
                } else {
                    info!("{}: {:X} -> {}", i, entries[i], owner.0.to_string())
                }
            }
        }
    }

    if args.get_modules {
        let attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
        let res = send_netlink_message(KsecCommand::GetModules, attrs);
        let attr_handle = res.get_payload().unwrap().get_attr_handle();
        let attr = attr_handle.get_attr_payload_as_with_len::<String>(KsecAttribute::Bin_0).unwrap();

        let modules = attr.split(' ');

        'outer: for module in modules {
            for proc_module in ModuleIter::new().unwrap() {
                if module.eq(&proc_module.unwrap().module) {
                    info!("{}", module);
                    continue 'outer;
                }
            }
            warn!("{} -> Hidden", module);
        }
    }

    if !args.get_symbol_addr.is_none() {
        let addr = get_symbol_addr(args.get_symbol_addr.unwrap());
        info!("{:X}", u64::from_le_bytes(addr));
    }

    if !args.read.is_none() {
        let read_args = args.read.unwrap();
        let addr = read_args[0].clone();
        let len = read_args[1].parse::<u64>().unwrap();

        let data = read_addr(addr, len);

        if args.disassemble {
            let cs = Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Att)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object");
            let base_addr = u64::from_str_radix(read_args[0].clone().trim_start_matches("0x"), 16).unwrap();
            let insns = cs.disasm_all(&data as &[u8], base_addr).expect("Failed to disassemble");
            for i in insns.as_ref() {
                println!("{} {:x?}", i, i.bytes());
            }
        } else {
            println!("{:?}", data);
        }
    }

    if !args.hook.is_none() {
        let hooked_function = args.hook.unwrap();
        let hooked_addr = get_symbol_addr(hooked_function.clone());
        let hooked_addr_hex = format!("0x{:X}", u64::from_le_bytes(hooked_addr));
        let hooked_addr_data = read_addr(hooked_addr_hex, 50);

        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");
        let insns = cs.disasm_all(&hooked_addr_data as &[u8], u64::from_le_bytes(hooked_addr)).expect("Failed to disassemble");

        let mut bytes_past: usize = 0;
        let mut insns_past: usize = 0;

        for i in insns.as_ref() {
            if bytes_past > 12 {
                break;
            }
            bytes_past += i.bytes().len();
            insns_past += 1;
        }

        for i in 0..insns_past {
            let detail = cs.insn_detail(&insns.as_ref()[i]).unwrap();
            for g in detail.groups() {
                if g.0 == CS_GRP_BRANCH_RELATIVE as u8 {
                    panic!("Relative branching instruction found within first 13 bytes");
                }
            }
        }

        let replaced_insns = hooked_addr_data[0..bytes_past].to_vec();

        let exec_addr = alloc_exec_mem();
        let shim_addr = get_shim_addr(hooked_function.clone());

        let mut exec_addr8 = [0u8; 8];
        exec_addr8.clone_from_slice(&exec_addr[0..8]);

        let movabs: [u8; 2] = [0x49, 0xBA]; // movabs r10
        let movabs_with_addr = [&movabs, &exec_addr8 as &[u8]].concat();
        let jmp: [u8; 3] = [0x41, 0xFF, 0xE2]; // jmp r10
        let mut hook_insns = [&movabs_with_addr as &[u8], &jmp].concat();
        let mut bytes: usize = 13;
        let nop: [u8; 1] = [0x90]; // nop
        while bytes < bytes_past {
            hook_insns = [&hook_insns as &[u8], &nop].concat();
            bytes += 1;
        }

        let jmp_back_addr: [u8; 8] = unsafe { transmute((u64::from_le_bytes(hooked_addr) + bytes_past as u64).to_le()) };
        let mut jmp_back_insns = [&movabs, &jmp_back_addr as &[u8]].concat();
        jmp_back_insns = [&jmp_back_insns as &[u8], &jmp].concat();

        let mut shim_insns = [&movabs, &shim_addr as &[u8]].concat();
        let call: [u8; 3] = [0x41, 0xFF, 0xD2]; // call r10
        shim_insns = [&shim_insns as &[u8], &call].concat();

        let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
        attrs.push(
            Nlattr::new(
                false,
                false,
                KsecAttribute::U64_0,
                u64::from_le_bytes(exec_addr8),
            ).unwrap(),
        );
        attrs.push(
            Nlattr::new(
                false,
                false,
                KsecAttribute::U64_1,
                u64::from_le_bytes(hooked_addr),
            ).unwrap(),
        );
        attrs.push(
            Nlattr::new(
                false,
                false,
                KsecAttribute::U64_2,
                bytes_past as u64,
            ).unwrap(),
        );
        attrs.push(
            Nlattr::new(
                false,
                false,
                KsecAttribute::Bin_0,
                hook_insns,
            ).unwrap(),
        );
        attrs.push(
            Nlattr::new(
                false,
                false,
                KsecAttribute::Bin_1,
                replaced_insns,
            ).unwrap(),
        );
        attrs.push(
            Nlattr::new(
                false,
                false,
                KsecAttribute::Bin_2,
                jmp_back_insns,
            ).unwrap(),
        );
        attrs.push(
            Nlattr::new(
                false,
                false,
                KsecAttribute::Bin_3,
                shim_insns,
            ).unwrap(),
        );
        let res = send_netlink_message(KsecCommand::Hook, attrs);
    }

    if !args.kprobe.is_none() {
        let hooked = args.kprobe.unwrap();

        let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
        attrs.push(
            Nlattr::new(
                false,
                false,
                KsecAttribute::Str,
                hooked,
            ).unwrap(),
        );
        let res = send_netlink_message(KsecCommand::Kprobe, attrs);
        let attr_handle = res.get_payload().unwrap().get_attr_handle();
        let ret = attr_handle.get_attr_payload_as_with_len::<&[u8]>(KsecAttribute::U64_0).unwrap().to_vec();
        info!("{:?}", ret);
    }

    return;
}

