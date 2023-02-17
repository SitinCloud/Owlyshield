#![no_std]
#![no_main]

use redbpf_probes::kprobe::prelude::*;
use redbpf_probes::bindings::{size_t, task_struct, pid, pid_t};
use probes::openmonitor::*;
//use libc::S_IFREG;


program!(0xFFFFFFFE, "GPL");

const S_IFMT: u16 = 0o00170000;
const S_IFREG: u16 = 0o0100000;

#[map]
static mut filepaths: PerfMap<FilePath> = PerfMap::with_max_entries(1024);

#[map]
static mut fileaccesses: PerfMap<FileAccess> = PerfMap::with_max_entries(1024);

//#[map]
//static mut entropies: PerfMap<f64> = PerfMap::with_max_entries(1024);



//#[repr(u64)]
pub enum AccessType {
    Read,
    Write,
    Unlink,
    Rmdir,
    Mkdir,
    Symlink,
    Create,
    Rename,
}


//#[kprobe("vfs_read")]
pub fn trace_read_entry2(regs: Registers) {
    //let tid = bpf_get_current_pid_tgid();
    unsafe {
        let f = regs.parm1() as *const file;
        //files.set(&tid, &f);
        //do_track_file_access(f, regs, AccessType::Read);
        //        rd.insert(regs.ctx, &5u8);
    }
}


//TODO : vérifier premier caractère == "/" avant de tout virer, au risque d'ignorer
//des fichiers dont le nom est d'une lettre à la racine de point de montage
#[inline]
fn only_zeros_unsafe(arr: &[u8]) -> bool {
    let len = arr.len();
    let ptr = arr.as_ptr();
    unsafe {
        for i in 1..len {
            if *ptr.add(i) != 0 {
                return false;
            }
        }
    }
    true
}


/*
#[kretprobe("vfs_read")]
pub fn trace_read_entry_ret(regs: Registers) {
let buf = regs.parm2() as *const u8;
let bytes = regs.parm3() as usize;
//   let entropy = entropy(buf, bytes);
}
*/

#[kprobe("vfs_read")]
pub fn trace_read_entry(regs: Registers) {
    unsafe {
        let f = regs.parm1() as *const file;
        let file = &*f;
        let bytes = regs.parm3() as size_t;
        let path = file.f_path().unwrap();
        let mut dentry = path.dentry();
        trace_entry(regs, AccessType::Read, &mut dentry, bytes);
    }
}

#[kprobe("vfs_write")]
pub fn trace_write_entry(regs: Registers) {
    unsafe {
        let f = regs.parm1() as *const file;
        let file = &*f;
        let bytes = regs.parm3() as size_t;
        let path = file.f_path().unwrap();
        let mut dentry = path.dentry();
        trace_entry(regs, AccessType::Write, &mut dentry, bytes);
    }
}

#[kprobe("vfs_unlink")]
pub fn trace_unlink(regs: Registers) {
    unsafe {
        let mut dentry = Some(regs.parm3() as *mut dentry);
        trace_entry(regs, AccessType::Unlink, &mut dentry, 0);
    }
}

#[kprobe("vfs_rmdir")]
pub fn trace_rmdir(regs: Registers) {
    unsafe {
        let mut dentry = Some(regs.parm3() as *mut dentry);
        trace_entry(regs, AccessType::Rmdir, &mut dentry, 0);
    }
}

#[kprobe("vfs_symlink")]
pub fn trace_symlink(regs: Registers) {
    unsafe {
        let mut dentry = Some(regs.parm3() as *mut dentry);
        trace_entry(regs, AccessType::Symlink, &mut dentry, 0);
    }
}

#[kprobe("vfs_mkdir")]
pub fn trace_mkdir(regs: Registers) {
    unsafe {
        let mut dentry = Some(regs.parm3() as *mut dentry);
        trace_entry(regs, AccessType::Mkdir, &mut dentry, 0);
    }
}

#[kprobe("vfs_create")]
pub fn trace_create(regs: Registers) {
    unsafe {
        let mut dentry = Some(regs.parm3() as *mut dentry);
        trace_entry(regs, AccessType::Create, &mut dentry, 0);
    }
}


#[repr(C)]
pub struct renamedata {
    pub old_mnt_userns: *mut user_namespace,
    pub old_dir: *mut inode,
    pub old_dentry: *mut dentry,
    pub new_mnt_users: *mut user_namespace,
    pub new_dir: *mut inode,
    pub new_dentry: *mut dentry,
    pub delegated_inode: *mut c_void,
    pub flags: uint32_t,
}

impl renamedata {
    pub fn old_dentry(&self) -> Option<*mut dentry> {
        let v = unsafe { bpf_probe_read(&self.old_dentry) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }

    pub fn new_dentry(&self) -> Option<*mut dentry> {
        let v = unsafe { bpf_probe_read(&self.new_dentry) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}

#[kprobe("vfs_rename")]
pub fn trace_rename(regs: Registers) {
    unsafe {
        let ptr_rename = regs.parm1() as *mut renamedata;
        let rename = &*ptr_rename;
        let mut old_dentry = rename.old_dentry();
        let mut new_dentry = rename.new_dentry();
        trace_entry(regs, AccessType::Rename, &mut old_dentry, 0);// &mut new_dentry);
    }
}

#[inline(always)]
pub unsafe fn trace_entry(regs: Registers, access_type: AccessType, dentry: &mut Option<*mut dentry>, bytes: size_t) { //, dentry_new: &mut Option<*mut dentry>) {
    let comm = bpf_get_current_comm();
    /*
    if comm != [ //redbpf_test
        114,
        101,
        100,
        98,
        112,
        102,
        95,
        116,
        101,
        115,
        116,
        0,
        0,
        0,
        0,
        0,
    ] {*/

    if comm != [111, 119, 108, 121, 115, 104, 105, 101, 108, 100, 95, 114, 97, 110, 115, 0] { //owlyshield_rans

        let ns = bpf_ktime_get_ns();
        let pid_tgid: u64 = bpf_get_current_pid_tgid();

        let de = &*dentry.unwrap();
        let inode = &*de.d_inode().unwrap();
        let i_mode = inode.i_mode().unwrap();
        //let mnt = path.mnt().unwrap();


        if ((i_mode) & S_IFMT) == S_IFREG {
            let access = match access_type {
                AccessType::Write => Access::Write(bytes as usize),
                AccessType::Read => Access::Read(bytes as usize),
                AccessType::Unlink => Access::Unlink(0usize),
                AccessType::Rmdir => Access::Rmdir(0usize),
                AccessType::Symlink => Access::Symlink(0usize),
                AccessType::Mkdir => Access::Mkdir(0usize),
                AccessType::Create => Access::Create(0usize),
                AccessType::Rename => Access::Rename(0usize),
            };


            let fileaccess = FileAccess {
                ns,
                ino: inode.i_ino().unwrap(),
                fsize: inode.i_size().unwrap(),
                entropy: 0f64,
                pid: pid_tgid,
                access: access,
                comm: comm,
            };
            fileaccesses.insert(regs.ctx, &fileaccess);
            dentry_to_path(regs, dentry, ns, 1);
            /*
            if dentry_new.is_some() {
                dentry_to_path(regs, dentry_new, ns, 2);
            }*/
        }
    }
}

#[inline]
pub unsafe fn dentry_to_path(regs: Registers, dentry: &mut Option<*mut dentry>, ns: u64, order: u8) {
    let mut i = 0usize;
    loop {
        if dentry.is_none() || i == PATH_LIST_LEN {
            let filepath = FilePath {
                //order,
                ns,
                level: usize::MAX,
                buf: [0u8; 32],
            };
            filepaths.insert(regs.ctx, &filepath);
            break;
        }
        let de = &*dentry.unwrap();
        //let i_name = de.d_iname().unwrap();
        let i_name = de.d_name().unwrap().name().unwrap();
        let mut ppath = [0u8; 32];

        bpf_probe_read_str(
            ppath.as_mut_ptr() as *mut _,
            32u32,
            //i_name.as_ptr() as *const _,
            i_name as *const _,
            );


        if only_zeros_unsafe(&ppath) {
            let filepath = FilePath {
            //    order,
                ns,
                level: usize::MAX,
                buf: [0u8; 32],
            };
            filepaths.insert(regs.ctx, &filepath);
            break;
        }

        let filepath = FilePath {
           // order,
            ns,
            level: i,
            buf: ppath,
        };
        filepaths.insert(regs.ctx, &filepath);

        i = i + 1;
        *dentry = de.d_parent();
    }
}

fn entropy(ptr: *const u8, len: usize) -> f64 {
    let mut freqs = [0; 32];
    unsafe {
        for i in 0..len {
            let byte = *ptr.offset(i as isize);
            let idx = (byte >> 3) as usize;
            let shift = (byte & 0x07) as usize;
            freqs[idx] |= 1 << shift;
        }
    }
    let mut entropy = 0.0;
    let len = len as f64;
    for i in 0..256 {
        let byte = i as u8;
        let idx = (byte >> 3) as usize;
        let shift = (byte & 0x07) as usize;
        let count = (freqs[idx] >> shift) & 1;
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p ; // (p.log2());
        }
    }
    entropy
}
