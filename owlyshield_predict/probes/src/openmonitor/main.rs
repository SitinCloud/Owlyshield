#![no_std]
#![no_main]

use redbpf_probes::kprobe::prelude::*;
use redbpf_probes::bindings::{size_t, task_struct, pid, pid_t};
use probes::openmonitor::*;

program!(0xFFFFFFFE, "GPL");

const S_IFMT: u16 = 0o00170000;
const S_IFREG: u16 = 0o0100000;
const S_IFDIR: u16 = 0o0040000;
const S_IFLNK: u16 = 0o0120000;

//#[repr(u64)]
#[derive(PartialEq, Eq)]
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

#[inline(always)]
pub fn trace_entry(regs: Registers, access_type: AccessType, dentry: &dentry, inode: &inode, bytes: size_t) {
    let comm = bpf_get_current_comm();
    if comm != [111, 119, 108, 121, 115, 104, 105, 101, 108, 100, 95, 114, 97, 110, 115, 0] {

        let ns = bpf_ktime_get_ns();
        let pid_tgid: u64 = bpf_get_current_pid_tgid();

        let i_mode = inode.i_mode().unwrap();
        if (((i_mode) & S_IFMT) == S_IFDIR) || (((i_mode) & S_IFMT) == S_IFREG) || (((i_mode) & S_IFMT) == S_IFLNK) {
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

            dentry_to_path(regs, dentry, ns, 1, &fileaccess);
        }
    }
}

#[kprobe("vfs_read")]
pub fn trace_read_entry(regs: Registers) {
    let file: &file = unsafe { (regs.parm1() as *const file).as_ref().unwrap() };        
    let path = file.f_path().unwrap();
    let dentry = unsafe { (path.dentry().unwrap()).as_ref().unwrap() };
    let bytes = regs.parm3() as size_t;
    let inode = unsafe { (dentry.d_inode().unwrap()).as_ref().unwrap() };
    trace_entry(regs, AccessType::Read, &dentry, &inode, bytes);
}

#[kprobe("vfs_write")]
pub fn trace_write_entry(regs: Registers) {
    let file: &file = unsafe { (regs.parm1() as *const file).as_ref().unwrap() };        
    let path = file.f_path().unwrap();
    let dentry = unsafe { (path.dentry().unwrap()).as_ref().unwrap() };
    let bytes = regs.parm3() as size_t;
    let inode = unsafe { (dentry.d_inode().unwrap()).as_ref().unwrap() };
    trace_entry(regs, AccessType::Write, &dentry, &inode, bytes);
}

#[kprobe("vfs_unlink")]
#[cfg(not(feature = "kl5-12"))]
pub fn trace_unlink(regs: Registers) {
    let dentry = unsafe { (regs.parm3() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (regs.parm2() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Unlink, &dentry, &inode, 0);
}
#[cfg(feature = "kl5-12")]
pub fn trace_unlink(regs: Registers) {
    let dentry = unsafe { (regs.parm2() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (regs.parm1() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Unlink, &dentry, &inode, 0);
}

#[kprobe("vfs_rmdir")]
#[cfg(not(feature = "kl5-12"))]
pub fn trace_rmdir(regs: Registers) {
    let dentry = unsafe { (regs.parm3() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (dentry.d_inode().unwrap()).as_ref().unwrap() };
    trace_entry(regs, AccessType::Rmdir, &dentry, &inode, 0);
}
#[cfg(feature = "kl5-12")]
pub fn trace_rmdir(regs: Registers) {
    let dentry = unsafe { (regs.parm2() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (dentry.d_inode().unwrap()).as_ref().unwrap() };
    trace_entry(regs, AccessType::Rmdir, &dentry, &inode, 0);
}

#[kprobe("vfs_symlink")]
#[cfg(not(feature = "kl5-12"))]
pub fn trace_symlink(regs: Registers) {
    let dentry = unsafe { (regs.parm3() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (regs.parm2() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Symlink, &dentry, &inode, 0);
}
#[cfg(feature = "kl5-12")]
pub fn trace_symlink(regs: Registers) {
    let dentry = unsafe { (regs.parm2() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (regs.parm1() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Symlink, &dentry, &inode, 0);
}

#[kprobe("vfs_mkdir")]
#[cfg(not(feature = "kl5-12"))]
pub fn trace_mkdir(regs: Registers) {
    let dentry = unsafe { (regs.parm3() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (regs.parm2() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Mkdir, &dentry, &inode, 0);
}
#[cfg(feature = "kl5-12")]
pub fn trace_mkdir(regs: Registers) {
    let dentry = unsafe { (regs.parm2() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (regs.parm1() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Mkdir, &dentry, &inode, 0);
}

#[kprobe("vfs_create")]
#[cfg(not(feature = "kl5-12"))]
pub fn trace_create(regs: Registers) {
    let dentry = unsafe { (regs.parm3() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (regs.parm2() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Create, &dentry, &inode, 0);
}
#[cfg(feature = "kl5-12")]
pub fn trace_create(regs: Registers) {
    let dentry = unsafe { (regs.parm2() as *mut dentry).as_ref().unwrap() };
    let inode = unsafe { (regs.parm1() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Create, &dentry, &inode, 0);
}

#[repr(C)]
#[cfg(not(feature = "kl5-12"))]
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

#[cfg(not(feature = "kl5-12"))]
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

    pub fn old_inode(&self) -> Option<*mut inode> {
        let v = unsafe { bpf_probe_read(&self.old_dir) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}

#[kprobe("vfs_rename")]
#[cfg(not(feature = "kl5-12"))]
pub fn trace_rename(regs: Registers) {
    let rename = unsafe { (regs.parm1() as *mut renamedata).as_ref().unwrap() };
    let old_dentry : &dentry = unsafe { (rename.old_dentry().unwrap() as *mut dentry).as_ref().unwrap() };
    let old_inode = unsafe { (rename.old_inode().unwrap() as *mut inode).as_ref().unwrap() };
    trace_entry(regs, AccessType::Rename, &old_dentry, &old_inode, 0);
}
#[cfg(feature = "kl5-12")]
pub fn trace_rename(regs: Registers) {
    let old_inode = unsafe { (regs.parm2() as *mut inode).as_ref().unwrap() };
    let old_dentry = unsafe { (regs.parm1() as *mut dentry).as_ref().unwrap() };
    trace_entry(regs, AccessType::Rename, &old_dentry, &old_inode, 0);
}

#[map]
static mut filepaths_map: HashMap<u64, [u8; 1024]> = HashMap::with_max_entries(64);

#[map]
static mut fileaccesses: PerfMap<[u8; 1024]> = PerfMap::with_max_entries(1024);

#[inline]
pub fn dentry_to_path(regs: Registers, dentry: &dentry, ns: u64, order: u8, fileaccess: &FileAccess) {
    let mut i = 0usize;
    let mut de = dentry;


    let pid_tgid: u64 = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    unsafe {
        if filepaths_map.get(&pid_tgid).is_none() {
            filepaths_map.set(&pid_tgid, &[0u8; 1024]);
        } 

        let u8_array = fileaccess.to_u8_array();

        let mut buf = filepaths_map.get_mut(&pid_tgid).unwrap();

        let mut offset = 0i64;

        let ret = unsafe {
            bpf_probe_read_kernel(
                buf.as_mut_ptr().offset(offset as isize) as *mut _,
                //u8_array.len() as usize,
                //(u8_array.len() as usize).try_into().unwrap(),
                FILE_ACCESS_SIZE as u32,
                u8_array.as_ptr() as *mut _,
                )
        } as i64;

                //offset += ret;
                //offset += u8_array.len() as i64;
                offset += FILE_ACCESS_SIZE as i64;

                // Add the slash before each directory entry except the first
                if offset != 0 {
                    let tmp = offset-1;
                    buf[tmp as usize] = b'/';
                }

                loop {
                    let i_name = de.d_name().unwrap().name().unwrap();

                    if offset < 0 {
                        break;
                    }

                    let name_len = unsafe {
                        bpf_probe_read_str(
                            buf.as_mut_ptr().offset(offset as isize) as *mut _,
                            //buf.as_mut_ptr().offset((i*2) as isize) as *mut _,
                            //buf.as_mut_ptr().offset(-1 as isize) as *mut _,
                            32u32,
                            i_name as *const _,
                            )
                    } as i64;

                    // Add the slash before each directory entry except the first
                    if offset != 0 {
                        let tmp = offset-1;
                        buf[tmp as usize] = b'/';
                    }

                    offset += name_len;

                    i += 1;
                    let parent = de.d_parent();
                    if parent.is_none() || i == PATH_LIST_LEN {
                        break;
                    } else {
                        de = unsafe { parent.unwrap().as_mut().unwrap() };
                    }
                }

                unsafe { 
                    fileaccesses.insert(regs.ctx, &buf);
                    filepaths_map.delete(&ns);
                }
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

