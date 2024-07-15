#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use aya_ebpf::{
    bpf_printk, check_bounds_signed,
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes,
    },
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, RetProbeContext},
};

use aya_log_ebpf::info;

use bindings::{__kernel_size_t, dentry, file, inode, path, qstr, u_int32_t, user_namespace};

use ebpf_monitor_common::*;

const S_IFMT: u16 = 0o00170000;
const S_IFREG: u16 = 0o0100000;
const S_IFDIR: u16 = 0o0040000;
const S_IFLNK: u16 = 0o0120000;

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
pub fn trace_entry(
    ctx: ProbeContext,
    access_type: AccessType,
    dentry: *const dentry,
    inode: *const inode,
    bytes: __kernel_size_t,
) -> Result<i64, i64> {
    let comm: [i8; 16] = comm_to_i8_array(bpf_get_current_comm().unwrap_or([0u8; 16]));

    if comm
        != [
            111, 119, 108, 121, 115, 104, 105, 101, 108, 100, 95, 114, 97, 110, 115, 0,
        ]
    {
        let ns: u64 = unsafe { bpf_ktime_get_ns() };
        let pid_tgid: u64 = bpf_get_current_pid_tgid();
        let i_mode: u16 = unsafe { bpf_probe_read_kernel(&(*inode).i_mode).map_err(|e: i64| e)? };

        if (((i_mode) & S_IFMT) == S_IFDIR)
            || (((i_mode) & S_IFMT) == S_IFREG)
            || (((i_mode) & S_IFMT) == S_IFLNK)
        {
            let access: Access = match access_type {
                AccessType::Write => Access::Write(bytes as usize),
                AccessType::Read => Access::Read(bytes as usize),
                AccessType::Unlink => Access::Unlink(0usize),
                AccessType::Rmdir => Access::Rmdir(0usize),
                AccessType::Symlink => Access::Symlink(0usize),
                AccessType::Mkdir => Access::Mkdir(0usize),
                AccessType::Create => Access::Create(0usize),
                AccessType::Rename => Access::Rename(0usize),
            };
            let fileaccess: FileAccess = FileAccess {
                ns,
                ino: unsafe { bpf_probe_read_kernel(&(*inode).i_ino).map_err(|e: i64| e)? },
                fsize: unsafe { bpf_probe_read_kernel(&(*inode).i_size).map_err(|e: i64| e)? },
                entropy: 0f64, // must be implemented
                pid: pid_tgid,
                access: access,
                comm: comm,
            };

            return dentry_to_path(ctx, dentry, ns, 1, &fileaccess); // returns Result
        }
    }
    Ok(0i64)
}

// KPROBES
// vfs_read vfs_write vfs_unlink vfs_rmdir vfs_symlink vfs_mkdir vfs_create vfs_rename

/*
List of struct fields needed :
    dentry : d_name, d_parent
    inode : i_mode, i_ino, i_size
*/

// VFS_READ
#[kprobe]
pub fn vfs_read(ctx: ProbeContext) -> i64 {
    unsafe {
        bpf_printk!(b"coucou depuis bpf");
    }
    match try_vfs_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_read(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_read called");
    let file: *const file = ctx.arg::<*const file>(0).ok_or(1i64)?;
    let path: *const path = &unsafe { bpf_probe_read_kernel(&(*file).f_path).map_err(|e: i64| e)? };
    let dentry: *const dentry =
        unsafe { bpf_probe_read_kernel(&(*path).dentry).map_err(|e: i64| e)? };
    let bytes: u64 = ctx.arg::<__kernel_size_t>(2).ok_or(1i64)?;
    let inode: *const inode =
        unsafe { bpf_probe_read_kernel(&(*dentry).d_inode).map_err(|e: i64| e)? };
    trace_entry(ctx, AccessType::Read, dentry, inode, bytes)
}

// VFS_WRITE
#[kprobe]
pub fn vfs_write(ctx: ProbeContext) -> i64 {
    match try_vfs_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_write(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_write called");
    let file: *const file = ctx.arg::<*const file>(0).ok_or(1i64)?;
    let path: *const path = &unsafe { bpf_probe_read_kernel(&(*file).f_path).map_err(|e: i64| e)? };
    let dentry: *const dentry =
        unsafe { bpf_probe_read_kernel(&(*path).dentry).map_err(|e: i64| e)? };
    let bytes: u64 = ctx.arg::<__kernel_size_t>(2).ok_or(1i64)?;
    let inode: *const inode =
        unsafe { bpf_probe_read_kernel(&(*dentry).d_inode).map_err(|e: i64| e)? };
    trace_entry(ctx, AccessType::Read, dentry, inode, bytes)
}

// VFS_UNLINK
#[kprobe]
pub fn vfs_unlink(ctx: ProbeContext) -> i64 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(feature = "kl5-12"))]
fn try_vfs_unlink(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_unlink called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(2).ok_or(1i64)?;
    let inode: *const inode = ctx.arg::<*const inode>(1).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Unlink, dentry, inode, 0)
}

#[cfg(feature = "kl5-12")]
fn try_vfs_unlink(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_unlink called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(1).ok_or(1i64)?;
    let inode: *const inode = ctx.arg::<*const inode>(0).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Unlink, dentry, inode, 0)
}

// VFS_RMDIR
#[kprobe]
pub fn vfs_rmdir(ctx: ProbeContext) -> i64 {
    match try_vfs_rmdir(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(feature = "kl5-12"))]
fn try_vfs_rmdir(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_rmdir called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(2).ok_or(1i64)?;
    let inode: *const inode =
        unsafe { bpf_probe_read_kernel(&(*dentry).d_inode).map_err(|e: i64| e)? };
    trace_entry(ctx, AccessType::Rmdir, dentry, inode, 0)
}

#[cfg(feature = "kl5-12")]
fn try_vfs_rmdir(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_rmdir called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(1).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Rmdir, dentry, inode, 0)
}

// VFS_SYMLINK
#[kprobe]
pub fn vfs_symlink(ctx: ProbeContext) -> i64 {
    match try_vfs_symlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(feature = "kl5-12"))]
fn try_vfs_symlink(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_symlink called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(2).ok_or(1i64)?;
    let inode: *const inode = ctx.arg::<*const inode>(1).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Symlink, dentry, inode, 0)
}

#[cfg(feature = "kl5-12")]
fn try_vfs_symlink(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_symlink called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(1).ok_or(1i64)?;
    let inode: *const inode = ctx.arg::<*const inode>(0).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Symlink, dentry, inode, 0)
}

// VFS_MKDIR
#[kprobe]
pub fn vfs_mkdir(ctx: ProbeContext) -> i64 {
    match try_vfs_mkdir(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(feature = "kl5-12"))]
fn try_vfs_mkdir(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_mkdir called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(2).ok_or(1i64)?;
    let inode: *const inode = ctx.arg::<*const inode>(1).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Mkdir, dentry, inode, 0)
}

#[cfg(feature = "kl5-12")]
fn try_vfs_mkdir(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_mkdir called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(1).ok_or(1i64)?;
    let inode: *const inode = ctx.arg::<*const inode>(0).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Mkdir, dentry, inode, 0)
}

// // VFS_CREATE (Isn't triggered)
// #[kretprobe]
// pub fn vfs_create(ctx: RetProbeContext) -> i64 {
//     match try_vfs_create(ctx) {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

// #[cfg(not(feature = "kl5-12"))]
// fn try_vfs_create(ctx: RetProbeContext) -> Result<i64, i64> {
//     //info!(&ctx, "function vfs_create called");
//     let dentry : *const dentry = ctx.arg::<*const dentry>(2).ok_or(1i64)?;
//     let inode : *const inode = ctx.arg::<*const inode>(1).ok_or(1i64)?;
//     trace_entry(ctx, AccessType::Create, dentry, inode, 0)
// }

#[cfg(feature = "kl5-12")]
fn try_vfs_create(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_create called");
    let dentry: *const dentry = ctx.arg::<*const dentry>(1).ok_or(1i64)?;
    let inode: *const inode = ctx.arg::<*const inode>(0).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Create, dentry, inode, 0)
}

// VFS_RENAME
#[kprobe]
pub fn vfs_rename(ctx: ProbeContext) -> i64 {
    match try_vfs_rename(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
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
    pub flags: u_int32_t,
}

#[cfg(not(feature = "kl5-12"))]
fn try_vfs_rename(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_rename called");
    let renamedata: *const renamedata = ctx.arg::<*const renamedata>(0).ok_or(1i64)?;
    let old_dentry: *const dentry =
        unsafe { bpf_probe_read_kernel(&(*renamedata).old_dentry).map_err(|e: i64| e)? };
    let old_inode: *const inode =
        unsafe { bpf_probe_read_kernel(&(*renamedata).old_dir).map_err(|e: i64| e)? };
    trace_entry(ctx, AccessType::Rename, old_dentry, old_inode, 0)
}

#[cfg(feature = "kl5-12")]
pub fn try_vfs_rename(ctx: ProbeContext) -> Result<i64, i64> {
    //info!(&ctx, "function vfs_rename called");
    let old_dentry: *const dentry = ctx.arg::<*const dentry>(0).ok_or(1i64)?;
    let old_inode: *const inode = ctx.arg::<*const inode>(1).ok_or(1i64)?;
    trace_entry(ctx, AccessType::Rename, old_dentry, old_inode, 0)
}

// MAPS

#[map]
pub static mut FILEPATHS_MAP: HashMap<u64, [u8; 1024]> = HashMap::with_max_entries(64, 0);

#[map]
pub static mut FILEACCESSES: PerfEventArray<[u8; 1024]> = PerfEventArray::with_max_entries(1024, 0);

#[inline]
pub fn dentry_to_path(
    ctx: ProbeContext,
    dentry: *const dentry,
    ns: u64,
    _order: u8,
    fileaccess: &FileAccess,
) -> Result<i64, i64> {
    // order needs to be implemented

    let mut i: usize = 0usize;
    let mut de: *const dentry = dentry;

    let pid_tgid: u64 = fileaccess.pid;

    unsafe {
        if FILEPATHS_MAP.get(&pid_tgid).is_none() {
            let _ = FILEPATHS_MAP.insert(&pid_tgid, &[0u8; 1024], 0);
        }

        let u8_array: [u8; FILE_ACCESS_SIZE] = fileaccess.to_u8_array();

        let buf: &mut [u8; 1024] = {
            let ptr: *mut [u8; 1024] = FILEPATHS_MAP.get_ptr_mut(&pid_tgid).ok_or(0)?;
            &mut *ptr
        };

        let mut offset: i64 = 0i64;
        let ret: Result<(), i64> = {
            bpf_probe_read_kernel_buf(
                u8_array.as_ptr(),
                &mut buf[offset as usize..offset as usize + FILE_ACCESS_SIZE],
            )
        };

        // Handle potential errors
        if let Err(err) = ret {
            return Err(err);
        }

        offset += FILE_ACCESS_SIZE as i64;

        loop {
            let d_name: qstr = bpf_probe_read_kernel(&(*de).d_name).map_err(|e: i64| e)?;
            let i_name: *const u8 = d_name.name;

            if offset < 0 {
                break;
            }

            let name_len = {
                bpf_probe_read_kernel_str_bytes(
                    i_name,
                    &mut buf[offset as usize..offset as usize + 32usize],
                )
                .unwrap_or(&[0u8; 16])
                .len()
            };

            // Add the slash before each directory entry except the first
            if offset != 0 {
                let tmp: usize = offset as usize - 1;
                // To not trigger the verifier :
                if check_bounds_signed(tmp as i64, 0, 1024) {
                    buf[tmp] = b'/';
                    offset += 1;
                }
            }

            offset += name_len as i64;

            i += 1;

            let parent: *const dentry =
                bpf_probe_read_kernel(&(*de).d_parent).map_err(|e: i64| e)?;
            if de == parent {
                break;
            }
            if parent.is_null() || i == PATH_LIST_LEN {
                break;
            } else {
                de = parent;
            }
        }

        FILEACCESSES.output(&ctx, buf, 0);
        FILEPATHS_MAP.remove(&ns)?;
    }
    Ok(0i64)
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
            entropy -= p; // (p.log2());
        }
    }
    entropy
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
