//! Low-level communication with the minifilter.
use std::time::SystemTime;

use crate::shared_def::{
    FileId,
    IOMessage,
    DriveType::{NoRootDir},
    DriveType,
    RuntimeFeatures,
};

use ebpf_monitor_common::FileAccess;
use ebpf_monitor_common::Access::{Read, Write, Unlink, Rmdir, Mkdir, Symlink, Create, Rename};

pub type Buf = [u8; 32];

impl DriveType {
    // pub fn from_filepath(filepath: String) -> DriveType {
    //     let mut drive_type = 1u32;
    //     if !filepath.is_empty() {
    //         let drive_path = &filepath[..(filepath.find('\\').unwrap_or(0) + 1)];
    //         unsafe {
    //             drive_type = GetDriveTypeA(PCSTR::from_raw(drive_path.as_ptr()));
    //         }
    //     }
    //     match drive_type {
    //         0 => Unknown,
    //         1 => NoRootDir,
    //         2 => Removable,
    //         3 => Fixed,
    //         4 => Remote,
    //         5 => CDRom,
    //         6 => RamDisk,
    //         _ => NoRootDir,
    //     }
    // }

    pub fn from_filepath(_filepath: String) -> DriveType {
        NoRootDir
    }
}

impl IOMessage {
    pub fn from(l_drivermsg: &LDriverMsg) -> IOMessage {
        IOMessage {
            extension: l_drivermsg.filepath.split(".").last().unwrap_or("").to_string(),
            file_id_id: FileId(l_drivermsg.ino),
            mem_sized_used: l_drivermsg.mem_sized_used,
            entropy: l_drivermsg.entropy,
            pid: l_drivermsg.pid,
            irp_op: l_drivermsg.irp_op,
            is_entropy_calc: l_drivermsg.is_entropy_calc,
            file_change: l_drivermsg.file_change,
            file_location_info: l_drivermsg.file_location_info,
            filepathstr: l_drivermsg.filepath.clone(),
            gid: l_drivermsg.gid,
            runtime_features: RuntimeFeatures {
                exepath: l_drivermsg.exepath.clone().into(),
                exe_still_exists: true,
            },
            file_size: l_drivermsg.fsize,
            time: SystemTime::now(),
        }
    }
}

/// The C object returned by the minifilter, available through [ReplyIrp].
/// It is low level and use C pointers logic which is
/// not always compatible with RUST (in particular the lifetime of *next). That's why we convert
/// it asap to a plain Rust [IOMessage] object.
/// ```next``` is null (0x0) when there is no [IOMessage] remaining
#[derive(Debug, Clone)]
#[repr(C)]
pub struct LDriverMsg {
    pub ns: u64,
    pub entropy: f64,
    pub is_entropy_calc: u8,
    pub ino: u64,
    pub pid: u32,
    pub fsize: i64,
    pub irp_op: u8,
    pub file_change: u8,
    pub file_location_info: u8,
    pub mem_sized_used: u64,
    pub comm: [i8; 16],
    pub gid: u64,
    pub exepath: String,
    pub filepath: String,
}

impl LDriverMsg {
    pub fn new() -> LDriverMsg {
        LDriverMsg {
            ns: 0,
            entropy: 0.0,
            is_entropy_calc: 0,
            ino: 0,
            pid: 0,
            fsize: 0,
            irp_op: 0,
            file_change: 0,
            file_location_info: 0,
            mem_sized_used: 0,
            comm: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            gid: 0,
            exepath: String::from(""),
            filepath: String::from(""),
        }
    }

    pub fn set_filepath(&mut self, filepath: String) {
        self.filepath = filepath;
    }

    pub fn add_fileaccess(&mut self, fileaccess: &FileAccess) {
        self.ns = fileaccess.ns;
        self.entropy = fileaccess.entropy;
        self.ino = fileaccess.ino;
        self.fsize = fileaccess.fsize;
        self.comm = fileaccess.comm;
        self.file_location_info = 1;
        match fileaccess.access {
            Read(mem) => {
                self.irp_op = 1;
                self.file_change = 0;
                self.mem_sized_used = mem.try_into().unwrap();
            },
            Write(mem) => {
                self.irp_op = 2;
                self.file_change = 2;
                self.mem_sized_used = mem.try_into().unwrap();
            },
            Unlink(mem) => {
                self.irp_op = 0;
                self.file_change = 6;
                self.mem_sized_used = mem.try_into().unwrap();
            },
            Rmdir(mem) => {
                self.irp_op = 0;
                self.file_change = 6;
                self.mem_sized_used = mem.try_into().unwrap();
            },
            Mkdir(mem) => {
                self.irp_op = 4;
                self.file_change = 3;
                self.mem_sized_used = mem.try_into().unwrap();
            },
            Symlink(mem) => {
                self.irp_op = 4;
                self.file_change = 3;
                self.mem_sized_used = mem.try_into().unwrap();
            },
            Create(mem) => {
                self.irp_op = 4;
                self.file_change = 3;
                self.mem_sized_used = mem.try_into().unwrap();
            },
            Rename(mem) => {
                self.irp_op = 3;
                self.file_change = 4;
                self.mem_sized_used = mem.try_into().unwrap();
            },
        }
    }

    pub fn set_pid(&mut self, pid: u32) {
        self.pid = pid;
    }

    pub fn set_gid(&mut self, gid: u64) {
        self.gid = gid;
    }

    pub fn set_exepath(&mut self, exepath: String) {
        self.exepath = exepath;
    }

}
