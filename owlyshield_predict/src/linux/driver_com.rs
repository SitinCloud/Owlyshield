//! Low-level communication with the minifilter.

use std::os::raw::*;

use self::DriveType::{CDRom, Fixed, NoRootDir, RamDisk, Remote, Removable, Unknown};
use sysinfo::{get_current_pid, Pid};
use wchar::wchar_t;

use probes::openmonitor::FileAccess;
use probes::openmonitor::FilePath;

use probes::openmonitor::Access::{Read, Write, Unlink, Rmdir, Mkdir, Symlink, Create, Rename};

use self::IrpMajorOp::{IrpCreate, IrpNone, IrpRead, IrpSetInfo, IrpWrite};

pub type Buf = [u8; 32];

/// Messages types to send directives to the minifilter, by using te [DriverComMessage] struct.
enum DriverComMessageType {
    /// Not used yet. The minifilter has the ability to monitor a specific part of the fs.
    _MessageAddScanDirectory,
    /// Not used yet. The minifilter has the ability to monitor a specific part of the fs.
    _MessageRemScanDirectory,
    /// Ask for a [ReplyIrp], if any available.
    MessageGetOps,
    /// Set this app pid to the minifilter (related IRPs will be ignored);
    MessageSetPid,
    /// Instruct the minifilter to kill all pids in the family designated by a given gid.
    MessageKillGid,
}

/// See [shared_def::IOMessage] struct and [this doc](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes).
pub enum IrpMajorOp {
    /// Nothing happened
    IrpNone,
    /// On read, any time following the successful completion of a create request.
    IrpRead,
    /// On write, any time following the successful completion of a create request.
    IrpWrite,
    /// Set Metadata about a file or file handle. In that case, [shared_def::FileChangeInfo] indicates
    /// the nature of the modification.
    IrpSetInfo,
    /// Open a handle to a file object or device object.
    IrpCreate,
    /// File object handle has been closed
    _IrpCleanUp, //not used (yet)
}

impl IrpMajorOp {
    pub fn from_byte(b: u8) -> IrpMajorOp {
        match b {
            0 => IrpNone,
            1 => IrpRead,
            2 => IrpWrite,
            3 => IrpSetInfo,
            4 => IrpCreate,
            5 => IrpCreate,
            _ => IrpNone,
        }
    }
}

/// See [shared_def::IOMessage] struct and [this doc](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea).
pub enum DriveType {
    /// The drive type cannot be determined.
    Unknown,
    /// The root path is invalid; for example, there is no volume mounted at the specified path.
    NoRootDir,
    /// The drive has removable media; for example, a floppy drive, thumb drive, or flash card reader.
    Removable,
    /// The drive has fixed media; for example, a hard disk drive or flash drive.
    Fixed,
    /// The drive is a remote (network) drive.
    Remote,
    /// The drive is a CD-ROM drive.
    CDRom,
    /// The drive is a RAM disk.
    RamDisk,
}

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

    pub fn from_filepath(filepath: String) -> DriveType {
        NoRootDir
    }
}

/// Contains all definitions shared between this usermode app and the minifilter in order
/// to communicate properly. Those are C-representation of structures sent or received from the minifilter.
pub mod shared_def {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::os::raw::{c_uchar, c_ulong, c_ulonglong, c_ushort};
    use std::path::PathBuf;
    use std::time::SystemTime;

    use probes::openmonitor::FileAccess;
    use probes::openmonitor::FilePath;
    use probes::openmonitor::Access::{Read, Write, Unlink, Rmdir, Mkdir, Symlink, Create, Rename};

    use serde::{Deserialize, Serialize};
    use wchar::wchar_t;

    use crate::driver_com::Buf;

    /// See [IOMessage] struct. Used with [crate::driver_com::IrpMajorOp::IrpSetInfo]
    #[derive(FromPrimitive)]
    pub enum FileChangeInfo {
        ChangeNotSet,
        OpenDirectory,
        ChangeWrite,
        ChangeNewFile,
        ChangeRenameFile,
        ChangeExtensionChanged,
        ChangeDeleteFile,
        /// Temp file: created and deleted on close
        ChangeDeleteNewFile,
        ChangeOverwriteFile,
    }

    /// See [IOMessage] struct.
    #[derive(FromPrimitive)]
    pub enum FileLocationInfo {
        NotProtected,
        Protected,
        MovedIn,
        MovedOut,
    }

    /// This class is the straight Rust translation of the Win32 API [UNICODE_STRING](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string),
    /// returned by the driver.
    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct UnicodeString {
        pub length: c_ushort,
        pub maximum_length: c_ushort,
        pub buffer: *const wchar_t,
    }

    const FILE_ID_LEN: usize = 32;

    #[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
    pub struct FileId(u64);

    /// Represents a driver message.
    ///
    /// - extension: The file extension
    /// - file_id_vsn: Hard Disk Volume Serial Number where the file is saved (from FILE_ID_INFO)
    /// - file_id_id:  File ID on the disk (FILE_ID_INFO)
    /// - mem_size_used: Number of bytes transferred (IO_STATUS_BLOCK.Information)
    /// - entropy: (Optional) File Entropy calculated by the driver
    /// - is_entropy_calc: is the entropy calculated?
    /// - pid: Pid responsible for this io activity
    /// - irp_op: Windows IRP Type catched by the minifilter:
    ///     * NONE (0)
    ///     * READ (1)
    ///     * WRITE (2)
    ///     * SETINFO (3)
    ///     * CREATE (4)
    ///     * CLEANUP (5)
    /// - file_change: type of i/o operation:
    ///     * FILE_CHANGE_NOT_SET (0)
    ///     * FILE_OPEN_DIRECTORY (1)
    ///     * FILE_CHANGE_WRITE (2)
    ///     * FILE_CHANGE_NEW_FILE (3)
    ///     * FILE_CHANGE_RENAME_FILE (4)
    ///     * FILE_CHANGE_EXTENSION_CHANGED (5)
    ///     * FILE_CHANGE_DELETE_FILE (6)
    ///     * FILE_CHANGE_DELETE_NEW_FILE (7)
    ///     * FILE_CHANGE_OVERWRITE_FILE (8)
    /// - file_location_info: the driver has the ability to monitor specific directories only (feature currently not used):
    ///     * FILE_NOT_PROTECTED (0): Monitored dirs do not contained this file
    ///     * FILE_PROTECTED (1)
    ///     * FILE_MOVED_IN (2)
    ///     * FILE_MOVED_OUT (3)
    /// - filepath: File path on the disk
    /// - gid: Group Identifier (maintained by the minifilter) of the operation
    /// - runtime_features: see class [RuntimeFeatures]
    /// - file_size: size of the file. Can be equal to -1 if the file path is not found.
    /// - time: time of execution of the i/o operation
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[repr(C)]
    pub struct IOMessage {
        pub extension: String,
        pub file_id_id: FileId,
        pub mem_sized_used: u64,
        pub entropy: f64,
        pub pid: u32,
        pub irp_op: u8,
        pub is_entropy_calc: u8,
        pub file_change: u8,
        pub file_location_info: u8,
        pub filepathstr: String,
        pub gid: u64,
        pub runtime_features: RuntimeFeatures,
        pub file_size: i64,
        pub time: SystemTime,
    }

    /// Stores runtime features that come from *owlyshield_predict* (and not the minifilter).
    ///
    /// - exepath: The path of the gid root process
    /// - exe_exists: Did the root exe file still existed (at the moment of this specific *DriverMessage* operation)?
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RuntimeFeatures {
        pub exepath: PathBuf,
        pub exe_still_exists: bool,
    }

    impl FileId {
        pub fn from(fileid: [u8; FILE_ID_LEN]) -> FileId {
            let mut hasher = DefaultHasher::new();
            fileid.hash(&mut hasher);
            let hash = hasher.finish();
            FileId(hash)
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
                runtime_features: RuntimeFeatures::new(),
                file_size: l_drivermsg.fsize,
                time: SystemTime::now(),
            }
        }
    }

    impl RuntimeFeatures {
        pub fn new() -> RuntimeFeatures {
            RuntimeFeatures {
                exepath: PathBuf::new(),
                exe_still_exists: true,
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
}
