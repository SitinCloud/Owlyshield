/// Contains all definitions shared between this usermode app and the minifilter in order
/// to communicate properly. Those are C-representation of structures sent or received from the minifilter.
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
const FILE_ID_LEN: usize = 16;
#[cfg(target_os = "linux")]
const FILE_ID_LEN: usize = 32;

/// See [`IOMessage`] struct. Used with [`crate::shared_def::IrpMajorOp::IrpSetInfo`]
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

/// See [`IOMessage`] struct.
#[derive(FromPrimitive)]
pub enum FileLocationInfo {
    NotProtected,
    Protected,
    MovedIn,
    MovedOut,
}

/// Messages types to send directives to the minifilter, by using te [`DriverComMessage`] struct.
pub enum DriverComMessageType {
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

/// See [`shared_def::IOMessage`] struct and [this doc](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes).
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
            0 => IrpMajorOp::IrpNone,
            1 => IrpMajorOp::IrpRead,
            2 => IrpMajorOp::IrpWrite,
            3 => IrpMajorOp::IrpSetInfo,
            4 => IrpMajorOp::IrpCreate,
            5 => IrpMajorOp::IrpCreate,
            _ => IrpMajorOp::IrpNone,
        }
    }
}

/// See [`shared_def::IOMessage`] struct and [this doc](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea).
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

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileId(pub u64);

impl FileId {
    pub fn from(fileid: [u8; FILE_ID_LEN]) -> FileId {
        let mut hasher = DefaultHasher::new();
        fileid.hash(&mut hasher);
        let hash = hasher.finish();
        FileId(hash)
    }
}

/// Represents a driver message.
///
/// - extension: The file extension
/// - `file_id_id`:  File ID on the disk (`FILE_ID_INFO`)
/// - `mem_size_used`: Number of bytes transferred (`IO_STATUS_BLOCK.Information`)
/// - `entropy`: (Optional) File Entropy calculated by the driver
/// - `is_entropy_calc`: is the entropy calculated?
/// - `pid`: Pid responsible for this io activity
/// - `irp_op`: Windows IRP Type catched by the minifilter:
///     * NONE (0)
///     * READ (1)
///     * WRITE (2)
///     * SETINFO (3)
///     * CREATE (4)
///     * CLEANUP (5)
/// - `file_change`: type of i/o operation:
///     * `FILE_CHANGE_NOT_SET` (0)
///     * `FILE_OPEN_DIRECTORY` (1)
///     * `FILE_CHANGE_WRITE` (2)
///     * `FILE_CHANGE_NEW_FILE` (3)
///     * `FILE_CHANGE_RENAME_FILE` (4)
///     * `FILE_CHANGE_EXTENSION_CHANGED` (5)
///     * `FILE_CHANGE_DELETE_FILE` (6)
///     * `FILE_CHANGE_DELETE_NEW_FILE` (7)
///     * `FILE_CHANGE_OVERWRITE_FILE` (8)
/// - `file_location_info`: the driver has the ability to monitor specific directories only (feature currently not used):
///     * `FILE_NOT_PROTECTED` (0): Monitored dirs do not contained this file
///     * `FILE_PROTECTED` (1)
///     * `FILE_MOVED_IN` (2)
///     * `FILE_MOVED_OUT` (3)
/// - filepath: File path on the disk
/// - gid: Group Identifier (maintained by the minifilter) of the operation
/// - `runtime_features`: see class [`RuntimeFeatures`]
/// - `file_size`: size of the file. Can be equal to -1 if the file path is not found.
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

/// Stores runtime features that come from *`owlyshield_predict`* (and not the minifilter).
///
/// - exepath: The path of the gid root process
/// - `exe_exists`: Did the root exe file still existed (at the moment of this specific *`DriverMessage`* operation)?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeFeatures {
    pub exepath: PathBuf,
    pub exe_still_exists: bool,
}

impl RuntimeFeatures {
    pub fn new() -> RuntimeFeatures {
        RuntimeFeatures {
            exepath: PathBuf::new(),
            exe_still_exists: true,
        }
    }
}
