//! Contains all definitions shared between this user-mode app and the minifilter in order to
//! communicate properly. Those are C-representation of structures sent or received from the minifilter.

use std::fmt;
use std::os::raw::{c_uchar, c_ulong, c_ulonglong, c_ushort};
use std::path::PathBuf;

use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};
use wchar::wchar_t;
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::Storage::FileSystem::FILE_ID_INFO;
use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameA;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/// See [`IOMessage`] struct. Used with [`IrpSetInfo`](crate::driver_comm::IrpMajorOp::IrpSetInfo)
#[derive(FromPrimitive)]
#[repr(C)]
pub enum FileChangeInfo {
    FileChangeNotSet,
    FileOpenDirectory,
    FileChangeWrite,
    FileChangeNewFile,
    FileChangeRenameFile,
    FileChangeExtensionChanged,
    FileChangeDeleteFile,
    /// Temp file: created and deleted on close
    FileChangeDeleteNewFile,
    FileChangeOverwriteFile,
}

/// See [`IOMessage`] struct.
#[derive(FromPrimitive)]
#[repr(C)]
pub enum FileLocationInfo {
    FileNotProtected,
    FileProtected,
    FileMovedIn,
    FileMovedOut,
}

/// Low-level C-like object to communicate with the minifilter.
/// The minifilter yields `ReplyIrp` objects (retrieved by [`get_irp`](crate::driver_comm::Driver::get_irp) to
/// manage the fixed size of the *data buffer.
/// In other words, a `ReplyIrp` is a collection of [`CDriverMsg`] with a capped size.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ReplyIrp {
    /// The size od the collection.
    pub data_size: c_ulonglong,
    /// The C pointer to the buffer containing the [`CDriverMsg`] events.
    pub data: *const CDriverMsg,
    /// The number of different operations in this collection.
    pub num_ops: u64,
}

impl ReplyIrp {
    /// Iterate through `self.data` and returns the collection of [`CDriverMsg`]
    #[inline]
    fn unpack_drivermsg(&self) -> Vec<&CDriverMsg> {
        let mut res = vec![];
        unsafe {
            let mut msg = &*self.data;
            res.push(msg);
            for _ in 0..(self.num_ops) {
                if msg.next.is_null() {
                    break;
                }
                msg = &*msg.next;
                res.push(msg);
            }
        }
        res
    }
}

/// This class is the straight Rust translation of the Win32 API
/// [`UNICODE_STRING`](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string),
/// returned by the driver.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct UnicodeString {
    pub length: c_ushort,
    pub maximum_length: c_ushort,
    pub buffer: *const wchar_t,
}

impl UnicodeString {
    /*
    pub fn to_string(&self) -> String {
        unsafe {
            let str_slice = std::slice::from_raw_parts(self.buffer, self.length as usize);
            let mut first_zero_index = 0;
            for (i, c) in str_slice.iter().enumerate() {
                if *c == 0 {
                    first_zero_index = i;
                    break;
                }
            }
            String::from_utf16_lossy(&str_slice[..first_zero_index])
        }
    }
    */

    /// Get the file path from the `UnicodeString` path and the extension returned by the driver.
    #[inline]
    pub fn to_string_ext(&self, extension: [wchar_t; 12]) -> String {
        unsafe {
            let str_slice = std::slice::from_raw_parts(self.buffer, self.length as usize);
            let mut first_zero_index = 0;
            let mut last_dot_index = 0;
            let mut first_zero_index_ext = 0;

            // Filepath
            for (i, c) in str_slice.iter().enumerate() {
                if *c == 46 {
                    last_dot_index = i + 1;
                }
                if *c == 0 {
                    first_zero_index = i;
                    break;
                }
            }

            if first_zero_index_ext > 0 && last_dot_index > 0 {
                // Extension
                for (i, c) in extension.iter().enumerate() {
                    if *c == 0 {
                        first_zero_index_ext = i;
                        break;
                    } else if *c != str_slice[last_dot_index + i] {
                        first_zero_index_ext = 0;
                        break;
                    }
                }
                String::from_utf16_lossy(
                    &[
                        &str_slice[..last_dot_index],
                        &extension[..first_zero_index_ext],
                    ]
                        .concat(),
                )
            } else {
                String::from_utf16_lossy(&str_slice[..first_zero_index])
            }
        }
    }
}

impl fmt::Display for UnicodeString {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let str_slice = std::slice::from_raw_parts(self.buffer, self.length as usize);
            let mut first_zero_index = 0;
            for (i, c) in str_slice.iter().enumerate() {
                if *c == 0 {
                    first_zero_index = i;
                    break;
                }
            }
            write!(
                f,
                "{}",
                String::from_utf16_lossy(&str_slice[..first_zero_index])
            )
        }
    }
}

/// Represents a driver message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct IOMessage {
    /// The file extension
    pub extension: [wchar_t; 12],
    /// Hard Disk Volume Serial Number where the file is saved (from [`FILE_ID_INFO`])
    pub file_id_vsn: c_ulonglong,
    /// File ID on the disk ([`FILE_ID_INFO`])
    pub file_id_id: [u8; 16],
    /// Number of bytes transferred (`IO_STATUS_BLOCK.Information`)
    pub mem_sized_used: c_ulonglong,
    /// (Optional) File Entropy calculated by the driver
    pub entropy: f64,
    /// Pid responsible for this io activity
    pub pid: c_ulong,
    /// Windows IRP Type caught by the minifilter:
    /// - NONE (0)
    /// - READ (1)
    /// - WRITE (2)
    /// - SETINFO (3)
    /// - CREATE (4)
    /// - CLEANUP (5)
    pub irp_op: c_uchar,
    /// Is the entropy calculated?
    pub is_entropy_calc: u8,
    /// Type of i/o operation:
    /// - FILE_CHANGE_NOT_SET (0)
    /// - FILE_OPEN_DIRECTORY (1)
    /// - FILE_CHANGE_WRITE (2)
    /// - FILE_CHANGE_NEW_FILE (3)
    /// - FILE_CHANGE_RENAME_FILE (4)
    /// - FILE_CHANGE_EXTENSION_CHANGED (5)
    /// - FILE_CHANGE_DELETE_FILE (6)
    /// - FILE_CHANGE_DELETE_NEW_FILE (7)
    /// - FILE_CHANGE_OVERWRITE_FILE (8)
    pub file_change: c_uchar,
    /// The driver has the ability to monitor specific directories only (feature currently not used):
    /// - FILE_NOT_PROTECTED (0): Monitored dirs do not contained this file
    /// - FILE_PROTECTED (1)
    /// - FILE_MOVED_IN (2)
    /// - FILE_MOVED_OUT (3)
    pub file_location_info: c_uchar,
    /// File path on the disk
    pub filepathstr: String,
    /// Group Identifier (maintained by the minifilter) of the operation
    pub gid: c_ulonglong,
    /// see class [`RuntimeFeatures`]
    pub runtime_features: RuntimeFeatures,
    /// Size of the file. Can be equal to -1 if the file path is not found.
    pub file_size: i64,
}

impl IOMessage {
    /// Make a new [`IOMessage`] from a received [`CDriverMsg`]
    #[inline]
    pub fn from(c_drivermsg: &CDriverMsg) -> Self {
        Self {
            extension: c_drivermsg.extension,
            file_id_vsn: c_drivermsg.file_id.VolumeSerialNumber,
            file_id_id: c_drivermsg.file_id.FileId.Identifier,
            mem_sized_used: c_drivermsg.mem_sized_used,
            entropy: c_drivermsg.entropy,
            pid: c_drivermsg.pid,
            irp_op: c_drivermsg.irp_op,
            is_entropy_calc: c_drivermsg.is_entropy_calc,
            file_change: c_drivermsg.file_change,
            file_location_info: c_drivermsg.file_location_info,
            filepathstr: c_drivermsg.filepath.to_string_ext(c_drivermsg.extension),
            gid: c_drivermsg.gid,
            runtime_features: RuntimeFeatures::new(),
            file_size: match PathBuf::from(
                &c_drivermsg.filepath.to_string_ext(c_drivermsg.extension),
            )
                .metadata()
            {
                Ok(f) => f.len() as i64,
                Err(_e) => -1,
            },
        }
    }
}

/// Stores runtime features that come from our application (and not the minifilter).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct RuntimeFeatures {
    /// The path of the gid root process
    pub exepath: PathBuf,
    ///  Did the root exe file still existed (at the moment of this specific *DriverMessage* operation)?
    pub exe_still_exists: bool,
}

impl RuntimeFeatures {
    /// Make a new [`RuntimeFeatures`]
    #[inline]
    pub fn new() -> Self {
        Self {
            exepath: PathBuf::new(),
            exe_still_exists: true,
        }
    }
}

impl Default for RuntimeFeatures {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The C object returned by the minifilter, available through [`ReplyIrp`].
/// It is low level and use C pointers logic which is not always compatible with RUST (in particular
/// the lifetime of `*next`). That's why we convert it asap to a plain Rust [`IOMessage`] object.
///
/// `next` is null `(0x0)` when there is no [`IOMessage`] remaining.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct CDriverMsg {
    pub extension: [wchar_t; 12],
    pub file_id: FILE_ID_INFO,
    pub mem_sized_used: c_ulonglong,
    pub entropy: f64,
    pub pid: c_ulong,
    pub irp_op: c_uchar,
    pub is_entropy_calc: u8,
    pub file_change: c_uchar,
    pub file_location_info: c_uchar,
    pub filepath: UnicodeString,
    pub gid: c_ulonglong,
    /// null (0x0) when there is no [`IOMessage`] remaining
    pub next: *const CDriverMsg,
}

/// To iterate easily over a collection of [`IOMessage`] received from the minifilter, before they are
/// converted to [`IOMessage`].
#[repr(C)]
pub struct CDriverMsgs<'a> {
    drivermsgs: Vec<&'a CDriverMsg>,
    index: usize,
}

impl CDriverMsgs<'_> {
    /// Make a new [`CDriverMsgs`] from a received [`ReplyIrp`]
    #[inline]
    pub fn new(irp: &ReplyIrp) -> CDriverMsgs {
        CDriverMsgs {
            drivermsgs: irp.unpack_drivermsg(),
            index: 0,
        }
    }
}

impl Iterator for CDriverMsgs<'_> {
    type Item = CDriverMsg;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.drivermsgs.len() {
            None
        } else {
            let res = *self.drivermsgs[self.index];
            self.index += 1;
            Some(res)
        }
    }
}