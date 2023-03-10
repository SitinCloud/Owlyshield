//! Low-level communication with the minifilter.
use core::ffi::c_void;
use std::mem;
use std::ptr;

use sysinfo::{get_current_pid, Pid};
use wchar::wchar_t;
use widestring::U16CString;

use windows::core::{Error, PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::GetDriveTypeA;
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterSendMessage,
};

use std::os::raw::{c_uchar, c_ulong, c_ulonglong, c_ushort};
use std::path::PathBuf;
use std::time::SystemTime;

use windows::Win32::Storage::FileSystem::FILE_ID_INFO;
use std::os::windows::ffi::OsStringExt;

use crate::shared_def::{
    DriverComMessageType,
    FileId,
    IOMessage,
    DriveType::{
        CDRom, Fixed, NoRootDir, RamDisk, Remote, Removable, Unknown
    },
    DriveType,
    RuntimeFeatures,
};

pub type BufPath = [wchar_t; 520];

/// The usermode app (this app) can send several messages types to the driver. See [`DriverComMessageType`]
/// for details.
/// Depending on the message type, the *pid*, *gid* and *path* fields can be optional.
#[derive(Debug)]
#[repr(C)]
struct DriverComMessage {
    /// The type message to send. See [DriverComMessageType].
    r#type: c_ulong,
    /// The pid of the process which triggered an i/o activity;
    pid: c_ulong,
    /// The gid is maintained by the driver
    gid: c_ulonglong,
    path: BufPath,
}

/// A minifilter is identified by a port (know in advance), like a named pipe used for communication,
/// and a handle, retrieved by [`Self::open_kernel_driver_com`].
#[derive(Debug)]
pub struct Driver {
    handle: HANDLE, //Full type name because Intellij raises an error...
}

impl DriveType {
    pub fn from_filepath(filepath: String) -> DriveType {
        let mut drive_type = 1u32;
        if !filepath.is_empty() {
            let drive_path = &filepath[..(filepath.find('\\').unwrap_or(0) + 1)];
            unsafe {
                drive_type = GetDriveTypeA(PCSTR::from_raw(drive_path.as_ptr()));
            }
        }
        match drive_type {
            0 => Unknown,
            1 => NoRootDir,
            2 => Removable,
            3 => Fixed,
            4 => Remote,
            5 => CDRom,
            6 => RamDisk,
            _ => NoRootDir,
        }
    }
}

impl Driver {
    /// Can be used to properly close the communication (and unregister) with the minifilter.
    /// If this fn is not used and the program has stopped, the handle is automatically closed,
    /// seemingly without any side-effects.
    pub fn _close_kernel_communication(&self) -> bool {
        unsafe { CloseHandle(self.handle).as_bool() }
    }

    /// The usermode running app (this one) has to register itself to the driver.
    pub fn driver_set_app_pid(&self) -> Result<(), Error> {
        let buf = Driver::string_to_commessage_buffer(r"\Device\harddiskVolume");

        let mut get_irp_msg: DriverComMessage = DriverComMessage {
            r#type: DriverComMessageType::MessageSetPid as c_ulong,
            pid: usize::from(get_current_pid().unwrap()) as c_ulong,
            gid: 140713315094899,
            path: buf, //wch!("\0"),
        };
        let mut tmp: u32 = 0;
        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(get_irp_msg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                Some(ptr::null_mut()),
                0,
                &mut tmp as *mut u32,
            )
        }
    }

    /// Try to open a com canal with the minifilter before this app is registered. This fn can fail
    /// is the minifilter is unreachable:
    /// * if it is not started (try ```sc start owlyshieldransomfilter``` first
    /// * if a connection is already established: it can accepts only one at a time.
    /// In that case the Error is raised by the OS (`windows::Error`) and is generally readable.
    pub fn open_kernel_driver_com() -> Result<Driver, Error> {
        let com_port_name = U16CString::from_str("\\RWFilter").unwrap().into_raw();
        let handle;
        unsafe {
            handle = FilterConnectCommunicationPort(
                PCWSTR(com_port_name),
                0,
                Some(ptr::null()),
                0,
                Some(ptr::null_mut()),
            )?;
        }
        let res = Driver { handle };
        Ok(res)
    }

    /// Ask the driver for a [`ReplyIrp`], if any. This is a low-level function and the returned object
    /// uses C pointers. Managing C pointers requires a special care, because of the Rust timelines.
    /// [`ReplyIrp`] is optional since the minifilter returns null if there is no new activity.
    pub fn get_irp(&self, vecnew: &mut Vec<u8>) -> Option<ReplyIrp> {
        let mut get_irp_msg = Driver::build_irp_msg(
            DriverComMessageType::MessageGetOps,
            get_current_pid().unwrap(),
            0,
            "",
        );
        let mut tmp: u32 = 0;
        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(get_irp_msg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                Some(vecnew.as_ptr() as *mut c_void),
                65536,
                ptr::addr_of_mut!(tmp) as *mut u32,
            )
                .expect("Cannot get driver message from driver");
        }
        if tmp != 0 {
            let reply_irp: ReplyIrp;
            unsafe {
                reply_irp = ptr::read_unaligned(vecnew.as_ptr() as *const ReplyIrp);
            }
            return Some(reply_irp);
        }
        None
    }

    /// Ask the minifilter to kill all pids related to the given *gid*. Pids are killed in drivermode
    /// by calls to `NtClose`.
    pub fn try_kill(&self, gid: c_ulonglong) -> Result<windows::core::HRESULT, Error> {
        let mut killmsg = DriverComMessage {
            r#type: DriverComMessageType::MessageKillGid as c_ulong,
            pid: 0, //get_current_pid().unwrap() as u32,
            gid,
            path: [0; 520],
        };
        let mut res: u32 = 0;
        let mut res_size: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(killmsg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                Some(ptr::addr_of_mut!(res) as *mut c_void),
                4,
                ptr::addr_of_mut!(res_size) as *mut u32,
            )?;
        }
        let hres = windows::core::HRESULT(res as i32);
        Ok(hres)
    }

    fn string_to_commessage_buffer(bufstr: &str) -> BufPath {
        let temp = U16CString::from_str(&bufstr).unwrap();
        let mut buf: BufPath = [0; 520];
        for (i, c) in temp.as_slice_with_nul().iter().enumerate() {
            buf[i] = *c as wchar_t;
        }
        buf
    }

    fn build_irp_msg(
        commsgtype: DriverComMessageType,
        pid: Pid,
        gid: u64,
        path: &str,
    ) -> DriverComMessage {
        DriverComMessage {
            r#type: commsgtype as c_ulong, // MessageSetPid
            pid: usize::from(pid) as c_ulong,
            gid,
            path: Driver::string_to_commessage_buffer(path),
        }
    }
}

/// Low-level C-like object to communicate with the minifilter.
/// The minifilter yields `ReplyIrp` objects (retrieved by [`crate::driver_com::Driver::get_irp`] to manage the fixed size of the *data buffer.
/// In other words, a `ReplyIrp` is a collection of [`CDriverMsg`] with a capped size.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ReplyIrp {
    /// The size od the collection.
    pub data_size: c_ulonglong,
    /// The C pointer to the buffer containinf the [CDriverMsg] events.
    pub data: *const CDriverMsg,
    /// The number of different operations in this collection.
    pub num_ops: u64,
}

/// This class is the straight Rust translation of the Win32 API [`UNICODE_STRING`](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string),
/// returned by the driver.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct UnicodeString {
    pub length: c_ushort,
    pub maximum_length: c_ushort,
    pub buffer: *const wchar_t,
}

/// The C object returned by the minifilter, available through [`ReplyIrp`].
/// It is low level and use C pointers logic which is
/// not always compatible with RUST (in particular the lifetime of *next). That's why we convert
/// it asap to a plain Rust [`IOMessage`] object.
/// ```next``` is null (0x0) when there is no [`IOMessage`] remaining
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

/// To iterate easily over a collection of [`IOMessage`] received from the minifilter, before they
/// are converted to [`IOMessage`]
pub struct CDriverMsgs<'a> {
    drivermsgs: Vec<&'a CDriverMsg>,
    index: usize,
}

impl UnicodeString {
    /// Get the file path from the `UnicodeString` path and the extension returned by the driver.
    pub fn as_string_ext(&self, extension: [wchar_t; 12]) -> String {
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

impl ReplyIrp {
    /// Iterate through ```self.data``` and returns the collection of [`CDriverMsg`]
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

impl IOMessage {
    pub fn from(c_drivermsg: &CDriverMsg) -> IOMessage {
        IOMessage {
            extension: std::ffi::OsString::from_wide(c_drivermsg.extension.split(|&v| v == 0).next().unwrap()).to_string_lossy().into() ,//String::from_utf16_lossy(&c_drivermsg.extension),
            file_id_id: FileId::from(c_drivermsg.file_id.FileId.Identifier),
            mem_sized_used: c_drivermsg.mem_sized_used,
            entropy: c_drivermsg.entropy,
            pid: c_drivermsg.pid,
            irp_op: c_drivermsg.irp_op,
            is_entropy_calc: c_drivermsg.is_entropy_calc,
            file_change: c_drivermsg.file_change,
            file_location_info: c_drivermsg.file_location_info,
            filepathstr: c_drivermsg.filepath.as_string_ext(c_drivermsg.extension),
            gid: c_drivermsg.gid,
            runtime_features: RuntimeFeatures::new(),
            file_size: match PathBuf::from(
                &c_drivermsg.filepath.as_string_ext(c_drivermsg.extension),
            )
                .metadata()
            {
                Ok(f) => f.len() as i64,
                Err(_) => -1,
            },
            time: SystemTime::now(),
        }
    }
}

impl CDriverMsgs<'_> {
    pub fn new(irp: &ReplyIrp) -> CDriverMsgs {
        CDriverMsgs {
            drivermsgs: irp.unpack_drivermsg(),
            index: 0,
        }
    }
}

impl Iterator for CDriverMsgs<'_> {
    type Item = CDriverMsg;

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
