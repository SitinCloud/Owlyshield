//! Low-level communication with the minifilter.

pub mod shared_def;

use std::mem;
use std::os::raw::{c_ulong, c_ulonglong};
use std::ptr;

use sysinfo::{get_current_pid, Pid, PidExt};
use wchar::wchar_t;
use widestring::U16CString;
use windows::core::{HRESULT, PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::GetDriveTypeA;
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterSendMessage,
};

use crate::driver_com::DriveType::{
    DriveCDRom, DriveFixed, DriveNoRootDir, DriveRamDisk, DriveRemote, DriveRemovable, DriveUnknown,
};
use crate::driver_com::IrpMajorOp::{IrpCreate, IrpNone, IrpRead, IrpSetInfo, IrpWrite};
use crate::driver_com::shared_def::ReplyIrp;

type BufPath = [wchar_t; 520];

/// The user-mode app (this app) can send several messages types to the driver. See [`DriverComMessageType`]
/// for details.
/// Depending on the message type, the *pid*, *gid* and *path* fields can be optional.
#[derive(Debug)]
#[repr(C)]
struct DriverComMessage {
    /// The type message to send. See [`DriverComMessageType`].
    r#type: c_ulong,
    /// The pid of the process which triggered an i/o activity;
    pid: c_ulong,
    /// The gid is maintained by the driver
    gid: c_ulonglong,
    path: BufPath,
}

/// Messages types to send directives to the minifilter, by using te [`DriverComMessage`] struct.
#[repr(C)]
#[allow(dead_code)]
enum DriverComMessageType {
    /// Not used yet. The minifilter has the ability to monitor a specific part of the fs.
    AddScanDirectory,
    /// Not used yet. The minifilter has the ability to monitor a specific part of the fs.
    RemScanDirectory,
    /// Ask for a [`ReplyIrp`], if any available.
    GetOps,
    /// Set this app pid to the minifilter (related IRPs will be ignored);
    SetPid,
    /// Instruct the minifilter to kill all pids in the family designated by a given gid.
    KillGid,
}

/// A minifilter is identified by a port (know in advance), like a named pipe used for communication,
/// and a handle, retrieved by [`open_kernel_driver_com`](Self::open_kernel_driver_com).
#[derive(Debug)]
#[repr(C)]
pub struct Driver {
    handle: HANDLE,
}

impl Driver {
    /// Can be used to properly close the communication (and unregister) with the minifilter.
    /// If this fn is not used and the program has stopped, the handle is automatically closed,
    /// seemingly without any side-effects.
    #[inline]
    pub fn close_kernel_communication(&self) -> bool {
        unsafe { CloseHandle(self.handle).as_bool() }
    }

    /// The user-mode running app (this one) has to register itself to the driver.
    ///
    /// # Panics
    /// This fn panics if it is unable to get the current pid.
    ///
    /// # Errors
    /// This fn returns an error if it is unable to register itself to the minifilter.
    #[inline]
    pub fn driver_set_app_pid(&self) -> Result<(), windows::core::Error> {
        let buf = Self::string_to_commessage_buffer(r"\Device\harddiskVolume");

        let mut get_irp_msg: DriverComMessage = DriverComMessage {
            r#type: DriverComMessageType::SetPid as c_ulong,
            pid: get_current_pid().unwrap().as_u32() as c_ulong,
            gid: 140_713_315_094_899,
            path: buf, //wch!("\0"),
        };
        let mut tmp: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(get_irp_msg).cast::<std::ffi::c_void>(),
                mem::size_of::<DriverComMessage>() as c_ulong,
                None,
                0,
                ptr::addr_of_mut!(tmp),
            )
        }
    }

    /// Try to open a com canal with the minifilter before this app is registered.
    ///
    /// # Panics
    /// This function will panic if the minifilter port has any nul value (except the last one)
    /// in it's name.
    ///
    /// # Errors
    /// This fn can fail is the minifilter is unreachable:
    ///
    /// * if it is not started (try `sc start snFilter` first
    /// * if a connection is already established: it can accepts only one at a time.
    ///
    /// In that case the Error is raised by the OS (`windows::Error`) and is generally readable.
    #[inline]
    pub fn open_kernel_driver_com() -> Result<Self, windows::core::Error> {
        let com_port_name = U16CString::from_str("\\snFilter").unwrap().into_raw();
        let handle;
        unsafe {
            handle = FilterConnectCommunicationPort(PCWSTR(com_port_name), 0, None, 0, None)?;
        }
        let res = Self { handle };
        Ok(res)
    }

    /// Ask the driver for a [`ReplyIrp`], if any. This is a low-level function and the returned object
    /// uses C pointers. Managing C pointers requires a special care, because of the Rust timelines.
    /// [`ReplyIrp`] is optional since the minifilter returns null if there is no new activity.
    ///
    /// # Panics
    /// This fn panics if it is unable to get the current pid or cannot get driver message from the
    /// minifilter.
    #[inline]
    pub fn get_irp(&self, vecnew: &mut Vec<u8>) -> Option<ReplyIrp> {
        let mut get_irp_msg = Self::build_irp_msg(
            DriverComMessageType::GetOps,
            get_current_pid().unwrap(),
            0,
            "",
        );
        let mut tmp: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(get_irp_msg).cast::<std::ffi::c_void>(),
                mem::size_of::<DriverComMessage>() as c_ulong,
                Option::from(vecnew.as_mut_ptr().cast::<std::ffi::c_void>()),
                65536_u32,
                ptr::addr_of_mut!(tmp).cast::<u32>(),
            )
                .expect("Cannot get driver message from driver");
        }

        if tmp != 0 {
            let reply_irp: ReplyIrp;
            unsafe {
                reply_irp =
                    ptr::read_unaligned(vecnew.as_ptr().cast::<ReplyIrp>());
            }
            return Some(reply_irp);
        }
        None
    }

    /// Ask the minifilter to kill all pids related to the given *gid*. Pids are killed in driver-mode
    /// by calls to `NtClose`.
    #[inline]
    pub fn try_kill(&self, gid: c_ulonglong) -> Result<HRESULT, windows::core::Error> {
        let mut killmsg = DriverComMessage {
            r#type: DriverComMessageType::KillGid as c_ulong,
            pid: 0, //get_current_pid().unwrap() as u32,
            gid,
            path: [0; 520],
        };
        let mut res: i32 = 0;
        let mut res_size: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(killmsg).cast::<std::ffi::c_void>(),
                mem::size_of::<DriverComMessage>() as c_ulong,
                Option::from(ptr::addr_of_mut!(res).cast::<std::ffi::c_void>()),
                4_u32,
                ptr::addr_of_mut!(res_size).cast::<u32>(),
            )?;
        }

        Ok(HRESULT(res))
    }

    #[inline]
    fn string_to_commessage_buffer(bufstr: &str) -> BufPath {
        let temp = U16CString::from_str(bufstr).unwrap();
        let mut buf: BufPath = [0; 520];
        for (i, c) in temp.as_slice_with_nul().iter().enumerate() {
            buf[i] = *c as wchar_t;
        }
        buf
    }

    // TODO: move to ComMessage?
    #[inline]
    fn build_irp_msg(
        commsgtype: DriverComMessageType,
        pid: Pid,
        gid: u64,
        path: &str,
    ) -> DriverComMessage {
        DriverComMessage {
            r#type: commsgtype as c_ulong, // SetPid
            pid: pid.as_u32() as c_ulong,
            gid,
            path: Self::string_to_commessage_buffer(path),
        }
    }
}

/// See [`IOMessage`](crate::shared_def::IOMessage) struct and
/// [this doc](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes).
#[repr(C)]
pub enum IrpMajorOp {
    /// Nothing happened
    IrpNone,
    /// On read, any time following the successful completion of a create request.
    IrpRead,
    /// On write, any time following the successful completion of a create request.
    IrpWrite,
    /// Set Metadata about a file or file handle. In that case, [`FileChangeInfo`](crate::shared_def::FileChangeInfo) indicates
    /// the nature of the modification.
    IrpSetInfo,
    /// Open a handle to a file object or device object.
    IrpCreate,
    /// File object handle has been closed
    IrpCleanUp,
}

impl IrpMajorOp {
    #[inline]
    pub fn from_byte(b: u8) -> Self {
        match b {
            // 0 => IrpNone,
            1 => IrpRead,
            2 => IrpWrite,
            3 => IrpSetInfo,
            4 | 5 => IrpCreate,
            _ => IrpNone,
        }
    }
}

/// See [`IOMessage`](crate::shared_def::IOMessage) struct and
/// [this doc](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea).
#[repr(C)]
pub enum DriveType {
    /// The drive type cannot be determined.
    DriveUnknown,
    /// The root path is invalid; for example, there is no volume mounted at the specified path.
    DriveNoRootDir,
    /// The drive has removable media; for example, a floppy drive, thumb drive, or flash card reader.
    DriveRemovable,
    /// The drive has fixed media; for example, a hard disk drive or flash drive.
    DriveFixed,
    /// The drive is a remote (network) drive.
    DriveRemote,
    /// The drive is a CD-ROM drive.
    DriveCDRom,
    /// The drive is a RAM disk.
    DriveRamDisk,
}

impl DriveType {
    /// Determines whether a disk drive is a removable, fixed, CD-ROM, RAM disk, or network drive.
    ///
    /// # Panics
    /// Will panic if drive path is invalid.
    #[inline]
    pub fn from_filepath(filepath: &str) -> Self {
        let mut drive_type = 1u32;
        if !filepath.is_empty() {
            let drive_path = &filepath[..=filepath.find('\\').unwrap()];
            unsafe {
                drive_type = GetDriveTypeA(PCSTR(String::from(drive_path).as_ptr()));
            }
        }
        match drive_type {
            0 => DriveUnknown,
            // 1 => DriveNoRootDir,
            2 => DriveRemovable,
            3 => DriveFixed,
            4 => DriveRemote,
            5 => DriveCDRom,
            6 => DriveRamDisk,
            _ => DriveNoRootDir,
        }
    }
}