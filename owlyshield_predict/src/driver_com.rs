use bindings::Windows::Win32::Foundation::CloseHandle;
use bindings::Windows::Win32::Foundation::{HANDLE, PWSTR};
use bindings::Windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterSendMessage,
};
use core::ffi::c_void;

use std::ptr;
use std::{mem, time};
use sysinfo::{get_current_pid, Pid};
use wchar::{wch, wchar_t, wchz};

use crate::driver_com::shared_def::ReplyIrp;
use crate::driver_com::IrpMajorOp::{IrpCreate, IrpNone, IrpRead, IrpSetInfo, IrpWrite};
use byteorder::*;
use rmp_serde::{Deserializer, Serializer};
use std::iter::Filter;
use std::os::raw::*;
use std::path::Path;
use widestring::U16CString;
use windows::{Error, HRESULT};

type BufPath = [wchar_t; 520];

#[derive(Debug)]
#[repr(C)]
struct ComMessage {
    r#type: c_ulong,
    pid: c_ulong,
    gid: c_ulonglong,
    path: BufPath,
}

#[derive(Debug)]
pub struct Driver {
    com_port_name: *mut u16,
    handle: HANDLE,
}

enum ComMessageType {
    MessageAddScanDirectory,
    MessageRemScanDirectory,
    MessageGetOps,
    MessageSetPid,
    MessageKillGid,
}

pub enum IrpMajorOp {
    IrpNone,
    IrpRead,
    IrpWrite,
    IrpSetInfo,
    IrpCreate,
    IrpCleanUp,
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

impl Driver {
    pub fn close_kernel_communication(&self) -> bool {
        unsafe { CloseHandle(&self.handle).as_bool() }
    }

    pub fn driver_set_app_pid(&self) -> Result<(), windows::Error> {
        let buf = Driver::string_to_commessage_buffer(r"\Device\harddiskVolume");

        let mut get_irp_msg: ComMessage = ComMessage {
            r#type: ComMessageType::MessageSetPid as c_ulong, //MessageSetPid
            pid: get_current_pid().unwrap() as c_ulong,
            gid: 140713315094899,
            path: buf, //wch!("\0"),
        };
        let mut tmp: u32 = 0;
        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(get_irp_msg) as *mut c_void,
                mem::size_of::<ComMessage>() as c_ulong,
                ptr::null_mut(),
                0,
                &mut tmp as *mut u32,
            )
        }
    }

    pub fn open_kernel_driver_com() -> Result<Driver, windows::Error> {
        let _com_port_name = U16CString::from_str("\\RWFilter").unwrap().into_raw();
        let _handle;
        unsafe {
            _handle = FilterConnectCommunicationPort(
                PWSTR(_com_port_name),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
            )?
        }
        let res = Driver {
            com_port_name: _com_port_name,
            handle: _handle,
        };
        Ok(res)
    }

    pub fn get_irp(&self, vecnew: &mut Vec<u8>) -> Option<ReplyIrp> {
        let mut get_irp_msg = Driver::build_irp_msg(
            ComMessageType::MessageGetOps,
            get_current_pid().unwrap(),
            0,
            "",
        );
        let mut tmp: u32 = 0;
        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(get_irp_msg) as *mut c_void,
                mem::size_of::<ComMessage>() as c_ulong,
                vecnew.as_ptr() as *mut c_void,
                65536 as u32,
                ptr::addr_of_mut!(tmp) as *mut u32,
            )
            .expect("Cannot get irp from driver");
        }
        if tmp != 0 {
            let reply_irp: shared_def::ReplyIrp;
            unsafe {
                reply_irp = std::ptr::read_unaligned(vecnew.as_ptr() as *const ReplyIrp);
            }
            return Some(reply_irp);
        }
        None
    }

    pub fn try_kill(&self, gid: c_ulonglong) -> Result<HRESULT, windows::Error> {
        //println!("TRY KILL {}", gid);
        let mut killmsg = ComMessage {
            r#type: ComMessageType::MessageKillGid as c_ulong,
            pid: 0, //get_current_pid().unwrap() as u32,
            gid: gid,
            path: [0; 520],
        };
        let mut res: u32 = 0;
        let mut res_size: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(killmsg) as *mut c_void,
                mem::size_of::<ComMessage>() as c_ulong,
                ptr::addr_of_mut!(res) as *mut c_void,
                4 as u32,
                ptr::addr_of_mut!(res_size) as *mut u32,
            )?;
        }
            //TODO

        let hres = HRESULT(res);
        return Ok(hres);
    }

    fn string_to_commessage_buffer(bufstr: &str) -> BufPath {
        let temp = U16CString::from_str(&bufstr).unwrap();
        let mut buf: BufPath = [0; 520];
        for (i, c) in temp.as_slice_with_nul().iter().enumerate() {
            buf[i] = c.clone() as wchar_t;
        }
        buf
    }

    fn build_irp_msg(commsgtype: ComMessageType, pid: Pid, gid: u64, path: &str) -> ComMessage {
        ComMessage {
            r#type: commsgtype as c_ulong, //MessageSetPid
            pid: pid as c_ulong,
            gid: gid,
            path: Driver::string_to_commessage_buffer(&path),
        }
    }
}

pub mod shared_def {
    use crate::driver_com::Driver;
    use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_128;
    use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_INFO;
    use serde::{de, Deserialize, Deserializer, Serialize};
    use std::ffi::{c_void, CStr, OsString};
    use std::fmt::Write;
    use std::os::raw::{c_uchar, c_ulong, c_ulonglong, c_ushort};
    use std::path::{Path, PathBuf};
    use std::string::FromUtf16Error;
    use std::thread::sleep;

    use serde::de::{MapAccess, SeqAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::Serializer;
    use std::fmt;
    use std::ptr::null;

    use wchar::wchar_t;
    use widestring::WideString;

    #[derive(FromPrimitive)]
    pub enum FileChangeInfo {
        FileChangeNotSet,
        FileOpenDirectory,
        FileChangeWrite,
        FileChangeNewFile,
        FileChangeRenameFile,
        FileChangeExtensionChanged,
        FileChangeDeleteFile,
        FileChangeDeleteNewFile, //TODO
        FileChangeOverwriteFile,
    }

    #[derive(FromPrimitive)]
    pub enum FileLocationInfo {
        FileNotProtected,
        FileProtected,
        FileMovedIn,
        FileMovedOut,
    }

    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct ReplyIrp {
        pub data_size: c_ulonglong,
        pub data: *const CDriverMsg,
        pub num_ops: u64,
    }

    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct UnicodeString {
        pub length: c_ushort,
        pub maximum_length: c_ushort,
        pub buffer: *const wchar_t,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[repr(C)]
    pub struct DriverMsg {
        pub extension: [wchar_t; 12],
        pub file_id_vsn: c_ulonglong,
        pub file_id_id: [u8; 16],
        pub mem_sized_used: c_ulonglong,
        pub entropy: f64,
        pub pid: c_ulong,
        pub irp_op: c_uchar,
        pub is_entropy_calc: u8,
        pub file_change: c_uchar,
        pub file_location_info: c_uchar,
        pub filepathstr: String,
        pub gid: c_ulonglong,
        pub runtime_features: RuntimeFeatures,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RuntimeFeatures {
        pub exepath: PathBuf,
        pub exe_still_exists: bool,
    }

    /// ```next``` is null (0x0) when there is no [DriverMsg] remaining
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
        pub next: *const CDriverMsg,
    }

    pub struct CDriverMsgs<'a> {
        drivermsgs: Vec<&'a CDriverMsg>,
        index: usize,
    }

    impl UnicodeString {
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

        pub fn dirname(&self) -> Option<String> {
            let temp = self.to_string();
            let parent = Path::new(&temp).parent();
            if parent.is_none() {
                None
            } else {
                Some(parent.unwrap().to_string_lossy().parse().unwrap())
            }
        }
    }

    impl ReplyIrp {
        pub fn get_drivermsg(&self) -> Option<&CDriverMsg> {
            if self.data.is_null() {
                return None;
            }
            unsafe { Some(&*self.data) }
        }

        fn unpack_drivermsg(&self) -> Vec<&CDriverMsg> {
            let mut res = vec![];
            unsafe {
                let mut msg = &*self.data;
                res.push(msg);
                for _ in 1..(self.num_ops) {
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

    impl DriverMsg {
        pub fn from(c_drivermsg: &CDriverMsg) -> DriverMsg {
            DriverMsg {
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
                filepathstr: c_drivermsg.filepath.to_string(),
                gid: c_drivermsg.gid,
                runtime_features: RuntimeFeatures::new(),
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

    impl CDriverMsg {
        fn next(&self) -> Option<&CDriverMsg> {
            if self.next.is_null() {
                return None;
            }
            unsafe { Some(&*self.next) }
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
}
