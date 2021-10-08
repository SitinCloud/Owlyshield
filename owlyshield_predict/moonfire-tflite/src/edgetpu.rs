// Copyright (C) 2020 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

// Matches edgetpu_c.h: enum edgetpu_device_type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub enum Type {
    ApexPci = 0,
    ApexUsb = 1,
}

// Matches edgetpu_c.h:struct edgetpu_device
#[repr(C)]
pub struct Device {
    type_: Type,
    path: *const c_char,
}

// matches edgetpu_c.h:struct edgetpu_option
#[repr(C)]
struct RawOption {
    name: *const c_char,
    value: *const c_char,
}

// #[link(name = "edgetpu")
extern "C" {
    fn edgetpu_list_devices(num_devices: *mut usize) -> *mut Device;
    fn edgetpu_free_devices(dev: *mut Device);
    fn edgetpu_create_delegate(
        type_: Type,
        name: *const libc::c_char,
        options: *const RawOption,
        num_options: usize,
    ) -> *mut super::TfLiteDelegate;
    fn edgetpu_free_delegate(delegate: *mut super::TfLiteDelegate);
    fn edgetpu_verbosity(verbosity: libc::c_int);
    fn edgetpu_version() -> *const c_char;
}

pub fn version() -> &'static str {
    unsafe { CStr::from_ptr(edgetpu_version()) }
        .to_str()
        .unwrap()
}

pub fn verbosity(verbosity: libc::c_int) {
    unsafe { edgetpu_verbosity(verbosity) };
}

pub struct Devices {
    devices: ptr::NonNull<Device>,
    num_devices: usize,
}

impl Devices {
    pub fn list() -> Self {
        let mut num_devices = 0usize;
        let ptr = unsafe { edgetpu_list_devices(&mut num_devices) };
        let devices = match num_devices {
            0 => ptr::NonNull::dangling(),
            _ => ptr::NonNull::new(ptr).unwrap(),
        };
        Devices {
            devices,
            num_devices,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.num_devices == 0
    }
    pub fn len(&self) -> usize {
        self.num_devices
    }
}

impl std::ops::Deref for Devices {
    type Target = [Device];

    fn deref(&self) -> &[Device] {
        unsafe { std::slice::from_raw_parts(self.devices.as_ptr(), self.num_devices) }
    }
}

impl<'a> std::iter::IntoIterator for &'a Devices {
    type Item = &'a Device;
    type IntoIter = std::slice::Iter<'a, Device>;

    fn into_iter(self) -> std::slice::Iter<'a, Device> {
        self.iter()
    }
}

impl Drop for Devices {
    fn drop(&mut self) {
        if self.num_devices > 0 {
            unsafe { edgetpu_free_devices(self.devices.as_ptr()) };
        }
    }
}

impl Device {
    pub fn create_delegate(&self) -> Result<super::Delegate, ()> {
        let delegate = unsafe { edgetpu_create_delegate(self.type_, self.path, ptr::null(), 0) };
        let delegate = ptr::NonNull::new(delegate).ok_or(())?;
        Ok(super::Delegate {
            delegate,
            free: edgetpu_free_delegate,
        })
    }

    pub fn type_(&self) -> Type {
        self.type_
    }
    pub fn path(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.path) }
    }
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}@{}", self.type_, self.path().to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn version() {
        println!("edgetpu version: {}", super::version());
    }

    #[test]
    fn list_devices() {
        let devices = super::Devices::list();
        println!("{} edge tpu devices:", devices.len());
        for d in &devices {
            println!("device: {:?}", d);
        }
    }

    #[test]
    fn create_delegate() {
        let devices = super::Devices::list();
        if !devices.is_empty() {
            devices[0].create_delegate().unwrap();
        }
    }
}
