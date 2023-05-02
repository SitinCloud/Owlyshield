//use cty::*;
use core::mem::{size_of, transmute};
use bytemuck::{Pod, Zeroable};

pub const PATH_SEGMENT_LEN: usize = 32; //32;
pub const PATH_LIST_LEN: usize = 11;

//#[derive(Debug)]
#[derive(Debug, Copy, Clone)]
#[repr(u64)]
pub enum Access {
    Read(usize),
    Write(usize),
    Unlink(usize),
    Rmdir(usize),
    Mkdir(usize),
    Symlink(usize),
    Create(usize),
    Rename(usize),
}


type Buf = [u8; 32];//PATH_SEGMENT_LEN];

//#[derive(Debug, Default)]
//#[repr(packed)]
pub struct FilePath {
//    pub order: u8,
    pub ns: u64,
    pub level: usize,
    pub buf: Buf,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FileAccess {
    pub ns: u64,
    pub entropy: f64,
    pub ino: u64,
    pub pid: u64,
    pub fsize: i64,
    pub access: Access,
    pub comm: [i8; 16],
}

// Automatically implement Pod and Zeroable for MyStruct
unsafe impl Pod for FileAccess {}
unsafe impl Zeroable for FileAccess {}

pub const FILE_ACCESS_SIZE: usize = size_of::<FileAccess>();

impl FileAccess {
    pub fn to_u8_array(&self) -> [u8; size_of::<Self>()] {
        // Create a reference to MyStruct with a raw pointer.
        let my_struct_ptr = self as *const FileAccess;

        // Transmute the raw pointer to a reference of [u8; size_of::<MyStruct>()]
        //let array: &[u8; size_of::<Self>()] = unsafe { transmute(my_struct_ptr) };
        let array: &[u8; FILE_ACCESS_SIZE] = unsafe { transmute(my_struct_ptr) };

        // Dereference the array reference to clone the array of bytes.
        *array
    }
}

