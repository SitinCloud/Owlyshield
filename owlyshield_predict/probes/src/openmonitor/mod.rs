//use cty::*;

pub const PATH_SEGMENT_LEN: usize = 32; //32;
pub const PATH_LIST_LEN: usize = 11;

#[derive(Debug)]
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

#[derive(Debug)]
pub struct FileAccess {
    pub ns: u64,
    pub entropy: f64,
    pub ino: u64,
    pub pid: u64,
    pub fsize: i64,
    pub access: Access,
    pub comm: [i8; 16],
}

