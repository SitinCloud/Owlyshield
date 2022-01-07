use std::{fmt, fs};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{Debug, Formatter};
use std::path::Path;

use object::{AddressSize, Object, read};
use object::read::pe::{ImageNtHeaders, PeFile, PeFile32, PeFile64};
use serde::Serialize;

use crate::PeParsingError::{ArchNotImplementedError, UnknownAddrSizeError};

#[derive(Serialize)]
pub struct StaticFeatures {
    pub appname: String,
    pub data_len: usize,
    pub section_table_len: usize,
    pub imports: Vec<LibImport>,
    pub has_dbg_symbols: bool,
}

#[derive(Serialize)]
pub struct LibImport {
    pub lib: String,
    pub import: String,
}

impl StaticFeatures {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}

pub enum PeParsingError {
    ArchNotImplementedError,
    UnknownAddrSizeError,
}

impl fmt::Display for PeParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Arch not implemented")
    }
}

impl Debug for PeParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Arch not implemented")
    }
}

impl Error for PeParsingError {}

pub fn inspect_pe(path: &Path) -> Result<StaticFeatures, Box<dyn Error>> {
    let bin_data = fs::read(path)?;
    let obj_data = object::File::parse(&*bin_data)?;
    let arch = obj_data.architecture();
    if let Some(addr_size) = arch.address_size() {
        match addr_size {
            AddressSize::U32 => {
                let obj_pe: PeFile32 = read::pe::PeFile::parse(&*bin_data)?;
                inspect_pe_aux(path, &bin_data, &obj_pe)
            }
            AddressSize::U64 => {
                let obj_pe: PeFile64 = read::pe::PeFile::parse(&*bin_data)?;
                inspect_pe_aux(path, &bin_data, &obj_pe)
            }
            _ => { Err(Box::new(ArchNotImplementedError)) }
        }
    } else {
        Err(Box::new(UnknownAddrSizeError))
    }
}

fn inspect_pe_aux<Pe: ImageNtHeaders>(path: &Path, bin_data: &Vec<u8>, obj_pe: &PeFile<Pe>) -> Result<StaticFeatures, Box<dyn Error>> {
    let pe_imports = obj_pe.imports()?;
    let mut lib_imports: Vec<LibImport> = vec![];
    for import in pe_imports {
        lib_imports.push(LibImport {
            lib: String::from_utf8(Vec::from(import.library())).unwrap(),
            import: String::from_utf8(Vec::from(import.name())).unwrap(),
        });
    }

    Ok(StaticFeatures {
        appname: path.file_name().unwrap_or(OsStr::new("UNKNOWN.exe")).to_os_string().into_string().unwrap_or(String::from("UNKNOWN.exe")),
        data_len: bin_data.len(),
        section_table_len: obj_pe.section_table().len(),
        imports: lib_imports,
        has_dbg_symbols: obj_pe.has_debug_symbols(),
    })
}
