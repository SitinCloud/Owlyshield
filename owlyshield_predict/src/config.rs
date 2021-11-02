use crate::extensions::ExtensionList;
use core::ops;
use registry::*;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::{Index, IndexMut};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Debug, EnumIter, PartialEq, Eq, Hash, Clone)]
pub enum Param {
    DebugPath,
    ConfigPath,
    NumVersion,
    UtilsPath,
    AppId,
}

impl Param {
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "CONFIG_PATH", // incidents reports, exclusions list
            Param::NumVersion => "NUM_VERSION",
            Param::DebugPath => "DEBUG_PATH", // dir with prediction.csv (used for debug)
            Param::UtilsPath => "UTILS_PATH", // toast.exe
            Param::AppId => "APP_ID", // AppUserModelID for toast notifications
        }
    }
}

#[derive(Debug)]
pub struct Config {
    params: HashMap<Param, String>,
    pub extensions_list: ExtensionList,
    pub threshold_drivermsgs: usize,
}

impl Config {
    pub fn new() -> Config {
        let mut params: HashMap<Param, String> = HashMap::new();
        for param in Param::iter() {
            let regkey = Hive::LocalMachine
                .open(r"SOFTWARE\Owlyshield", Security::Read)
                .expect("Cannot open registry hive");
            let val = regkey
                .value(Param::convert_to_str(&param))
                .expect(&format!("Cannot open registry key {:?}", param))
                .to_string();
            params.insert(param, val);
        }
        Config {
            params,
            extensions_list: ExtensionList::new(),
            threshold_drivermsgs: 100,
        }
    }
}

impl Index<Param> for Config {
    type Output = String;

    fn index(&self, index: Param) -> &Self::Output {
        &self.params[&index]
    }
}
