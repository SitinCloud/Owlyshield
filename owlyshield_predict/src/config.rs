use std::collections::HashMap;
use std::ops::Index;
use std::path::{Path, PathBuf};

use registry::*;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::extensions::ExtensionList;

#[derive(Debug, EnumIter, PartialEq, Eq, Hash, Clone)]
pub enum Param {
    DebugPath,
    ConfigPath,
    NumVersion,
    UtilsPath,
    AppId,
    KillPolicy,
}

#[derive(PartialEq)]
pub enum KillPolicy {
    Suspend,
    Kill,
    DoNothing,
}

impl Param {
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "CONFIG_PATH", // incidents reports, exclusions list
            Param::NumVersion => "NUM_VERSION",
            Param::DebugPath => "DEBUG_PATH", // dir with prediction.csv (used for debug)
            Param::UtilsPath => "UTILS_PATH", // toast.exe
            Param::AppId => "APP_ID",         // AppUserModelID for toast notifications
            Param::KillPolicy => "KILL_POLICY", // SUSPEND / KILL
        }
    }
}

#[derive(Debug)]
pub struct Config {
    params: HashMap<Param, String>,
    current_exe: PathBuf,
    pub extensions_list: ExtensionList,
    pub threshold_drivermsgs: usize,
    pub threshold_prediction: f32,
    pub timesteps_stride: usize,
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
                .unwrap_or_else(|_| panic!("Cannot open registry key {:?}", param))
                .to_string();
            params.insert(param, val);
        }
        Config {
            params,
            current_exe: std::env::current_exe().unwrap(),
            extensions_list: ExtensionList::new(),
            threshold_drivermsgs: 100,
            threshold_prediction: 0.65,
            timesteps_stride: 20,
        }
    }

    pub fn model_path(&self, model_name: &str) -> PathBuf {
        let models_dir = self.current_exe.parent().unwrap();
        models_dir.join(Path::new(model_name))
    }

    pub fn get_kill_policy(&self) -> KillPolicy {
        match self[Param::KillPolicy].as_str() {
            "KILL" => KillPolicy::Kill,
            "SUSPEND" => KillPolicy::Suspend,
            &_ => KillPolicy::DoNothing,
        }
    }
}

impl Index<Param> for Config {
    type Output = String;

    fn index(&self, index: Param) -> &Self::Output {
        &self.params[&index]
    }
}
