use std::collections::HashMap;
use std::ops::Index;
use std::path::{Path, PathBuf};
use configparser::ini::Ini;
#[cfg(target_os = "windows")]
use registry::*;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::extensions::ExtensionList;

#[derive(Debug, EnumIter, PartialEq, Eq, Hash, Clone)]
pub enum Param {
    ProcessActivityLogPath,
    LogPath,
    ConfigPath,
    NumVersion,
    UtilsPath,
    AppId,
    KillPolicy,
    Language,
    Telemetry,
    MqttServer,
    Unknown,
}

#[derive(PartialEq)]
pub enum KillPolicy {
    Suspend,
    Kill,
    DoNothing,
}

impl Param {
    #[cfg(target_os = "windows")]
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "CONFIG_PATH", // incidents reports, exclusions list
            Param::NumVersion => "NUM_VERSION",
            Param::ProcessActivityLogPath => "PROCESS_ACTIVITY_PATH", // dir with prediction.csv (used for debug)
            Param::LogPath => "LOG_PATH", // dir with log files
            Param::UtilsPath => "UTILS_PATH", // toast.exe
            Param::AppId => "APP_ID",         // AppUserModelID for toast notifications
            Param::KillPolicy => "KILL_POLICY", // SUSPEND / KILL
            Param::Language => "LANGUAGE",    // Language used at installation
            Param::Telemetry => "TELEMETRY",  // 1 if telemetry is active, 0 if not
            Param::MqttServer => "MQTT_SERVER",
            _ => "UNKNOWN"
        }
    }

    #[cfg(target_os = "linux")]
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "config_path", // incidents reports, exclusions list
            Param::NumVersion => "num_version",
            Param::ProcessActivityLogPath => "process_activity_path", // dir with prediction.csv (used for debug)
            Param::LogPath => "log_path", // dir with log files
            Param::UtilsPath => "utils_path", // toast.exe
            Param::AppId => "app_id",         // AppUserModelID for toast notifications
            Param::KillPolicy => "kill_policy", // SUSPEND / KILL
            Param::Language => "language",    // Language used at installation
            Param::Telemetry => "telemetry",  // 1 if telemetry is active, 0 if not
            Param::MqttServer => "mqtt_server",
            _ => "unknown"
        }
    }

    fn get_string_vec() -> Vec<String> {
        let mut params = vec![
            Param::KillPolicy,
            Param::ConfigPath,
            Param::LogPath,
            Param::Telemetry,
            Param::NumVersion,
            Param::ProcessActivityLogPath,
            Param::Language,
        ];

        if cfg!(target_os = "windows") {
            params.append(&mut vec![
                Param::AppId,
                Param::UtilsPath,
            ]);
        }
        if cfg!(feature = "mqtt") {
            params.push(Param::MqttServer);
        }

        let mut ret = Vec::new();
        for param in params {
            let val = Self::convert_to_str(&param).to_string();
            ret.push(val);
        }
        ret
    }

    #[cfg(target_os = "windows")]
    fn convert_from_str(param: String) -> Param {
        match param.as_str() {
            "CONFIG_PATH" => Param::ConfigPath, // incidents reports, exclusions list
            "NUM_VERSION" => Param::NumVersion,
            "PROCESS_ACTIVITY_PATH" => Param::ProcessActivityLogPath, // dir with prediction.csv (used for debug)
            "LOG_PATH" => Param::LogPath, // dir with log files
            "UTILS_PATH" => Param::UtilsPath, // toast.exe
            "APP_ID" => Param::AppId,         // AppUserModelID for toast notifications
            "KILL_POLICY" => Param::KillPolicy, // SUSPEND / KILL
            "LANGUAGE" => Param::Language,    // Language used at installation
            "TELEMETRY" => Param::Telemetry,  // 1 if telemetry is active, 0 if not
            "MQTT_SERVER" => Param::MqttServer,
            _ => Param::Unknown,
        }
    }

    #[cfg(target_os = "linux")]
    fn convert_from_str(param: String) -> Param {
        match param.as_str() {
            "config_path" => Param::ConfigPath, // incidents reports, exclusions list
            "num_version" => Param::NumVersion,
            "process_activity_path" => Param::ProcessActivityLogPath, // dir with prediction.csv (used for debug)
            "log_path" => Param::LogPath, // dir with log files
            "utils_path" => Param::UtilsPath, // toast.exe
            "app_id" => Param::AppId,         // AppUserModelID for toast notifications
            "kill_policy" => Param::KillPolicy, // SUSPEND / KILL
            "language" => Param::Language,    // Language used at installation
            "telemetry" => Param::Telemetry,  // 1 if telemetry is active, 0 if not
            "mqtt_server" => Param::MqttServer,
            _ => Param::Unknown,
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
        Config {
            params: Self::get_params(),
            current_exe: std::env::current_exe().unwrap(),
            extensions_list: ExtensionList::new(),
            threshold_drivermsgs: 70,
            threshold_prediction: 0.55,
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

    #[cfg(target_os = "windows")]
    fn get_params() -> HashMap<Param, String> {
        let mut params: HashMap<Param, String> = HashMap::new();
        for param in ConfigReader::read_params_from_registry(Param::get_string_vec(), r"SOFTWARE\Owlyshield") {
            params.insert(Param::convert_from_str(param.0), param.1);
        }
        params
    }

    #[cfg(target_os = "linux")]
    fn get_params() -> HashMap<Param, String> {
        let mut params: HashMap<Param, String> = HashMap::new();
        for param in ConfigReader::read_params_from_file(Param::get_string_vec(), "/etc/owlyshield/owlyshield.conf", "owlyshield") {
            params.insert(Param::convert_from_str(param.0), param.1);
        }
        params
    }
}

impl Index<Param> for Config {
    type Output = String;

    fn index(&self, index: Param) -> &Self::Output {
        &self.params[&index]
    }
}

pub struct ConfigReader {
    // location: String,
}

impl ConfigReader {

    #[cfg(target_os = "windows")]
    pub fn read_param(param: String, location: &str, _bloc: &str) -> String {
        Self::read_param_from_registry(param.as_str(), location)
    }

    #[cfg(target_os = "linux")]
    pub fn read_param(param: String, location: &str, bloc: &str) -> String {
        Self::read_param_from_file(param.as_str(), location, bloc)
    }

    #[cfg(target_os = "windows")]
    pub fn read_params(params: Vec<String>, location: &str, _bloc: &str) -> HashMap<String, String> {
        Self::read_params_from_registry(params, location)
    }

    #[cfg(target_os = "linux")]
    pub fn read_params(params: Vec<String>, location: &str, bloc: &str) -> HashMap<String, String> {
        Self::read_params_from_file(params, location, bloc)
    }

    pub fn read_param_from_file(param: &str, location: &str, bloc: &str) -> String  {
        //"/etc/owlyshield/owlyshield.conf"
        let mut config = Ini::new();
        let _map = config.load(location);
        config.get(bloc, param).unwrap()
    }

    #[cfg(target_os = "windows")]
    pub fn read_param_from_registry(param: &str, location: &str) -> String  {
        let regkey = Hive::LocalMachine
            .open(location, Security::Read)
            .expect("Cannot open registry hive");
        regkey
            .value(param)
            .unwrap_or_else(|_| panic!("Cannot open registry key {param:?}"))
            .to_string()
    }

    fn read_params_from_file(params: Vec<String>, location: &str, bloc: &str) -> HashMap<String, String> {
        let mut ret: HashMap<String, String> = HashMap::new();
        let mut config = Ini::new();
        let _map = config.load(location);

        for param in params {
            let val = config.get(bloc, param.as_str()).unwrap();
            ret.insert(param, val);
        }
        ret
    }

    #[cfg(target_os = "windows")]
    fn read_params_from_registry(params: Vec<String>, location: &str) -> HashMap<String, String> {
        let mut ret: HashMap<String, String> = HashMap::new();
        for param in params {
            let val = Self::read_param_from_registry(param.as_str(), location);
            ret.insert(param, val);
        }
        ret
    }
}
