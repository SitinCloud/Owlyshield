//! Interface inherited from [Connector] for Community.
//! This allows the program to communicate with the user through Windows toasts.

use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use chrono::{DateTime, Local};
use curl::easy::Easy;
use log::error;
use registry::{Hive, Security};
use serde::Serialize;

use crate::config::{Config, Param};
use crate::connectors::connector::{Connector, ConnectorError};
use crate::notifications::toast;
use crate::process::ProcessRecord;
use crate::utils::FILE_TIME_FORMAT;

use std::io::Read;

/// Struct of the [Community] interface.
pub struct Community;

impl Community {
    /// Returns the name of the [Community] interface.
    fn name() -> String {
        String::from("Community")
    }

    fn client() -> String {
        let regkey = Hive::LocalMachine
            .open(r"SOFTWARE\Owlyshield\Telemetry", Security::Read)
            .expect("Cannot open registry hive");
        regkey
            .value("CLIENT_ID")
            .unwrap_or_else(|_| panic!("Cannot open registry key CLIENT_ID"))
            .to_string()
    }

    fn username() -> String {
        let regkey = Hive::LocalMachine
            .open(r"SOFTWARE\Owlyshield\Telemetry", Security::Read)
            .expect("Cannot open registry hive");
        regkey
            .value("USER")
            .unwrap_or_else(|_| panic!("Cannot open registry key USER"))
            .to_string()
    }

    fn company() -> String {
        let regkey = Hive::LocalMachine
            .open(r"SOFTWARE\Owlyshield\Telemetry", Security::Read)
            .expect("Cannot open registry hive");
        regkey
            .value("COMPANY")
            .unwrap_or_else(|_| panic!("Cannot open registry key COMPANY"))
            .to_string()
    }

    fn country() -> String {
        let regkey = Hive::LocalMachine
            .open(r"SOFTWARE\Owlyshield\Telemetry", Security::Read)
            .expect("Cannot open registry hive");
        regkey
            .value("COUNTRY")
            .unwrap_or_else(|_| panic!("Cannot open registry key COUNTRY"))
            .to_string()
    }

    fn phone() -> String {
        let regkey = Hive::LocalMachine
            .open(r"SOFTWARE\Owlyshield\Telemetry", Security::Read)
            .expect("Cannot open registry hive");
        regkey
            .value("PHONE")
            .unwrap_or_else(|_| panic!("Cannot open registry key PHONE"))
            .to_string()
    }
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
struct Telemetry {
    clientId: String,
    username: String,
    company: String,
    country: String,
    phone: String,
    hostname: String,
    numVersion: String,
    language: String,
    killPolicy: String,
}

impl Telemetry {
    fn from(config: &Config) -> Telemetry {
        return Telemetry {
            clientId: Community::client(),
            username: Community::username(),
            company: Community::company(),
            country: Community::country(),
            phone: Community::phone(),
            hostname: hostname::get()
                .unwrap()
                .to_str()
                .unwrap_or("Unknown host")
                .to_string(),
            numVersion: config[Param::NumVersion].clone(),
            language: config[Param::Language].clone(),
            killPolicy: config[Param::KillPolicy].clone(),
        };
    }

    fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Implementation of the methods from [Connector] for the [Community] interface.
impl Connector for Community {
    fn to_string(&self) -> String {
        Community::name()
    }

    fn on_startup(&self, config: &Config) -> Result<(), ConnectorError> {
        let toast = match toast(config, "Program Started", "") {
            Ok(()) => "".to_string(),
            Err(e) => e,
        };

        if config[Param::Telemetry].clone() == "1" {
            let event = Telemetry::from(config).to_json();
            eprintln!("event = {:?}", event);
            let mut data = event.as_bytes();
            let mut easy = Easy::new();
            let api_url = "https://api.owlyshield.com/telemetry"; //"telemetry.owlyshield.com";
            easy.url(api_url).unwrap();
            easy.post(true).unwrap();
            easy.post_field_size(data.len() as u64).unwrap();
            let mut transfer = easy.transfer();
            transfer.read_function(|buf| Ok(data.read(buf).unwrap_or(0)))?;

            return match transfer.perform() {
                Ok(()) => {
                    if toast.is_empty() {
                        Ok(())
                    } else {
                        Err(ConnectorError::new(
                            Community::name().as_str(),
                            format!("Connector error: {}", toast).as_str(),
                        ))
                    }
                }
                Err(e) => Err(ConnectorError::new(
                    Community::name().as_str(),
                    format!("Connector error: {}\n{}", toast, e.description()).as_str(),
                )),
            };
        }
        Ok(())
    }

    fn on_event_kill(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        _prediction: f32,
    ) -> Result<(), ConnectorError> {
        let report_dir = Path::new(&config[Param::ConfigPath]).join("threats");
        let now = (DateTime::from(SystemTime::now()) as DateTime<Local>)
            .format(FILE_TIME_FORMAT)
            .to_string();
        let report_path = if !report_dir.exists() {
            PathBuf::from("")
        } else {
            report_dir.join(Path::new(&format!(
                "{}_{}_report_{}.html",
                &proc.appname.replace('.', "_"),
                now,
                &proc.gid,
            )))
        };
        if !report_dir.exists() {
            error!(
                "Cannot read report file: dir does not exist: {}",
                report_dir.to_str().unwrap()
            );
        }
        match toast(
            config,
            &format!("Ransomware detected! {}", proc.appname),
            report_path.to_str().unwrap_or(""),
        ) {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectorError::new(Community::name().as_str(), &e)),
        }
    }
}
