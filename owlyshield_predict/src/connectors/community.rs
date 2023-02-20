//! Interface inherited from [Connector] for Community.
//! This allows the program to communicate with the user through Windows toasts.

use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use chrono::{DateTime, Local};
use curl::easy::Easy;
use log::error;
use serde::Serialize;

use crate::config::{Config, ConfigReader, Param};
use crate::connectors::connector::{Connector, ConnectorError};
use crate::notifications::notify;
use crate::process::ProcessRecord;
use crate::utils::FILE_TIME_FORMAT;
use crate::logging::Logging;

use std::io::Read;

#[cfg(target_os = "windows")]
const CONF_LOCATION: &str = r"SOFTWARE\Owlyshield\Telemetry";
#[cfg(target_os = "windows")]
const CONF_BLOC: &str = "";

#[cfg(target_os = "linux")]
const CONF_LOCATION: &str = "/etc/owlyshield/owlyshield.conf";
#[cfg(target_os = "linux")]
const CONF_BLOC: &str = "telemetry";

/// Struct of the [Community] interface.
pub struct Community;

impl Community {
    /// Returns the name of the [Community] interface.
    fn name() -> String {
        String::from("Community")
    }

    fn client() -> String {
        let param = "CLIENT_ID";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
    }

    fn username() -> String {
        let param = "USER";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
    }

    fn company() -> String {
        let param = "COMPANY";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
    }

    fn country() -> String {
        let param = "COUNTRY";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
    }

    fn phone() -> String {
        let param = "PHONE";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
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
        let toast = match notify(config, "Program Started", "") {
            Ok(()) => "".to_string(),
            Err(e) => e,
        };

        if config[Param::Telemetry].clone() == "1" {
            let event = Telemetry::from(config).to_json();
            eprintln!("event = {:?}", event);
            // Logging::connect(format!("event = {:?}", event).as_str());
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
                    if toast == "" {
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
            Logging::error(format!("Cannot read report file: dir does not exist: {}", report_dir.to_str().unwrap()).as_str());
        }
        match notify(
            config,
            &format!("Ransomware detected! {}", proc.appname),
            report_path.to_str().unwrap_or(""),
        ) {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectorError::new(Community::name().as_str(), &e)),
        }
    }
}
