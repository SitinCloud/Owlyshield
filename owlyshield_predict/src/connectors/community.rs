//! Interface inherited from [Connector] for Community.
//! This allows the program to communicate with the user through Windows toasts.

use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use chrono::{DateTime, Local};
use log::error;

use crate::config::{Config, Param};
use crate::connectors::connector::{Connector, ConnectorError};
use crate::notifications::toast;
use crate::process::ProcessRecord;
use crate::utils::FILE_TIME_FORMAT;

/// Struct of the [Community] interface.
pub struct Community;

impl Community {
    /// Returns the name of the [Community] interface.
    fn name() -> String {
        String::from("Community")
    }
}

/// Implementation of the methods from [Connector] for the [Community] interface.
impl Connector for Community {
    fn to_string(&self) -> String {
        return Community::name();
    }

    fn on_startup(&self, config: &Config) -> Result<(), ConnectorError> {
        match toast(&config, &"Program Started", "") {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectorError::new(Community::name().as_str(), &e)),
        }
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
                &proc.appname.replace(".", "_"),
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
