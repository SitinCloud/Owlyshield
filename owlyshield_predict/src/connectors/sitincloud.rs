//!  Interface inherited from [Connector] for SitinCloud web-app.

use std::collections::HashSet;
use std::io::Read;
use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};
use curl::easy::Easy;
use serde::Serialize;

use crate::config::{Config, ConfigReader, Param};
use crate::connectors::connector::{Connector, ConnectorError};
use crate::process::ProcessRecord;
use crate::logging::Logging;

#[cfg(target_os = "windows")]
const CONF_LOCATION: &str = r"SOFTWARE\Owlyshield\SitinCloud";
#[cfg(target_os = "windows")]
const CONF_BLOC: &str = "";

#[cfg(target_os = "linux")]
const CONF_LOCATION: &str = "/etc/conf/owlyshield.conf";
#[cfg(target_os = "linux")]
const CONF_BLOC: &str = "sitincloud";

/// Struct of the [SitinCloud] interface.
pub struct SitinCloud;

impl SitinCloud {
    /// Returns the name of the [SitinCloud] interface.
    fn name() -> String {
        String::from("SitinCloud")
    }
    /// Returns the username for the [SitinCloud] interface.
    /// The value is stored in the registry of the local machine.
    fn username() -> String {
        let param = "USER";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
    }
    /// Returns the host for the `[SitinCloud] interface.
    /// The value is stored in the registry of the local machine.
    fn host() -> String {
        let param = "API_HOST";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
    }
    /// Returns the client id for the [SitinCloud] interface.
    /// The value is stored in the registry of the local machine.
    fn client() -> String {
        let param = "CLIENT_ID";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
    }
    /// Returns the license key for the [SitinCloud] interface.
    /// The value is stored in the registry of the local machine.
    fn license_key() -> String {
        let param = "LICENSE_KEY";
        ConfigReader::read_param(param.to_string(), CONF_LOCATION, CONF_BLOC)
    }
}

/// Struct expected by the [SitinCloud] interface.
#[derive(Serialize)]
#[allow(non_snake_case)]
struct SecurityEvent {
    appName: String,
    clientId: String,
    hostname: String,
    killTime: String,
    clientKey: String,
    pidsCount: usize,
    predScore: f32,
    startTime: String,
    filesChanged: HashSet<String>,
    filesCreated: HashSet<String>,
    // extensionsRead: HashSet,
    // extensionsWrite: HashSet,
    filesMovedCount: usize,
    // filesCreatedTime: HashSet, // nb files created by time
    // filesUpdatedTime: HashSet, // nb files updated by time
    filesChangedCount: usize,
    filesCreatedCount: usize,
    filesDeletedCount: usize,
    filesRenamedCount: usize,
    secondsSinceLaunch: i64,
    dirWithFilesChanged: HashSet<String>,
    dirWithFilesCreated: HashSet<String>,
    extensionsWriteCount: usize,
    sumWeightReadEntropy: f64,
    sumWeightWriteEntropy: f64,
    filesExtensionChangedCount: usize,
}

impl SecurityEvent {
    /// Creates [SecurityEvent] from [ProcessRecord] and prediction.
    fn from(proc: &ProcessRecord, prediction: f32) -> SecurityEvent {
        let start: DateTime<Utc> = proc.time_started.into();
        let kill: DateTime<Utc> = proc.time_killed.unwrap_or_else(SystemTime::now).into();

        return SecurityEvent {
            appName: proc.appname.clone(),
            clientId: SitinCloud::client(),
            hostname: hostname::get()
                .unwrap()
                .to_str()
                .unwrap_or("Unknown host")
                .to_string(),
            killTime: kill.to_rfc3339_opts(SecondsFormat::Micros, true),
            clientKey: SitinCloud::client(),
            pidsCount: proc.pids.len(),
            predScore: prediction,
            startTime: start.to_rfc3339_opts(SecondsFormat::Micros, true),
            filesChanged: proc.fpaths_updated.clone(),
            filesCreated: proc.fpaths_created.clone(),
            filesMovedCount: proc.files_read.len(), // Files moved ?
            filesChangedCount: proc.files_written.len(),
            filesCreatedCount: proc.files_opened.len(),
            filesDeletedCount: proc.files_deleted.len(),
            filesRenamedCount: proc.files_renamed.len(),
            secondsSinceLaunch: (kill - start).num_seconds() * 10,
            dirWithFilesChanged: proc.dirs_with_files_updated.clone(),
            dirWithFilesCreated: proc.dirs_with_files_created.clone(),
            extensionsWriteCount: proc.extensions_written.count_all(), // duplicate
            sumWeightReadEntropy: proc.entropy_read,
            sumWeightWriteEntropy: proc.entropy_written,
            filesExtensionChangedCount: proc.extensions_read.count_all(), // duplicate
        };
    }

    /// Converts [SecurityEvent] to JSON.
    fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
struct Telemetry {
    clientId: String,
    username: String,
    hostname: String,
    numVersion: String,
    licenseKey: String,
    killPolicy: String,
    language: String,
}

impl Telemetry {
    fn from(config: &Config) -> Telemetry {
        return Telemetry {
            clientId: SitinCloud::client(),
            username: SitinCloud::username(),
            hostname: hostname::get()
                .unwrap()
                .to_str()
                .unwrap_or("Unknown host")
                .to_string(),
            numVersion: config[Param::NumVersion].clone(),
            licenseKey: SitinCloud::license_key(),
            killPolicy: config[Param::KillPolicy].clone(),
            language: config[Param::Language].clone(),
        };
    }

    fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Implementation of the methods from [Connector] for the [SitinCloud] interface.
impl Connector for SitinCloud {
    fn to_string(&self) -> String {
        SitinCloud::name()
    }

    fn on_startup(&self, config: &Config) -> Result<(), ConnectorError> {
        let event = Telemetry::from(config).to_json();
        eprintln!("event = {}", event);
        // log::info!("event = {}", event);
        // log::info!("CONNECT: event = {}", event);
        // Logging::connect(format!("event = {}", event).as_str());
        let mut data = event.as_bytes();
        let mut easy = Easy::new();
        let mut api_url = SitinCloud::host();
        api_url.push_str("/telemetry");
        easy.url(api_url.as_str()).unwrap();
        easy.post(true).unwrap();
        easy.post_field_size(data.len() as u64).unwrap();
        let mut transfer = easy.transfer();
        transfer.read_function(|buf| Ok(data.read(buf).unwrap_or(0)))?;

        match transfer.perform() {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectorError::new(
                SitinCloud::name().as_str(),
                format!("Connector error: {}", e.description()).as_str(),
            )),
        }
    }

    fn on_event_kill(
        &self,
        _config: &Config,
        proc: &ProcessRecord,
        prediction: f32,
    ) -> Result<(), ConnectorError> {
        let event = SecurityEvent::from(proc, prediction).to_json();
        let mut data = event.as_bytes();
        let mut easy = Easy::new();
        let mut api_url = SitinCloud::host();
        api_url.push_str("/security-event");
        easy.url(api_url.as_str()).unwrap();
        easy.post(true).unwrap();
        easy.post_field_size(data.len() as u64).unwrap();
        let mut transfer = easy.transfer();
        transfer.read_function(|buf| Ok(data.read(buf).unwrap_or(0)))?;

        match transfer.perform() {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectorError::new(
                SitinCloud::name().as_str(),
                format!("Connector error: {}", e.description()).as_str(),
            )),
        }
    }
}

impl From<curl::Error> for ConnectorError {
    /// Performs the conversion from [curl::Error] to [ConnectorError].
    fn from(e: curl::Error) -> Self {
        ConnectorError::new(SitinCloud::name().as_str(), e.description())
    }
}
