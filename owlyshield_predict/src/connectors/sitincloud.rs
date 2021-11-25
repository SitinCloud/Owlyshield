//!  Interface inherited from [Connector] for SitinCloud web-app.

use std::collections::HashSet;
use std::time::SystemTime;
use chrono::{DateTime, SecondsFormat, Utc};
use curl::easy::Easy;
use serde::Serialize;
use std::io::Read;
use curl::Error;
use registry::{Hive, RegKey, Security};

use crate::connectors::connector::{Connector, ConnectorError};
use crate::process::{FileId, ProcessRecord};

/// Struct of the [SitinCloud] interface.
pub struct SitinCloud;

impl SitinCloud {
    /// Returns the name of the [SitinCloud] interface.
    fn get_name() -> String {
        String::from("SitinCloud")
    }
    /// Returns the host for the `[SitinCloud] interface.
    /// The value is stored in the registry of the local machine.
    fn get_host() -> String {
        let regkey = Hive::LocalMachine.open(r"SOFTWARE\Owlyshield\SitinCloud", Security::Read).expect("Cannot open registry hive");
        return regkey.value("HOST").expect(&format!("Cannot open registry key HOST")).to_string();
    }
    /// Returns the client id for the [SitinCloud] interface.
    /// The value is stored in the registry of the local machine.
    fn get_client() -> String {
        let regkey = Hive::LocalMachine.open(r"SOFTWARE\Owlyshield\SitinCloud", Security::Read).expect("Cannot open registry hive");
        return regkey.value("CLIENT_ID").expect(&format!("Cannot open registry key HOST")).to_string();
    }
}

/// Struct expected by the [SitinCloud] interface.
#[derive(Serialize)]
#[allow(non_snake_case)]
struct SecurityEvent {
    appName: String,
    clientId: String,
    hostname: String,
    killTime : String,
    clientKey: String,
    pidsCount: usize,
    predScore : f32,
    startTime: String,
    filesChanged : HashSet<String>,
    filesCreated: HashSet<String>,
    //extensionsRead: HashSet,
    //extensionsWrite: HashSet,
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
        let kill: DateTime<Utc> = proc.time_killed.unwrap().into();
        let now: DateTime<Utc> = SystemTime::now().into();

        return SecurityEvent {
            appName: proc.appname.clone(),
            clientId: SitinCloud::get_client(),
            hostname: hostname::get().unwrap().to_str().unwrap_or("Unknown host").to_string(),
            killTime: kill.to_rfc3339_opts(SecondsFormat::Micros, true),
            clientKey: SitinCloud::get_client(),
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
            secondsSinceLaunch: (kill-start).num_seconds()*10,
            dirWithFilesChanged: proc.dirs_with_files_updated.clone(),
            dirWithFilesCreated: proc.dirs_with_files_created.clone(),
            extensionsWriteCount: proc.extensions_written.count_all(), // doublon
            sumWeightReadEntropy: proc.entropy_read,
            sumWeightWriteEntropy: proc.entropy_written,
            filesExtensionChangedCount: proc.extensions_read.count_all(), // doublon
        }
    }

    /// Converts [SecurityEvent] to JSON.
    fn to_json(&self) -> String {
        return serde_json::to_string(&self).unwrap_or("{}".to_string());
    }
}

/// Implementation of the methods from [Connector] for the [SitinCloud] interface.
impl Connector for SitinCloud {
    fn new() -> SitinCloud {
        SitinCloud {}
    }

    fn to_string(&self) -> String {
        return SitinCloud::get_name();
    }

    fn send_event(&self, proc: &ProcessRecord, prediction: f32) -> Result<(), ConnectorError> {
        let host = "";
        let error = ConnectorError::new(SitinCloud::get_name().as_str(), "Connector error");

        let event = SecurityEvent::from(proc, prediction).to_json();
        let mut data = event.as_bytes();
        let mut easy = Easy::new();
        easy.url(SitinCloud::get_host().as_str()).unwrap();
        easy.post(true).unwrap();
        easy.post_field_size(data.len() as u64).unwrap();
        let mut transfer = easy.transfer();
        // match
        transfer.read_function(|buf| {
            Ok(data.read(buf).unwrap_or(0))
        })?;

        match transfer.perform() {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectorError::new(SitinCloud::get_name().as_str(), "Connector error")),
        }
    }
}

impl From<curl::Error> for ConnectorError {
    /// Performs the conversion from [curl::Error] to [ConnectorError].
    fn from(e: curl::Error) -> Self {
        ConnectorError::new(SitinCloud::get_name().as_str(), e.description())
    }
}