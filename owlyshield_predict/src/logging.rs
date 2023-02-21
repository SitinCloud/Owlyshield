use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::time::SystemTime;
use chrono::{DateTime, Local};
use log::{error, warn, info};
use crate::utils::LOG_TIME_FORMAT;
use crate::config::ConfigReader;

#[derive(Copy, Clone)]
enum Status {
    Start, // Program starting
    Stop, // Program stopping
    Alert, // Program detected a malware
    Warning, // Warning in program execution
    Error, // Error in program execution
}

impl Status {
    fn to_str(&self) -> &str {
        match self {
            Status::Start => "START",
            Status::Stop => "STOP",
            Status::Alert => "ALERT",
            Status::Warning => "WARNING",
            Status::Error => "ERROR",
        }
    }
}

pub struct Logging;

impl Logging {

    #[cfg(target_os = "windows")]
    pub fn init() {
        let log_source = "Owlyshield Ransom Rust";
        winlog::register(log_source);
        winlog::init(log_source).unwrap_or(());
    }

    #[cfg(target_os = "linux")]
    pub fn init() {

    }

    /// Log the program start event
    pub fn start() {
        Logging::log(Status::Start, "");
    }

    /// Log the program stop event
    pub fn stop() {
        Logging::log(Status::Stop, "");
    }

    /// Log the detection of malware or suspicious activity
    pub fn alert(message: &str) {
        Logging::log(Status::Alert, message);
    }

    /// Log a warning in the program execution
    pub fn warning(message: &str) {
        Logging::log(Status::Warning, message);
    }

    /// Log an error in the program execution
    pub fn error(message: &str) {
        Logging::log(Status::Error, message);
    }

    #[cfg(target_os = "windows")]
    fn log(status: Status, message: &str) {
        Self::log_in_file(status, message, ConfigReader::read_param_from_registry("LOG_PATH", r"SOFTWARE\Owlyshield").as_str());

        match status.clone() {
            Status::Alert | Status::Warning => { warn!("{}: {}", status.to_str(), message); },
            Status::Error => error!("{}: {}", status.to_str(), message),
            _ => {
                if message.is_empty() {
                    info!("{}", status.to_str());
                } else {
                    info!("{}: {}", status.to_str(), message);
                }
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn log(status: Status, message: &str) {
        let dir: &str = "/var/log/owlyshield";
        Self::log_in_file(status, message, dir);
    }

    fn log_in_file(status: Status, message: &str, dir: &str) {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(Path::new(&dir).join("owlyshield.log"))
            .unwrap();

        let now = (DateTime::from(SystemTime::now()) as DateTime<Local>)
            .format(LOG_TIME_FORMAT)
            .to_string();

        let comment = if message.is_empty() {
            format!("{} localhost owlyshield[{}]: {}", now, std::process::id(), status.to_str())
        } else {
            format!("{} localhost owlyshield[{}]: {}: {}", now, std::process::id(), status.to_str(), message)
        };

        if let Err(e) = writeln!(file, "{comment}") {
            eprintln!("Couldn't write to file: {e}");
            error!("Couldn't write to file: {e}");
        }
    }
}
