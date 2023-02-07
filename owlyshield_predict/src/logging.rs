use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::time::SystemTime;
use chrono::{DateTime, Local};
use log::error;
use registry::{Hive, Security};
use crate::utils::LOG_TIME_FORMAT;

enum Status {
    Start, // Program starting
    Stop, // Program stopping
    Alert, // Program detected a malware
    // Warning, // Warning in program execution
    Error, // Error in program execution
}

impl Status {
    fn to_str(&self) -> &str {
        match self {
            Status::Start => "START",
            Status::Stop => "STOP",
            Status::Alert => "ALERT",
            // Status::Warning => "WARNING",
            Status::Error => "ERROR",
        }
    }
}

pub struct Logging;

impl Logging {
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

    // /// Log a warning in the program execution
    // pub fn warning(message: &str) {
    //     Logging::log(Status::Warning, message);
    // }

    /// Log an error in the program execution
    pub fn error(message: &str) {
        Logging::log(Status::Error, message);
    }

    fn log(status: Status, message: &str) {
        let regkey = Hive::LocalMachine
            .open(r"SOFTWARE\Owlyshield", Security::Read)
            .expect("Cannot open registry hive");
        let dir = regkey
            .value("LOG_PATH")
            .unwrap_or_else(|_| panic!("Cannot open registry key LOG_PATH"))
            .to_string();

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
            error!("Couldn't write to file: {}", e);
        }
    }
}