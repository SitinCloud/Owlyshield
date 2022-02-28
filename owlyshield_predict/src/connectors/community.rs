//! Interface inherited from [Connector] for Community.
//! This allows the program to communicate with the user through Windows toasts.

use std::collections::HashSet;
use std::time::SystemTime;
use chrono::{DateTime, Local, SecondsFormat, Utc};
use curl::easy::Easy;
use serde::Serialize;
use std::io::Read;
use std::path::Path;
use curl::Error;
use registry::{Hive, RegKey, Security};
use log::error;
use crate::config::{Config, Param};

use crate::connectors::connector::{Connector, ConnectorError};
use crate::process::{FileId, ProcessRecord};
use crate::utils::FILE_TIME_FORMAT;

use std::ptr::null_mut;

use bindings::Windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, PWSTR};
use bindings::Windows::Win32::Security::*;
use bindings::Windows::Win32::System::Diagnostics::Debug::GetLastError;
use bindings::Windows::Win32::System::RemoteDesktop::*;
use bindings::Windows::Win32::System::Threading::CreateProcessAsUserW;
use bindings::Windows::Win32::System::Threading::CREATE_NEW_CONSOLE;
use bindings::Windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};
use widestring::{U16CString, UCString};
use std::process::Command;

use std::path::PathBuf;
use crate::notifications::toast;

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
    // fn new() -> Community {
    //     Community {}
    // }

    fn to_string(&self) -> String {
        return Community::name();
    }

    fn on_startup(&self, config: &Config) -> Result<(), ConnectorError> {
        match toast(&config, &"Program Started", "") {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectorError::new(Community::name().as_str(), &e)),
        }
    }

    fn on_event_kill(&self, config: &Config, proc: &ProcessRecord, prediction: f32) -> Result<(), ConnectorError> {
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
        match toast(config, &format!("Ransomware detected! {}", proc.appname), report_path.to_str().unwrap_or("")) {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectorError::new(Community::name().as_str(), &e)),
        }
    }
}