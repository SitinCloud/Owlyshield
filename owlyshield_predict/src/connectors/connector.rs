//! [Connector] allows to decouple connectors modules for interfaces.
//! Implements the methods of the [Connector] trait to create your interface.

use crate::process::ProcessRecord;

use crate::config::Config;
use log::error;
use std::error::Error;
use std::fmt;

/// Contains the methods of the [Connector] interface.
pub trait Connector {
    /// Returns the name of the interface.
    fn to_string(&self) -> String;
    /// Actions on service startup
    fn on_startup(&self, config: &Config) -> Result<(), ConnectorError>;
    /// Send events to the interface.
    fn on_event_kill(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        prediction: f32,
    ) -> Result<(), ConnectorError>;
}

/// Struct containing a custom error for [Connector] type.
pub struct ConnectorError {
    connector_name: String,
    details: String,
}

impl ConnectorError {
    pub fn new(n: &str, d: &str) -> ConnectorError {
        return ConnectorError {
            connector_name: n.to_string(),
            details: d.to_string(),
        };
    }
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} : {}", self.connector_name, self.details)
    }
}
