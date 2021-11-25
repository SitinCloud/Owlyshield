//! [Connector] allows to decouple connectors modules for interfaces.

use crate::process::ProcessRecord;

use crate::connectors::sitincloud::SitinCloud;
use log::error;
use std::fmt;
use std::error::Error;

/// Contains the methods of the [Connector] interface.
pub trait Connector {
    /// Creates a new [Connector] instance.
    fn new() -> Self where Self: Sized;
    /// Returns the name of the interface.
    fn to_string(&self) -> String;
    /// Send events to the interface.
    fn send_event(&self, proc: &ProcessRecord, prediction: f32) -> Result<(), ConnectorError>;
}

/// Struct containing the list of connectors.
pub struct Connectors {
    connectors: Vec<Box<dyn Connector>>,
}


impl Connectors {
    /// Creates a new [Connectors] list.
    pub fn new() -> Connectors {
        Connectors {
            connectors: Vec::new(),
        }
    }

    /// Adds a [Connector] to [Connectors] list.
    pub fn add<T: 'static +Connector>(&mut self, connector: T) {
        self.connectors.push(Box::new(connector));
    }

    /// Send events using the send_event method of all connectors.
    pub fn send_events(&self, proc: &ProcessRecord, prediction: f32)
    {
        for connector in &self.connectors {
            let result = connector.send_event(proc, prediction);
            match result {
                Ok(result) => result,
                Err(e) => {
                    error!("{}", e.to_string());
                    println!("{}", e.to_string());
                    panic!("{}", e.to_string());
                }
            }
        }
    }
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
        }
    }
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} : {}", self.connector_name, self.details)
    }
}
