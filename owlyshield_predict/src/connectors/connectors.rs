//! [Connectors] allows to manage the list of [Connector].

use crate::process::ProcessRecord;

use crate::config::Config;
use crate::connectors::community::Community;
use crate::connectors::connector::Connector;
use crate::connectors::sitincloud::SitinCloud;
use log::error;
use std::error::Error;
use std::fmt;

/// Struct initializing the list of connectors and managing launch events.
pub struct Connectors;

impl Connectors {
    /// Initialize the list of [Connector]
    ///
    /// Add your custom connector in the Vec array.
    ///
    /// # Example
    /// Basic usage:
    /// ```
    /// vec![
    ///     Box::new(MyConnector),
    /// ]
    /// ```
    /// Where `MyConnector` is a struct implementing the [Connector] trait.
    fn new() -> Vec<Box<dyn Connector>> {
        vec![
            Box::new(Community),
            // Box::new(SitinCloud),
            // Box::new(MyConnector),
        ]
    }

    /// Launch on_startup method of all connectors at service startup.
    pub fn on_startup(config: &Config) {
        for connector in Connectors::new() {
            let on_startup = connector.on_startup(config);
            match on_startup {
                Ok(on_startup) => on_startup,
                Err(e) => {
                    error!("{}", e.to_string());
                    println!("{}", e.to_string());
                    // panic!("{}", e.to_string());
                }
            }
        }
    }

    /// Launch on_event_kill method of all connectors at threat detection.
    pub fn on_event_kill(config: &Config, proc: &ProcessRecord, prediction: f32) {
        for connector in Connectors::new() {
            let on_event_kill = connector.on_event_kill(config, proc, prediction);
            match on_event_kill {
                Ok(on_event_kill) => on_event_kill,
                Err(e) => {
                    error!("{}", e.to_string());
                    println!("{}", e.to_string());
                    // panic!("{}", e.to_string());
                }
            }
        }
    }
}
