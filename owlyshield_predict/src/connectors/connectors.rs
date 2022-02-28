//! [Connectors] allows to manage the list of [Connector].

use crate::process::ProcessRecord;

use log::error;
use std::fmt;
use std::error::Error;
use crate::config::Config;
use crate::connectors::connector::Connector;
use crate::connectors::community::Community;
use crate::connectors::sitincloud::SitinCloud;

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
    pub fn on_startup(config: &Config)
    {
        for connector in Connectors::new() {
            let result = connector.on_startup(config);
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

    /// Launch on_event_kill method of all connectors at threat detection.
    pub fn on_event_kill(config: &Config, proc: &ProcessRecord, prediction: f32)
    {
        for connector in Connectors::new() {
            let result = connector.on_event_kill(config, proc, prediction);
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