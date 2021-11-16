use std::error::Error;
use crate::process::ProcessRecord;

pub trait Connector {
    fn send_event(sec_event: &SecurityEvent) -> Result<(), ConnectorError>;
    // fn try_send_event(sec_event: &SecurityEvent) -> Future<Output=Result<(), Box<dyn Error>>>;
}

pub struct ConnectorError {
    pub details: String,
}

pub struct SecurityEvent {

}

impl ConnectorError {
    pub fn new(s: &str) -> ConnectorError {
        todo!()
    }
}

impl SecurityEvent {
    fn from(proc: &ProcessRecord) -> SecurityEvent {
        todo!()
    }
}
