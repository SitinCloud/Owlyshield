//! Owlyshield is an open-source AI-driven behaviour based antiransomware engine designed to run
//!

// #![cfg_attr(debug_assertions, allow(dead_code, unused_imports, unused_variables))]

extern crate num;
#[macro_use]
extern crate num_derive;

#[cfg(feature = "service")]
use std::ffi::OsString; //win
#[cfg(feature = "service")]
use std::sync::mpsc; //win
#[cfg(feature = "service")]
use std::time::Duration;

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::service_control_handler::ServiceControlHandlerResult;
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::{define_windows_service, service_control_handler, service_dispatcher};

use crate::connectors::register::Connectors;
#[cfg(target_os = "windows")]
use crate::driver_com::Driver;
#[cfg(target_os = "windows")]
use crate::driver_com::shared_def::{CDriverMsgs, IOMessage};
#[cfg(target_os = "linux")]
use crate::driver_com::shared_def::{LDriverMsg, IOMessage};
use crate::logging::Logging;
use crate::worker::process_record_handling::{ExepathLive, ProcessRecordHandlerLive};
use crate::worker::worker_instance::{IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter, Worker};

mod actions_on_kill;
mod config;
mod connectors;
mod csvwriter;
#[cfg(target_os = "windows")]
#[path = "windows/driver_com.rs"]
mod driver_com;
#[cfg(target_os = "linux")]
#[path = "linux/driver_com.rs"]
mod driver_com;
#[cfg(target_os = "windows")]
#[path = "windows/run.rs"]
mod run;
#[cfg(target_os = "linux")]
#[path = "linux/run.rs"]
mod run;
mod extensions;
mod jsonrpc;
mod logging;
#[cfg(target_os = "windows")]
mod notifications;
mod predictions;
mod process;
mod utils;
mod whitelist;
mod worker;

#[cfg(feature = "service")]
const SERVICE_NAME: &str = "Owlyshield Service";
#[cfg(feature = "service")]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

#[cfg(feature = "service")]
define_windows_service!(ffi_service_main, service_main);

// examples at https://github.com/mullvad/windows-service-rs/tree/master/examples
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn service_main(arguments: Vec<OsString>) {
    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        // error!("Critical error: {}", pi);
        println!("{}", pi);
        Logging::error(format!("Critical error: {}", pi).as_str());
    }));
    // let log_source = "Owlyshield Ransom Rust 2";
    // winlog::register(log_source);
    // winlog::init(log_source).unwrap_or(());
    // info!("Program started.");
    Logging::start();


    if let Err(_e) = run_service(arguments) {
        // error!("Error in run_service.");
        Logging::error("Error in run_service.");
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn run_service(_arguments: Vec<OsString>) -> Result<(), windows_service::Error> {
    let (shutdown_tx, shutdown_rx) = channel();
    let shutdown_tx1 = shutdown_tx.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Interrogate => {
                shutdown_tx.send(()).unwrap();
                // info!("Stop event received");
                Logging::stop();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let next_status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    // Tell the system that the service is running now
    status_handle.set_service_status(next_status)?;

    thread::spawn(move || {
        let t = thread::spawn(move || {
            run();
        })
            .join();
        if t.is_err() {
            shutdown_tx1.send(()).unwrap();
        }
    });

    loop {
        // Poll shutdown event.
        match shutdown_rx.recv_timeout(Duration::from_secs(1)) {
            // Break the loop either upon stop or channel disconnect
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,

            // Continue work if no events were received within the timeout
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        };
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn main() -> Result<(), windows_service::Error> {
    // Register generated `ffi_service_main` with the system and start the service, blocking
    // this thread until the service is stopped.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(feature = "service"))]
fn main() {
    //https://patorjk.com/software/taag/#p=display&f=Bloody&t=Owlyshield
    let banner = r#"

 ▒█████   █     █░ ██▓   ▓██   ██▓  ██████  ██░ ██  ██▓▓█████  ██▓    ▓█████▄
▒██▒  ██▒▓█░ █ ░█░▓██▒    ▒██  ██▒▒██    ▒ ▓██░ ██▒▓██▒▓█   ▀ ▓██▒    ▒██▀ ██▌
▒██░  ██▒▒█░ █ ░█ ▒██░     ▒██ ██░░ ▓██▄   ▒██▀▀██░▒██▒▒███   ▒██░    ░██   █▌
▒██   ██░░█░ █ ░█ ▒██░     ░ ▐██▓░  ▒   ██▒░▓█ ░██ ░██░▒▓█  ▄ ▒██░    ░▓█▄   ▌
░ ████▓▒░░░██▒██▓ ░██████▒ ░ ██▒▓░▒██████▒▒░▓█▒░██▓░██░░▒████▒░██████▒░▒████▓
░ ▒░▒░▒░ ░ ▓░▒ ▒  ░ ▒░▓  ░  ██▒▒▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓  ░░ ▒░ ░░ ▒░▓  ░ ▒▒▓  ▒
  ░ ▒ ▒░   ▒ ░ ░  ░ ░ ▒  ░▓██ ░▒░ ░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░ ░  ░░ ░ ▒  ░ ░ ▒  ▒
░ ░ ░ ▒    ░   ░    ░ ░   ▒ ▒ ░░  ░  ░  ░   ░  ░░ ░ ▒ ░   ░     ░ ░    ░ ░  ░
    ░ ░      ░        ░  ░░ ░           ░   ░  ░  ░ ░     ░  ░    ░  ░   ░
                          ░ ░                                          ░

                                                                By SitinCloud
    "#;
    println!("{}", banner);

    run::run();
}
