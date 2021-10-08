#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]

use crate::driver_com::shared_def::{DriverMsg, DriverMsgs};
use crate::prediction::TfLite;
use crate::process::procs::Procs;
use crate::worker::process_irp;
use log::{error, info, trace};
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::ffi::OsString;
use std::path::Path;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread::park_timeout;
use std::time;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

mod actions_on_kill;
mod config;
mod csvwriter;
mod driver_com;
mod extensions;
mod notifications;
mod prediction;
mod process;
mod utils;
mod whitelist;
mod worker;

extern crate num;
#[macro_use]
extern crate num_derive;

#[cfg(feature = "service")]
const SERVICE_NAME: &str = "Owlyshield Service";
#[cfg(feature = "service")]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

#[cfg(feature = "service")]
define_windows_service!(ffi_service_main, service_main);

// examples at https://github.com/mullvad/windows-service-rs/tree/master/examples
#[cfg(feature = "service")]
fn service_main(arguments: Vec<OsString>) {
    std::panic::set_hook(Box::new(|pi| {
        error!("Critical error: {}", pi);
        println!("{}", pi);
    }));
    let log_source = "Owlyshield Ransom Rust";
    winlog::register(&log_source);
    winlog::init(&log_source).unwrap_or(());
    info!("Program started.");

    if let Err(_e) = run_service(arguments) {
        error!("Error in run_service.");
    }
}

#[cfg(feature = "service")]
fn run_service(arguments: Vec<OsString>) -> Result<(), windows_service::Error> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let shutdown_tx1 = shutdown_tx.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Interrogate => {
                shutdown_tx.send(()).unwrap();
                info!("Stop event received");
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

    std::thread::spawn(move || {
        let t = std::thread::spawn(move || {
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

    // Do some work
    Ok(())
}

#[cfg(feature = "service")]
fn main() -> Result<(), windows_service::Error> {
    // Register generated `ffi_service_main` with the system and start the service, blocking
    // this thread until the service is stopped.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(feature = "service"))]
fn main() {
    run();
}

fn run() {
    std::panic::set_hook(Box::new(move |pi| {
        error!("Critical error: {}", pi);
        println!("{}", pi);
    }));
    let log_source = "Owlyshield Ransom Rust";
    winlog::register(&log_source);
    winlog::init(&log_source).unwrap_or(());
    info!("Program started.");

    let driver =
        driver_com::Driver::open_kernel_driver_com().expect("Cannot open driver communication");
    driver
        .driver_set_app_pid()
        .expect("Cannot set driver app pid");
    let mut vecnew: Vec<u8> = Vec::with_capacity(65536);
    let mut procs: Procs = Procs::new();

    let tflite = TfLite::new(21, 10);
    let config = config::Config::new();
    let whitelist = whitelist::WhiteList::from(
        &Path::new(&config[config::Param::ConfigPath]).join(Path::new("exclusions.txt")),
    )
    .unwrap();

    loop {
        if let Some(reply_irp) = driver.get_irp(&mut vecnew) {
            if reply_irp.num_ops > 0 {
                let drivermsgs = DriverMsgs::new(&reply_irp);
                for x in drivermsgs {
                    //println!("{:?}", x);
                    let continue_loop =
                        process_irp(&driver, &config, &whitelist, &mut procs, &tflite, &x);
                    if !continue_loop {
                        break;
                    }
                }
            } else {
                std::thread::sleep(time::Duration::from_millis(100));
            }
        } else {
            panic!("Can't receive IRP?");
        }
    }

    //driver.close_kernel_communication();

    //println!("{:?}", config);
    //println!("{:?}", config[config::Param::ApiAddr]);
    //println!("end");
}
