#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]

use crate::driver_com::shared_def::{CDriverMsgs, C_DriverMsg, DriverMsg};
use crate::prediction::TfLite;
use crate::process::procs::Procs;
use crate::worker::{process_irp, process_irp_deser, save_irp};
use log::{error, info, trace};
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::iter::FromIterator;
use std::os::raw::c_short;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null;
use std::rc::Rc;
use serde::{Deserialize, Serialize};
use std::thread::park_timeout;
use std::time;
use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_128;
use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_INFO;
use serde::{Deserializer, Serializer};
use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;
use widestring::WideString;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::ServiceControlHandlerResult;
use windows_service::{service_control_handler, service_dispatcher};

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

pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join(" ")
}

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
    std::panic::set_hook(Box::new(|pi| {
        error!("Critical error: {}", pi);
        println!("{}", pi);
    }));
    let log_source = "Owlyshield Ransom Rust";
    winlog::register(&log_source);
    winlog::init(&log_source).unwrap_or(());
    info!("Program started.");

    let driver =
        driver_com::Driver::open_kernel_driver_com().expect("Cannot open driver communication");
    println!("{:?}", driver);
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
    .expect("Cannot open exclusions.txt");

    // SAVE_IRP_CSV
    if cfg!(feature = "serialize_irp") {
        println!("SAVE_IRP_CSV");
        let filename =
            &Path::new(&config[config::Param::DebugPath]).join(Path::new("serialized_irp.txt"));
        loop {
            if let Some(reply_irp) = driver.get_irp(&mut vecnew) {
                if reply_irp.num_ops > 0 {
                    let drivermsgs = CDriverMsgs::new(&reply_irp);
                    for drivermsg in drivermsgs {
                        save_irp(&config, &mut procs, filename, &drivermsg);
                    }
                } else {
                    std::thread::sleep(time::Duration::from_millis(100));
                }
            } else {
                panic!("Can't receive IRP?");
            }
        }
    }

    // READ_IRP_CSV & PROCESS
    if cfg!(feature = "deserialize_irp") {
        println!("READ_IRP_CSV");
        let filename =
            &Path::new(&config[config::Param::DebugPath]).join(Path::new("serialized_irp.txt"));
        let mut file = File::open(Path::new(filename)).unwrap();
        let file_len = file.metadata().unwrap().len() as usize;

        let buf_size = 1000;
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(buf_size, 0);
        let mut cursor_index = 0 as usize;

        while cursor_index + buf_size < file_len {
            //TODO ToFix! last 1000 buffer ignored
            buf.fill(0);
            file.seek(SeekFrom::Start(cursor_index as u64)).unwrap();
            file.read_exact(&mut buf).unwrap();
            let mut cursor_record_end = buf_size;
            for i in 0..(buf_size-3) {
                // A strange chain is used to avoid collisions with the windows fileid
                if buf[i] == 255u8 && buf[i + 1] == 0u8 && buf[i + 2] == 13u8 && buf[i + 3] == 10u8
                {
                    cursor_record_end = i;
                    break;
                }
            }
            //let dms: DriverMsg = rmp_serde::from_read_ref(&buf[0..cursor_record_end]).unwrap();
            let res_drivermsg = rmp_serde::from_read_ref(&buf[0..cursor_record_end]);
            match res_drivermsg {
                Ok(drivermsg) => {
                    process_irp_deser(&config, &whitelist, &mut procs, &drivermsg);
                }
                Err(_e) => {
                    println!("Error deserializeing buffer {}", cursor_index); //buffer is too small
                }
            }

            //process_irp_deser(&config, &whitelist, &mut procs, &dms);
            //println!("DMS {:?}", dms);
            cursor_index += cursor_record_end + 4;
        }
    }

    // PROCESS_IRP (Live)
    if cfg!(not(any(
        feature = "serialize_irp",
        feature = "deserialize_irp"
    ))) {
        println!("PROCESS_IRP");
        loop {
            if let Some(reply_irp) = driver.get_irp(&mut vecnew) {
                if reply_irp.num_ops > 0 {
                    let drivermsgs = CDriverMsgs::new(&reply_irp);
                    for drivermsg in drivermsgs {
                        let dm2 = DriverMsg::from(&drivermsg);
                        //println!("{:?}", dm2);
                        let continue_loop =
                            process_irp(&driver, &config, &whitelist, &mut procs, &tflite, &dm2);
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
    }

    //driver.close_kernel_communication();

    //println!("{:?}", config);
    //println!("{:?}", config[config::Param::ApiAddr]);
    //println!("end");
}
