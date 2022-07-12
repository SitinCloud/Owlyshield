//! Owlyshield is an open-source AI-driven behaviour based antiransomware engine designed to run
//!

#![cfg_attr(debug_assertions, allow(dead_code, unused_imports, unused_variables))]

extern crate num;
#[macro_use]
extern crate num_derive;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::io::{Seek, SeekFrom};
use std::os::raw::c_ulong;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::{thread, time};
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

use log::{error, info};
use sysinfo::SystemExt;
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::{define_windows_service, service_control_handler, service_dispatcher};
use windows_service::service_control_handler::ServiceControlHandlerResult;
use crate::config::KillPolicy;
use crate::connectors::connectors::Connectors;

use crate::driver_com::shared_def::{CDriverMsgs, IOMessage};
use crate::predictions::prediction_malware::TfLiteMalware;
use crate::predictions::prediction_static::TfLiteStatic;
use crate::process::procs::Procs;
use crate::worker::{process_drivermessage, process_drivermessage_replay, process_suspended_procs, record_drivermessage};

mod predictions;
mod actions_on_kill;
mod config;
mod csvwriter;
mod driver_com;
mod extensions;
mod notifications;
mod process;
mod utils;
mod whitelist;
mod worker;
mod connectors;


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

    run();
}

fn run() {
    std::panic::set_hook(Box::new(|pi| {
        error!("Critical error: {}", pi);
        println!("{}", pi);
    }));
    let log_source = "Owlyshield Ransom Rust";
    winlog::register(&log_source);
    winlog::init(&log_source).unwrap_or(());
    info!("Program started.");

    let driver = driver_com::Driver::open_kernel_driver_com()
        .expect("Cannot open driver communication (is the minifilter started?)");
    driver
        .driver_set_app_pid()
        .expect("Cannot set driver app pid");
    let mut vecnew: Vec<u8> = Vec::with_capacity(65536);

    if cfg!(feature = "replay") {
        println!("Replay Driver Messages");
        let config = config::Config::new();
        let mut procs: Procs = Procs::new();
        let tflite_malware = TfLiteMalware::new();
        let filename =
            &Path::new(&config[config::Param::DebugPath]).join(Path::new("drivermessages.txt"));
        let mut file = File::open(Path::new(filename)).unwrap();
        let file_len = file.metadata().unwrap().len() as usize;

        let buf_size = 1000;
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(buf_size, 0);
        let mut cursor_index = 0 as usize;

        while cursor_index + buf_size < file_len {
            // TODO ToFix! last 1000 buffer ignored
            buf.fill(0);
            file.seek(SeekFrom::Start(cursor_index as u64)).unwrap();
            file.read_exact(&mut buf).unwrap();
            let mut cursor_record_end = buf_size;
            for i in 0..(buf_size - 3) {
                // A strange chain is used to avoid collisions with the windows fileid
                if buf[i] == 255u8 && buf[i + 1] == 0u8 && buf[i + 2] == 13u8 && buf[i + 3] == 10u8
                {
                    cursor_record_end = i;
                    break;
                }
            }
            match rmp_serde::from_read_ref(&buf[0..cursor_record_end]) {
                Ok(iomsg) => {
                    process_drivermessage_replay(&config, &mut procs, &tflite_malware, &iomsg);
                }
                Err(_e) => {
                    println!("Error deserializeing buffer {}", cursor_index); //buffer is too small
                }
            }
            cursor_index += cursor_record_end + 4;
        }
    }

    if cfg!(not(feature = "replay")) {
        let config = config::Config::new();

        if cfg!(feature = "malware") {
            println!("\nMALWARE PROTECTION MODE");
        }
        if cfg!(feature = "novelty") {
            println!("\nNOVELTY PROTECTION MODE");
        }
        if cfg!(feature = "record") {
            println!("\nRECORD");
        }
        println!("Interactive - can also work as a service.\n");

        let filename=
            &Path::new(&config[config::Param::DebugPath]).join(Path::new("drivermessages.txt"));
        let mut pids_exepaths: HashMap<c_ulong, PathBuf> = HashMap::new();

        let mut system = sysinfo::System::new_all();
        let kill_policy = config.get_kill_policy();

        let (tx_pred, rx_pred) = channel();

        if cfg!(not(feature = "replay")) {
            Connectors::on_startup(&config);

            let (tx_kill, rx_kill) = channel();
            if rx_kill.try_recv().is_ok() {
                let gid_to_kill = rx_kill.try_recv().unwrap();
                let proc_handle = driver.try_kill(gid_to_kill).unwrap();
                log::info!("Killed Process with Handle {}", proc_handle.0);
            }

            thread::spawn(move || { // Thread creation
                let mut procs: Procs = Procs::new();
                let mut predictions_static: HashMap<String, f32> = HashMap::new();

                let tflite_malware = TfLiteMalware::new();
                let tflite_static = TfLiteStatic::new();
                let config = config::Config::new();

                let whitelist = whitelist::WhiteList::from(
                    &Path::new(&config[config::Param::ConfigPath]).join(Path::new("exclusions.txt")),
                ).expect("Cannot open exclusions.txt");
                whitelist.refresh_periodically();

                let mut iteration = 0;

                loop {
                    let mut iomsg = rx_pred.recv().unwrap();
                    let _process_drivermessage = process_drivermessage(
                        &tx_kill, &config, &whitelist, &mut procs, &mut predictions_static, &tflite_malware, &tflite_static, &mut iomsg,
                    ).is_ok();

                    iteration += 1;
                    if &iteration % 10 == 0 && kill_policy == KillPolicy::Suspend {
                        process_suspended_procs(&tx_kill, &config, &mut procs);
                    }

                    if &iteration % 1000 == 0 && procs.len() > 50 {
                        system.refresh_all();
                        procs.purge(&system);
                    }
                }
            });
        }

        loop {
            if let Some(reply_irp) = driver.get_irp(&mut vecnew) {
                if reply_irp.num_ops > 0 {
                    let drivermsgs = CDriverMsgs::new(&reply_irp);
                    for drivermsg in drivermsgs {
                        if cfg!(feature = "record") {
                            record_drivermessage(filename, &mut pids_exepaths, &drivermsg);
                        }
                        let iomsg = IOMessage::from(&drivermsg);
                        if tx_pred.send(iomsg.clone()).is_ok() {
                            tx_pred.send(iomsg.clone()).unwrap();
                        } else {
                            panic!("{}", tx_pred.send(iomsg.clone()).unwrap_err().to_string());
                        }
                    }
                }
            } else {
                panic!("Can't receive Driver Message?");
            }
        }
    }
}
