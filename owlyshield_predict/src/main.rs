//! Owlyshield is an open-source AI-driven behaviour based antiransomware engine designed to run
//!

// #![cfg_attr(debug_assertions, allow(dead_code, unused_imports, unused_variables))]

extern crate num;
#[macro_use]
extern crate num_derive;

#[cfg(feature = "service")]
use std::ffi::OsString; //win
use std::fs::File;
use std::io::Read;
use std::io::{Seek, SeekFrom};
use std::path::Path;
#[cfg(feature = "service")]
use std::sync::mpsc; //win
use std::sync::mpsc::channel; //win et Linux ?
use std::thread;
use std::time::Duration;  //win

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

    run();
}

#[cfg(target_os = "windows")]
fn run() {
    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        // error!("Critical error: {}", pi);
        println!("{}", pi);
        Logging::error(format!("Critical error: {}", pi).as_str());
    }));
    // let log_source = "Owlyshield Ransom Rust 1";
    // winlog::register(log_source);
    // winlog::init(log_source).unwrap_or(());
    // info!("Program started.");
    Logging::start();
    // info!("START");

    let driver = Driver::open_kernel_driver_com()
        .expect("Cannot open driver communication (is the minifilter started?)");
    driver
        .driver_set_app_pid()
        .expect("Cannot set driver app pid");
    let mut vecnew: Vec<u8> = Vec::with_capacity(65536);

    if cfg!(feature = "replay") {
        println!("Replay Driver Messages");
        let config = config::Config::new();
        let whitelist = whitelist::WhiteList::from(
            &Path::new(&config[config::Param::ConfigPath]).join(Path::new("exclusions.txt")),
        )
            .unwrap();
        let mut worker = Worker::new_replay(&config, &whitelist);

        let filename =
            &Path::new(&config[config::Param::DebugPath]).join(Path::new("drivermessages.txt"));
        let mut file = File::open(Path::new(filename)).unwrap();
        let file_len = file.metadata().unwrap().len() as usize;

        let buf_size = 1000;
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(buf_size, 0);
        let mut cursor_index = 0;

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
            match rmp_serde::from_slice(&buf[0..cursor_record_end]) {
                Ok(mut iomsg) => {
                    worker.process_io(&mut iomsg);
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

        let (tx_iomsgs, rx_iomsgs) = channel::<IOMessage>();

        if cfg!(not(feature = "replay")) {
            Connectors::on_startup(&config);

            let (tx_kill, rx_kill) = channel();
            if rx_kill.try_recv().is_ok() {
                let gid_to_kill = rx_kill.try_recv().unwrap();
                let proc_handle = driver.try_kill(gid_to_kill).unwrap();
                // info!("Killed Process with Handle {}", proc_handle.0);
                Logging::alert(format!("Killed Process with Handle {}", proc_handle.0).as_str());
            }

            //NEW
            thread::spawn(move || {
                let whitelist = whitelist::WhiteList::from(
                    &Path::new(&config[config::Param::ConfigPath])
                        .join(Path::new("exclusions.txt")),
                )
                    .expect("Cannot open exclusions.txt");
                whitelist.refresh_periodically();

                let mut worker = Worker::new();

                worker = worker.exepath_handler(Box::new(ExepathLive::default()));

                if cfg!(feature = "malware") {
                    worker = worker
                        .whitelist(&whitelist)
                        .process_record_handler(Box::new(ProcessRecordHandlerLive::new(
                            &config, tx_kill,
                        )));
                }

                if cfg!(feature = "record") {
                    worker = worker.register_iomsg_postprocessor(Box::new(
                        IOMsgPostProcessorWriter::from(&config),
                    ));
                }

                if cfg!(feature = "jsonrpc") {
                    worker = worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorRPC::new()))
                }

                if cfg!(feature = "mqtt") {
                    worker = worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorMqtt::new()));
                }

                worker = worker.build();

                loop {
                    let mut iomsg = rx_iomsgs.recv().unwrap();
                    worker.process_io(&mut iomsg);
                }
            });
        }

        loop {
            if let Some(reply_irp) = driver.get_irp(&mut vecnew) {
                if reply_irp.num_ops > 0 {
                    let drivermsgs = CDriverMsgs::new(&reply_irp);
                    for drivermsg in drivermsgs {
                        let iomsg = IOMessage::from(&drivermsg);
                        if tx_iomsgs.send(iomsg).is_ok() {
                        } else {
                            // error!("Cannot send iomsg");
                            println!("Cannot send iomsg");
                            Logging::error("Cannot send iomsg");
                        }
                    }
                } else {
                    thread::sleep(Duration::from_millis(10));
                }
            } else {
                panic!("Can't receive Driver Message?");
            }
        }
    }
}

#[cfg(target_os = "linux")]
use futures::stream::StreamExt;
#[cfg(target_os = "linux")]
use std::{ffi::CStr, ptr};
#[cfg(target_os = "linux")]
use tracing::Level;
#[cfg(target_os = "linux")]
use tracing_subscriber::FmtSubscriber;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::os::raw::c_char;
#[cfg(target_os = "linux")]
use redbpf::load::Loader;
#[cfg(target_os = "linux")]
use probes::openmonitor::*;
#[cfg(target_os = "linux")]
use psutil::process::Process;
#[cfg(target_os = "linux")]
use lru::LruCache;
#[cfg(target_os = "linux")]
use std::num::NonZeroUsize;

#[cfg(target_os = "linux")]
fn probe_code() -> &'static [u8] {
    include_bytes!(
        // concat!(
        //     env!("CARGO_MANIFEST_DIR"),
        //     "/../target/bpf/programs/openmonitor/openmonitor.elf"
        // )
        "/home/fedora/redbpf_test/target/bpf/programs/openmonitor/openmonitor.elf"
    )
}

#[cfg(target_os = "linux")]
type Buf = [u8; 32];

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn run() {
    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        // error!("Critical error: {}", pi);
        println!("{}", pi);
        Logging::error(format!("Critical error: {}", pi).as_str());
    }));
    Logging::start();
    // info!("START");

    let mut vecnew: Vec<u8> = Vec::with_capacity(65536);

    if cfg!(feature = "replay") {
        println!("Replay Driver Messages");
        let config = config::Config::new();
        let whitelist = whitelist::WhiteList::from(
            &Path::new(&config[config::Param::ConfigPath]).join(Path::new("exclusions.txt")),
        )
            .unwrap();
        let mut worker = Worker::new_replay(&config, &whitelist);

        let filename =
            &Path::new(&config[config::Param::DebugPath]).join(Path::new("drivermessages.txt"));
        let mut file = File::open(Path::new(filename)).unwrap();
        let file_len = file.metadata().unwrap().len() as usize;

        let buf_size = 1000;
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(buf_size, 0);
        let mut cursor_index = 0;

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
            match rmp_serde::from_slice(&buf[0..cursor_record_end]) {
                Ok(mut iomsg) => {
                    worker.process_io(&mut iomsg);
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

        let (tx_iomsgs, rx_iomsgs) = channel::<IOMessage>();

        if cfg!(not(feature = "replay")) {
            Connectors::on_startup(&config);

            let (tx_kill, rx_kill) = channel();
            if rx_kill.try_recv().is_ok() {
                let gid_to_kill = rx_kill.try_recv().unwrap();
                // let proc_handle = driver.try_kill(gid_to_kill).unwrap();
                // TODO KILL gid_to_kill

                // info!("Killed Process with Handle {}", proc_handle.0);
                // Logging::alert(format!("Killed Process with Handle {}", proc_handle.0).as_str());
            }

            //NEW
            thread::spawn(move || {
                let whitelist = whitelist::WhiteList::from(
                    &Path::new(&config[config::Param::ConfigPath])
                        .join(Path::new("exclusions.txt")),
                )
                    .expect("Cannot open exclusions.txt");
                whitelist.refresh_periodically();

                let mut worker = Worker::new();

                worker = worker.exepath_handler(Box::new(ExepathLive::default()));

                if cfg!(feature = "malware") {
                    worker = worker
                        .whitelist(&whitelist)
                        .process_record_handler(Box::new(ProcessRecordHandlerLive::new(
                            &config, tx_kill,
                        )));
                }

                if cfg!(feature = "record") {
                    worker = worker.register_iomsg_postprocessor(Box::new(
                        IOMsgPostProcessorWriter::from(&config),
                    ));
                }

                if cfg!(feature = "jsonrpc") {
                    worker = worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorRPC::new()))
                }

                worker = worker.build();

                loop {
                    let mut iomsg = rx_iomsgs.recv().unwrap();
                    worker.process_io(&mut iomsg);
                }
            });
        }

        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::WARN)
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();

        let mut loaded = Loader::load(probe_code()).expect("error on Loader::load");

        let probenames = vec![
            "vfs_read",
            "vfs_write",
            "vfs_unlink",
            "vfs_rmdir",
            "vfs_symlink",
            "vfs_mkdir",
            "vfs_create",
            "vfs_rename",
        ];

        for probename in probenames {
            let probe = &mut loaded
                .kprobe_mut(probename)
                .expect("error on KProbe::attach_kprobe");
            probe
                .attach_kprobe(probename, 0)
                .expect("error on KProbe::attach_kprobe");
        }

        let mut gid_roots = HashMap::new();
        let mut gids = LruCache::new(NonZeroUsize::new(1024).unwrap());
        let mut filepaths: HashMap<u64, Vec<Buf>> = Default::default();

        let mut paths = LruCache::new(NonZeroUsize::new(1024).unwrap());
        let mut fileaccesses = LruCache::new(NonZeroUsize::new(1024).unwrap());

        while let Some((map_name, events)) = loaded.events.next().await {
            for event in &events {
                if map_name == "filepaths" {
                    let filepath = unsafe { ptr::read(event.as_ptr() as *const FilePath) };
                    println!("FP: {}", filepath.ns);
                    if !filepaths.contains_key(&filepath.ns) {
                        filepaths.insert(filepath.ns, Vec::new());
                    }
                    if filepath.level == usize::MAX {
                        let path = to_paths(&filepaths.get(&filepath.ns).unwrap());
                        paths.push(filepath.ns, path.clone());
                        filepaths.remove(&filepath.ns);
                    } else {
                        filepaths.get_mut(&filepath.ns).unwrap().push(filepath.buf);
                    }
                } else if map_name == "fileaccesses" {
                    let fileaccess = unsafe { ptr::read(event.as_ptr() as *const FileAccess) };
                    fileaccesses.push(fileaccess.ns, fileaccess);
                }
            }

            for (ns, fileaccess) in fileaccesses.iter() {
                if paths.contains(ns) {
                    let mut drivermsg  = LDriverMsg::new();
                    drivermsg.set_filepath(paths.pop_entry(ns).unwrap().1);
                    drivermsg.add_fileaccess(fileaccess);

                    let comm = unsafe { CStr::from_ptr(fileaccess.comm.as_ptr() as *const c_char)
                        .to_string_lossy()
                        .into_owned() };
                    let exepath = unsafe {
                        let slice = std::slice::from_raw_parts(fileaccess.comm.as_ptr() as *const u8, 16);
                        std::str::from_utf8(slice).unwrap()
                    };
                    let pid = (fileaccess.pid & 0xffffffff) as usize;
                    let gid = get_gid(&mut gid_roots, &mut gids, pid);

                    drivermsg.set_gid(gid.try_into().unwrap());
                    drivermsg.set_pid(pid.try_into().unwrap());
                    drivermsg.set_exepath(exepath.to_string());

                    let iomsg = IOMessage::from(&drivermsg);
                    if tx_iomsgs.send(iomsg).is_ok() {
                    } else {
                        println!("Cannot send iomsg");
                        Logging::error("Cannot send iomsg");
                    }
                }
            }
        }
    }
}

// #[cfg(target_os = "linux")]
// fn get_gid(gid_roots: &mut HashMap<usize, usize>, gids: &mut LruCache<usize, usize>, pid: usize) -> usize {
//     if !gids.contains(&pid) {
//         let pid_root = get_pid_root(pid);
//         let gid = match gid_roots.get(&pid_root) {
//             Some(gid) => *gid,
//             None => {
//                 let new_gid = gid_roots.len();
//                 gid_roots.insert(pid_root, new_gid);
//                 new_gid
//             }
//         };
//         gid
//     } else {
//         return *gids.get(&pid).unwrap();
//     }
// }

#[cfg(target_os = "linux")]
fn get_gid(gid_roots: &mut HashMap<usize, usize>, gids: &mut LruCache<usize, usize>, pid: usize) -> Option<usize> {
    if !gids.contains(&pid) {
        if let Some(gid) = get_gid_aux(gid_roots, pid) {
            gids.put(pid, gid);
            Some(gid)
        } else {
            None
        }
    } else {
        Some(*gids.get(&pid).unwrap())
    }
}

#[cfg(target_os = "linux")]
fn get_gid_aux(gid_roots: &mut HashMap<usize, usize>, pid: usize) -> Option<usize> {
    let res_process = Process::new(pid as u32);
    if res_process.is_err() {
        return None;
    }
    let process = res_process.unwrap();
    let res_ppid = process.ppid();
    if res_ppid.is_err() {
        return None;
    }
    if let Some(ppid) = res_ppid.unwrap() {
        if ppid == 1 {
            let new_gid = gid_roots.len();
            gid_roots.insert(pid, new_gid);
            Some(new_gid)
        } else {
            get_gid_aux(gid_roots, ppid as usize)
        }
    } else {
        None
    }
}

// #[cfg(target_os = "linux")]
// #[inline]
// fn get_pid_root(pid: usize) -> usize {
//     let pr_process = Process::new(pid as u32);
//     if pr_process.is_err() {
//         return 0;
//     }
//     let process = pr_process.unwrap();
//     let pr_ppid = process.ppid();
//     if pr_ppid.is_err() {
//         return 0;
//     }
//     let ppid = process.ppid().unwrap().unwrap_or(0) as usize;
//     match ppid {
//         1 => ppid,
//         _ => get_pid_root(ppid),
//     }
// }

#[cfg(target_os = "linux")]
fn to_paths(paths: &Vec<Buf>) -> String {
    paths
        .iter()
        .rev()
        .map(|s| unsafe {
            CStr::from_ptr(s.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<String>>()
        .join("/")
        .to_string()
}
