use futures::stream::StreamExt;
use std::{ffi::CStr, ptr};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use std::collections::HashMap;
use std::os::raw::c_char;
use redbpf::load::Loader;
use probes::openmonitor::*;
use psutil::process::Process;
use lru::LruCache;
use std::num::NonZeroUsize;

use crate::Logging;
use crate::config;
use crate::whitelist;
use std::path::Path;
use crate::Worker;
use std::fs::File;
use std::io::{Seek, SeekFrom, Read};
use std::sync::mpsc::channel;
use crate::IOMessage;
use crate::Connectors;
use crate::ExepathLive;
use crate::ProcessRecordHandlerLive;
use crate::IOMsgPostProcessorWriter;
use crate::IOMsgPostProcessorRPC;
use crate::IOMsgPostProcessorMqtt;
use crate::LDriverMsg;
use std::thread;
use crate::config::Param;
use crate::driver_com::Buf;
use crate::threathandling::LinuxThreatHandler;



fn probe_code() -> &'static [u8] {
    include_bytes!(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/target/bpf/programs/openmonitor/openmonitor.elf"
            )
        // "/home/fedora/redbpf_test/target/bpf/programs/openmonitor/openmonitor.elf"
        )
}

#[tokio::main(flavor = "current_thread")]
pub async fn run() {
    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        // error!("Critical error: {}", pi);
        println!("{}", pi);
        Logging::error(format!("Critical error: {}", pi).as_str());
    }));
    Logging::start();
    // info!("START");

    if cfg!(feature = "replay") {
        println!("Replay Driver Messages");
        let config = config::Config::new();
        let whitelist = whitelist::WhiteList::from(
            &Path::new(&config[config::Param::ConfigPath]).join(Path::new("exclusions.txt")),
            )
            .unwrap();
        let mut worker = Worker::new_replay(&config, &whitelist);

        let filename =
            &Path::new(&config[config::Param::ProcessActivityLogPath]).join(Path::new("drivermessages.txt"));
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
                    println!("Error deserializing buffer {}", cursor_index); //buffer is too small
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
                                    &config, Box::new(LinuxThreatHandler::default()),
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
                    worker = worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorMqtt::new(config[Param::MqttServer].clone())));
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

        while let Some((map_name, events)) = loaded.events.next().await {
            for event in &events {
                if map_name == "fileaccesses" {
                    let array = unsafe { ptr::read(event.as_ptr() as *const [u8; 1024]) };
                    let skip_idx = FILE_ACCESS_SIZE - 1;
                    let null_index = array.iter().skip(skip_idx).position(|&x| x == 0).unwrap_or(1024);
                    let valid_slice = &array[skip_idx..null_index+skip_idx];
                    let as_str = std::str::from_utf8(valid_slice).unwrap();
                    let without_trailing_slashes = as_str.trim_end_matches('/');
                    let split_parts: Vec<&str> = without_trailing_slashes.split('/').collect();
                    let reversed_parts: Vec<&str> = split_parts.into_iter().rev().collect();
                    let filepath = reversed_parts.join("/");

                    let fileaccess_slice = &array[..FILE_ACCESS_SIZE];
                    let fileaccess: FileAccess = *bytemuck::from_bytes(fileaccess_slice);
                    let comm = unsafe { CStr::from_ptr(fileaccess.comm.as_ptr() as *const c_char).to_string_lossy().into_owned() };

                    let mut drivermsg  = LDriverMsg::new();

                    drivermsg.set_filepath(filepath);
                    drivermsg.add_fileaccess(&fileaccess);

                    let pid = (fileaccess.pid & 0xffffffff) as usize;

                    if let Some((opt_cmdline, gid)) = get_gid(&mut gid_roots, &mut gids, pid) {     
                        drivermsg.set_gid(gid.try_into().unwrap());
                        drivermsg.set_pid(pid.try_into().unwrap());

                        if let Some(cmdline) = opt_cmdline {
                            drivermsg.set_exepath(cmdline);
                        } else {
                            drivermsg.set_exepath(comm.clone());
                        }

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
}

fn get_gid(gid_roots: &mut HashMap<usize, usize>, gids: &mut LruCache<usize, usize>, pid: usize) -> Option<(Option<String>, usize)> {
    if !gids.contains(&pid) {
        if let Some((opt_cmdline, gid)) = get_gid_aux(gid_roots, pid) {
            gids.put(pid, gid);
            Some((opt_cmdline, gid))
        } else {
            None
        }
    } else {
        Some((None, *gids.get(&pid).unwrap()))
    }
}

fn get_gid_aux(gid_roots: &mut HashMap<usize, usize>, pid: usize) -> Option<(Option<String>, usize)> {
    let res_process = Process::new(pid as u32);
    if res_process.is_err() {
        return None;
    }
    let process = res_process.unwrap();
    let res_ppid = process.ppid();
    if res_ppid.is_err() {
        return None;
    }
    let res_cmdline = process.cmdline();
    if let Some(ppid) = res_ppid.unwrap() {
        if ppid == 1 {
            let new_gid = gid_roots.len();
            gid_roots.insert(pid, new_gid);
            if res_cmdline.is_ok() {
                if let Some(cmdline) = res_cmdline.unwrap() {
                    Some((Some(cmdline), new_gid))
                } else {
                    Some((None, new_gid))
                }
            } else {
                Some((None, new_gid))
            }
        } else {
            get_gid_aux(gid_roots, ppid as usize)
        }
    } else {
        None
    }
}

