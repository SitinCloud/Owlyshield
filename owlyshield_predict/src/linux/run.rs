use lru::LruCache;
use psutil::process::Process;
use std::collections::HashMap;
use std::ffi::CStr;
use std::num::NonZeroUsize;
use std::os::raw::c_char;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use crate::config;
use crate::config::Param;
use crate::threathandling::LinuxThreatHandler;
use crate::whitelist;
use crate::Connectors;
use crate::ExepathLive;
use crate::IOMessage;
use crate::IOMsgPostProcessorMqtt;
use crate::IOMsgPostProcessorRPC;
use crate::IOMsgPostProcessorWriter;
use crate::LDriverMsg;
use crate::Logging;
use crate::ProcessRecordHandlerLive;
use crate::Worker;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::mpsc::channel;
use std::thread;

use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use ebpf_monitor_common::*;
use log::{debug, info, warn};
use tokio::signal;
use tokio::task;

#[tokio::main(flavor = "current_thread")]
pub async fn run() -> Result<(), anyhow::Error> {
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

        let filename = &Path::new(&config[config::Param::ProcessActivityLogPath])
            .join(Path::new("drivermessages.txt"));
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
                            &config,
                            Box::new(LinuxThreatHandler::default()),
                        )));
                }

                if cfg!(feature = "record") {
                    worker = worker.register_iomsg_postprocessor(Box::new(
                        IOMsgPostProcessorWriter::from(&config),
                    ));
                }

                if cfg!(feature = "jsonrpc") {
                    worker =
                        worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorRPC::new()))
                }

                if cfg!(feature = "mqtt") {
                    worker = worker.register_iomsg_postprocessor(Box::new(
                        IOMsgPostProcessorMqtt::new(config[Param::MqttServer].clone()),
                    ));
                }

                worker = worker.build();

                loop {
                    if let Some(mut iomsg) = rx_iomsgs.recv().ok() {
                        worker.process_io(&mut iomsg);
                    }
                }
            });
        }

        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::WARN)
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        #[cfg(debug_assertions)]
            let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../vfs-kprobes/target/bpfel-unknown-none/debug/ebpf-monitor"
        ))?;
        #[cfg(not(debug_assertions))]
            let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../vfs-kprobes/target/bpfel-unknown-none/release/ebpf-monitor"
        ))?;
        if let Err(e) = BpfLogger::init(&mut bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }

        // KPROBES
        // vfs_read vfs_write vfs_unlink vfs_rmdir vfs_symlink vfs_mkdir vfs_create vfs_rename

        let program_vfs_read: &mut KProbe = bpf.program_mut("vfs_read").unwrap().try_into()?;
        program_vfs_read.load()?;
        program_vfs_read.attach("vfs_read", 0)?;

        let program_vfs_write: &mut KProbe = bpf.program_mut("vfs_write").unwrap().try_into()?;
        program_vfs_write.load()?;
        program_vfs_write.attach("vfs_write", 0)?;

        let program_vfs_unlink: &mut KProbe = bpf.program_mut("vfs_unlink").unwrap().try_into()?;
        program_vfs_unlink.load()?;
        program_vfs_unlink.attach("vfs_unlink", 0)?;

        let program_vfs_rmdir: &mut KProbe = bpf.program_mut("vfs_rmdir").unwrap().try_into()?;
        program_vfs_rmdir.load()?;
        program_vfs_rmdir.attach("vfs_rmdir", 0)?;

        let program_vfs_symlink: &mut KProbe =
            bpf.program_mut("vfs_symlink").unwrap().try_into()?;
        program_vfs_symlink.load()?;
        program_vfs_symlink.attach("vfs_symlink", 0)?;

        let program_vfs_mkdir: &mut KProbe = bpf.program_mut("vfs_mkdir").unwrap().try_into()?;
        program_vfs_mkdir.load()?;
        program_vfs_mkdir.attach("vfs_mkdir", 0)?;

        /*
        // There is an issue with vfs_creat which isn't triggered event when creating files.
        let program_vfs_create: &mut KProbe = bpf.program_mut("vfs_create").unwrap().try_into()?;
        program_vfs_create.load()?;
        program_vfs_create.attach("vfs_create", 0)?;
        */

        let program_vfs_rename: &mut KProbe = bpf.program_mut("vfs_rename").unwrap().try_into()?;
        program_vfs_rename.load()?;
        program_vfs_rename.attach("vfs_rename", 0)?;

        // DISPLAY FILEPATHS (There is an issue with some d_name starting with "/" which causes filepaths to contain successive /)

        let mut fileaccesses_events: AsyncPerfEventArray<_> =
            bpf.take_map("FILEACCESSES").unwrap().try_into().unwrap();

        for cpu_id in online_cpus()? {
            let mut gid_roots = HashMap::new();
            let mut gids = LruCache::new(NonZeroUsize::new(1024).unwrap());

            let mut fileaccesses_cpu_buf = fileaccesses_events.open(cpu_id, None)?;
            let tx_thread = tx_iomsgs.clone();
            task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    if let Some(events) = fileaccesses_cpu_buf.read_events(&mut buffers).await.ok()
                    {
                        for i in 0..events.read {
                            let buf: &mut BytesMut = &mut buffers[i];
                            if let Some(str_bytes) = buf.get(FILE_ACCESS_SIZE..) {
                                let _filepath_str: &str =
                                    unsafe { core::str::from_utf8_unchecked(str_bytes) };

                                if let Some(fileaccess_slice) = &buf.get(..FILE_ACCESS_SIZE) {
                                    let fileaccess: FileAccess =
                                        *bytemuck::from_bytes(fileaccess_slice);
                                    let comm = unsafe {
                                        CStr::from_ptr(fileaccess.comm.as_ptr() as *const c_char)
                                            .to_string_lossy()
                                            .into_owned()
                                    };

                                    let mut drivermsg = LDriverMsg::new();

                                    // drivermsg.set_filepath(filepath);
                                    drivermsg.add_fileaccess(&fileaccess);

                                    let pid = (fileaccess.pid & 0xffffffff) as usize;

                                    if let Some((opt_cmdline, gid)) =
                                        get_gid(&mut gid_roots, &mut gids, pid)
                                    {
                                        drivermsg.set_gid(gid.try_into().unwrap());
                                        drivermsg.set_pid(pid.try_into().unwrap());

                                        if let Some(cmdline) = opt_cmdline {
                                            drivermsg.set_exepath(cmdline);
                                        } else {
                                            drivermsg.set_exepath(comm.clone());
                                        }

                                        let iomsg = IOMessage::from(&drivermsg);
                                        if tx_thread.send(iomsg).is_ok() {
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
            });
        }
        info!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
        info!("Exiting...");
    }

    Ok(())
}

fn get_gid(
    gid_roots: &mut HashMap<usize, usize>,
    gids: &mut LruCache<usize, usize>,
    pid: usize,
) -> Option<(Option<String>, usize)> {
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

fn get_gid_aux(
    gid_roots: &mut HashMap<usize, usize>,
    pid: usize,
) -> Option<(Option<String>, usize)> {
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
