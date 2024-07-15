use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use tokio::task;
use bytes::BytesMut;
use ebpf_monitor_common::*;


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

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
        "../../target/bpfel-unknown-none/debug/ebpf-monitor"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf-monitor"
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
    
    let program_vfs_symlink: &mut KProbe = bpf.program_mut("vfs_symlink").unwrap().try_into()?;
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

    let mut fileaccesses_events : AsyncPerfEventArray<_> = bpf.take_map("FILEACCESSES").unwrap().try_into().unwrap();

    for cpu_id in online_cpus()? {
        
        let mut fileaccesses_cpu_buf = fileaccesses_events.open(cpu_id, None)?; 

        task::spawn(async move {
            let mut buffers = (0..10)
            .map(|_| BytesMut::with_capacity(1024))    
            .collect::<Vec<_>>();
            
            loop {
                let events = fileaccesses_cpu_buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf: &mut BytesMut = &mut buffers[i];
                    if let Some(str_bytes) = buf.get(FILE_ACCESS_SIZE..) {
                        let fileaccess: &str = unsafe {core::str::from_utf8_unchecked(str_bytes)};
                        // dbg!(fileaccess);
                        // info!("{}", fileaccess);
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
