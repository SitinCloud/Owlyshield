use std::fs::File;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime};
use std::sync::mpsc::channel;
use std::io::{Read, Seek, SeekFrom};
use crate::{CDriverMsgs, config, Connectors, Driver, ExepathLive, IOMessage, IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter, Logging, ProcessRecordHandlerLive, whitelist, Worker};
use crate::config::Param;
use crate::threathandling::WindowsThreatHandler;

pub fn run() {
    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        // error!("Critical error: {}", pi);
        println!("{pi}");
        Logging::error(format!("Critical error: {pi}").as_str());
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
                    println!("Error deserializing buffer {cursor_index}"); //buffer is too small
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
                            &config, Box::new(WindowsThreatHandler::from(driver)),
                        )));
                }

                if cfg!(feature = "record") {
                    worker = worker.register_iomsg_postprocessor(Box::new(
                        IOMsgPostProcessorWriter::from(&config),
                    ));
                }

                if cfg!(feature = "jsonrpc") {
                    worker = worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorRPC::new()));
                }

                if cfg!(feature = "mqtt") {
                    worker = worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorMqtt::new(config[Param::MqttServer].clone())));
                }

                worker = worker.build();

                let mut count = 0;
                let mut timer = SystemTime::now();
                loop {
                    let mut iomsg = rx_iomsgs.recv().unwrap();
                    worker.process_io(&mut iomsg);
                    if count > 200 && SystemTime::now().duration_since(timer).unwrap() > Duration::from_secs(3) {
                        worker.process_suspended_records(&config, Box::new(WindowsThreatHandler::from(driver)));
                        count = 0;
                        timer = SystemTime::now();
                    }
                    count += 1;
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
