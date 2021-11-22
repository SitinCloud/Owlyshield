use std::collections::HashSet;
use std::os::raw::{c_ulong, c_ulonglong};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::SystemTime;

use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_128;
use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_INFO;
use log::debug;
use slc_paths::clustering::clustering;
use sysinfo::{System, Pid, ProcessExt, ProcessStatus, SystemExt};

use crate::config::Config;
use crate::csvwriter::CsvWriter;
use crate::driver_com::shared_def::*;
use crate::driver_com::IrpMajorOp;
use crate::extensions::ExtensionsCount;
use crate::prediction::predmtrx::{PredictionRow, VecvecCapped, VecvecCappedF32};
use crate::prediction::{Predictions, TfLite};
use crate::prediction::{PREDMTRXCOLS, PREDMTRXROWS};

#[derive(Debug)]
pub struct ProcessRecord<'a> {
    pub appname: String,
    pub gid: c_ulonglong,
    pub pids: HashSet<c_ulong>,
    pub total_ops_r: u64,
    pub total_ops_rn: u64,
    pub total_ops_w: u64,
    pub total_ops_c: u64,
    pub total_bytes_r: u64,
    pub total_bytes_w: u64,
    pub sum_entropy_weight_r: f64,
    pub sum_entropy_weight_w: f64,
    pub file_ids_r: HashSet<FileId>,
    pub file_ids_rn: HashSet<FileId>,
    pub file_ids_c: HashSet<FileId>,
    pub file_ids_w: HashSet<FileId>,
    pub file_ids_d: HashSet<FileId>,
    pub file_paths_c: HashSet<String>,
    pub file_paths_u: HashSet<String>,
    pub dir_with_files_c: HashSet<String>,
    pub dir_with_files_u: HashSet<String>,
    pub dir_with_files_o: HashSet<String>,
    pub extensions_count_r: ExtensionsCount<'a>,
    pub extensions_count_w: ExtensionsCount<'a>,
    pub exepath: PathBuf,
    pub exe_still_exists: bool,
    pub is_malicious: bool,
    pub time_started: SystemTime,
    pub time_killed: Option<SystemTime>,
    pub nb_clusters: usize,
    pub clusters_max_size: usize,
    pub driver_msg_count: usize,

    config: &'a Config,
    predmtrx: VecvecCappedF32,
    predictions: Predictions,
    debug_csv_writer: CsvWriter,

    tx: Sender<MultiThread>,
    rx: Receiver<MultiThread>,
    is_tread_clustering_running: bool,
}

#[derive(Debug)]
pub struct MultiThread {
    pub nb_clusters: usize,
    pub clusters_max_size: usize,
}

impl ProcessRecord<'_> {
    pub fn from<'a>(
        config: &'a Config,
        drivermsg: &DriverMsg,
        appname: String,
        exepath: PathBuf,
    ) -> ProcessRecord<'a> {
        let (tx, rx) = mpsc::channel::<MultiThread>();

        ProcessRecord {
            appname: appname,
            gid: drivermsg.gid,
            pids: HashSet::new(),
            total_ops_r: 0,
            total_ops_rn: 0,
            total_ops_w: 0,
            total_ops_c: 0,
            total_bytes_r: 0,
            total_bytes_w: 0,
            sum_entropy_weight_r: 0.0,
            sum_entropy_weight_w: 0.0,
            file_ids_r: HashSet::new(),
            file_ids_rn: HashSet::new(),
            file_ids_c: HashSet::new(),
            file_ids_w: HashSet::new(),
            file_ids_d: HashSet::new(),
            file_paths_c: HashSet::new(),
            file_paths_u: HashSet::new(),
            dir_with_files_c: HashSet::new(),
            dir_with_files_u: HashSet::new(),
            dir_with_files_o: HashSet::new(),
            extensions_count_r: ExtensionsCount::new(&config.extensions_list),
            extensions_count_w: ExtensionsCount::new(&config.extensions_list),
            exepath: exepath,
            exe_still_exists: true,
            is_malicious: false,
            time_started: SystemTime::now(),
            time_killed: None,
            config: &config,
            predmtrx: VecvecCapped::new(PREDMTRXCOLS, PREDMTRXROWS), //23 * 200
            predictions: Predictions::new(),
            debug_csv_writer: CsvWriter::from(&config),
            driver_msg_count: 0,
            nb_clusters: 0,
            clusters_max_size: 0,
            tx,
            rx,
            is_tread_clustering_running: false,
        }
    }

    pub fn launch_thread_clustering(&self) {
        let tx = self.tx.to_owned();
        let dir_with_files_u = self.dir_with_files_u.clone();
        thread::spawn(move || {
            let cs = clustering(dir_with_files_u.clone());
            let res = MultiThread {
                nb_clusters: cs.len(),
                clusters_max_size: cs.iter().map(|c| c.size()).max().unwrap_or(0),
            };
            tx.send(res).unwrap();
        });
    }

    pub fn add_irp_record(&mut self, drivermsg: &DriverMsg) {
        self.driver_msg_count += 1;
        self.pids.insert(drivermsg.pid.clone());
        self.exe_still_exists = drivermsg.runtime_features.exe_still_exists;
        match IrpMajorOp::from_byte(drivermsg.irp_op) {
            IrpMajorOp::IrpNone => {}
            IrpMajorOp::IrpRead => self.update_read(&drivermsg),
            IrpMajorOp::IrpWrite => self.update_write(&drivermsg),
            IrpMajorOp::IrpSetInfo => self.update_set(&drivermsg),
            IrpMajorOp::IrpCreate => self.update_create(&drivermsg),
            IrpMajorOp::IrpCleanUp => {}
        }
    }

    fn update_read(&mut self, drivermsg: &DriverMsg) {
        self.total_ops_r += 1;
        self.total_bytes_r += drivermsg.mem_sized_used;
        self.file_ids_r.insert(FileId::from(&FILE_ID_INFO {
            FileId: FILE_ID_128 {
                Identifier: drivermsg.file_id_id,
            },
            VolumeSerialNumber: drivermsg.file_id_vsn,
        })); //FileId::from(&drivermsg.file_id));
        self.extensions_count_r
            .add_cat_extension(&*String::from_utf16_lossy(&drivermsg.extension));
        self.sum_entropy_weight_r =
            (drivermsg.entropy * (drivermsg.mem_sized_used as f64)) + self.sum_entropy_weight_r;
    }

    fn update_write(&mut self, drivermsg: &DriverMsg) {
        self.total_ops_w += 1;
        self.total_bytes_w += drivermsg.mem_sized_used;
        let fpath = drivermsg.filepathstr.clone(); //.to_string();
        self.file_paths_u.insert(fpath);
        self.file_ids_w.insert(FileId::from(&FILE_ID_INFO {
            FileId: FILE_ID_128 {
                Identifier: drivermsg.file_id_id,
            },
            VolumeSerialNumber: drivermsg.file_id_vsn,
        })); //FileId::from(&drivermsg.file_id));
             //if let Some(dir) = &drivermsg.filepath.dirname() {
        if let Some(dir) = Some(
            Path::new(&drivermsg.filepathstr)
                .parent()
                .unwrap_or(Path::new(r".\"))
                .to_string_lossy()
                .parse()
                .unwrap(),
        ) {
            self.dir_with_files_u.insert(dir);
        }
        self.extensions_count_w
            .add_cat_extension(&*String::from_utf16_lossy(&drivermsg.extension));
        self.sum_entropy_weight_w =
            (drivermsg.entropy * (drivermsg.mem_sized_used as f64)) + self.sum_entropy_weight_w;
    }

    fn update_set(&mut self, drivermsg: &DriverMsg) {
        let file_location_enum = num::FromPrimitive::from_u8(drivermsg.file_location_info);
        let file_change_enum = num::FromPrimitive::from_u8(drivermsg.file_change);
        let fpath = drivermsg.filepathstr.clone(); //.to_string();
        match file_change_enum {
            Some(FileChangeInfo::FileChangeDeleteFile) => {
                self.file_ids_d.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: drivermsg.file_id_id,
                    },
                    VolumeSerialNumber: drivermsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));

                self.file_paths_u.insert(fpath.clone());
                if let Some(dir) = Some(
                    Path::new(&drivermsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_u.insert(dir);
                }
            }
            Some(FileChangeInfo::FileChangeExtensionChanged) => {
                self.extensions_count_w
                    .add_cat_extension(&*String::from_utf16_lossy(&drivermsg.extension));

                self.file_paths_u.insert(fpath.clone());
                //if let Some(dir) = drivermsg.filepath.dirname() {
                if let Some(dir) = Some(
                    Path::new(&drivermsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    self.dir_with_files_u.insert(dir);
                }
                self.file_ids_rn.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: drivermsg.file_id_id,
                    },
                    VolumeSerialNumber: drivermsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
                self.total_ops_rn += 1;
            }
            Some(FileChangeInfo::FileChangeRenameFile) => {
                self.file_paths_u.insert(fpath.clone());
                if let Some(dir) = Some(
                    Path::new(&drivermsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_u.insert(dir);
                }
                self.file_ids_rn.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: drivermsg.file_id_id,
                    },
                    VolumeSerialNumber: drivermsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
                self.total_ops_rn += 1;
            }
            _ => {}
        }
        match file_location_enum {
            /*
            Some(FileLocationInfo::FileMovedIn) => {
                println!("MOVED IN");
                self.file_paths_c.insert(fpath.clone());
                if let Some(dir) = Some(Path::new(&drivermsg.filepathstr).parent().unwrap().to_string_lossy().parse().unwrap()) {
                //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_c.insert(dir);
                }
            }*/
            Some(FileLocationInfo::FileMovedOut) => {
                //println!("MOVED OUT");
                self.file_paths_u.insert(fpath.clone());
                if let Some(dir) = Some(
                    Path::new(&drivermsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_u.insert(dir);
                }
            }
            _ => {}
        }
    }

    fn update_create(&mut self, drivermsg: &DriverMsg) {
        self.total_ops_c += 1;
        self.extensions_count_w
            .add_cat_extension(&*String::from_utf16_lossy(&drivermsg.extension));
        let file_change_enum = num::FromPrimitive::from_u8(drivermsg.file_change);
        let fpath = drivermsg.filepathstr.clone(); //.to_string();
        match file_change_enum {
            Some(FileChangeInfo::FileChangeNewFile) => {
                self.file_ids_c.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: drivermsg.file_id_id,
                    },
                    VolumeSerialNumber: drivermsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
                self.file_paths_c.insert(fpath); //todo
                if let Some(dir) = Some(
                    Path::new(&drivermsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_c.insert(dir);
                }
            }
            Some(FileChangeInfo::FileChangeOverwriteFile) => {
                //file is overwritten
                self.file_ids_c.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: drivermsg.file_id_id,
                    },
                    VolumeSerialNumber: drivermsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
            }
            Some(FileChangeInfo::FileChangeDeleteFile) => {
                //opened and deleted on close
                self.file_ids_d.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: drivermsg.file_id_id,
                    },
                    VolumeSerialNumber: drivermsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
                self.file_paths_u.insert(fpath);
                if let Some(dir) = Some(
                    Path::new(&drivermsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_u.insert(dir);
                }
            }
            Some(FileChangeInfo::FileOpenDirectory) => {
                if let Some(dir) = Some(
                    Path::new(&drivermsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_o.insert(dir);
                }
            }
            _ => {}
        }
    }

    pub fn write_learn_csv(&mut self) {
        let predict_row = PredictionRow::from(&self);
        //println!("Prediction Row - {:?}", predict_row);
        if self.driver_msg_count % self.config.threshold_drivermsgs == 0 {
            self.debug_csv_writer
                .write_debug_csv_files(&self.appname, self.gid, &predict_row)
                .unwrap_or_else(|_| debug!("Cannot write debug csv file"));
        }
    }

    pub fn eval(&mut self, tflite: &TfLite) -> Option<(VecvecCappedF32, f32)> {
        let predict_row = PredictionRow::from(&self);

        if self.driver_msg_count % self.config.threshold_drivermsgs == 0 {
            self.predmtrx.push_row(predict_row.to_vec_f32()).unwrap();

            if !self.is_tread_clustering_running {
                self.launch_thread_clustering();
                self.is_tread_clustering_running = true;
                //println!("launch thread");
            } else {
                let received = self.rx.try_recv();
                if received.is_ok() {
                    let mt = received.unwrap();
                    //println!("received thread: {:?}", mt);
                    self.nb_clusters = mt.nb_clusters;
                    self.clusters_max_size = mt.clusters_max_size;
                    self.is_tread_clustering_running = false;
                } else {
                    // println!("Waiting for thread");
                }
            }

            if self.predmtrx.rows_len() > 0 {
                if self.is_to_predict() {
                    let prediction = tflite.make_prediction(&self.predmtrx);
                    //println!("PROC: {:?}", self);
                    //println!("MTRX: {:?}", self.predmtrx);
                    //println!("{}", prediction);
                    //println!("##########");
                    self.predictions.register_prediction(
                        SystemTime::now(),
                        self.file_ids_w.len(),
                        prediction,
                    );
                    return Some((self.predmtrx.clone(), prediction));
                }
            }
        }
        None
    }

    fn is_to_predict(&self) -> bool {
        if self.file_paths_u.len() < 60 || self.predmtrx.rows_len() < 70 {
            false
        } else {
            match self.predictions.predictions_count() {
                0..=3 => self.driver_msg_count % self.config.threshold_drivermsgs == 0,
                4..=10 => self.driver_msg_count % (self.config.threshold_drivermsgs * 50) == 0,
                11..=50 => self.driver_msg_count % (self.config.threshold_drivermsgs * 150) == 0,
                n if n > 100000 => false,
                _ => self.driver_msg_count % (self.config.threshold_drivermsgs * 300) == 0,
            }
        }
    }

    fn is_process_still_running(&self, system: &System) -> bool {
        for p in &self.pids {
            let pid = Pid::from_str(&p.to_string()).unwrap();
            if let Some(process) = system.process(pid) {
                if process.status().to_string() == ProcessStatus::Run.to_string() {
                    return true;
                }
            }
        }
        return false;
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct FileId {
    pub volume_serial: u64,
    pub file_id: Vec<u8>,
}

impl FileId {
    pub fn from(file_id_info: &FILE_ID_INFO) -> FileId {
        FileId {
            volume_serial: file_id_info.VolumeSerialNumber,
            file_id: file_id_info.FileId.Identifier.to_vec(),
        }
    }
}

pub mod procs {
    use sysinfo::System;
    use crate::process::ProcessRecord;

    pub struct Procs<'a> {
        pub procs: Vec<ProcessRecord<'a>>,
    }

    impl<'a> Procs<'a> {
        pub fn new() -> Procs<'a> {
            Procs { procs: vec![] }
        }

        pub fn get_by_gid_index(&self, gid: u64) -> Option<usize> {
            for (i, proc) in self.procs.iter().enumerate() {
                if proc.gid == gid {
                    return Some(i);
                }
            }
            None
        }

        pub fn add_record(&mut self, proc: ProcessRecord<'a>) {
            self.procs.push(proc)
        }

        pub fn purge(&mut self, system: &System) {
            self.procs.retain(|p| p.is_process_still_running(system)); // || p.time_killed.is_some());
        }

        pub fn len(&self) -> usize {
            self.procs.len()
        }
    }
}
