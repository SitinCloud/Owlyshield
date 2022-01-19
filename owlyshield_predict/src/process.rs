//! Where the activities of processes are recorded and calculations of features are done, to feed
//! the input tensors used in the [crate::prediction] module.
//!
//! ## A GID is a family of processes
//! Each windows process has a unique parent. However, there are notable differences with Linux:
//! * Process creation is achieved by calling *CreateProcess*, which differs from *fork*,
//! * A process can erase its genealogy, and event change its parent!
//! Process Creations are monitored by the minifilter. As all processes are children of *Windows System*,
//! identified by pid == 4, the minifilter defines subfamilies identified by a unique group id
//! (referred to *gid* in the code).
//!
//! ## How is a GID state maintained over time?
//! A [ProcessRecord] instance is associated to each *GID* identified by the driver.
//! [crate::driver_com::shared_def::IOMessage] fetched from the minifilter contains data that
//! are aggregated in real time and used for predictions by the RNN.
//!
//! ## Time is not a good metric
//! Let's consider two scenarios about the performances of the client hardware hosting *Owlyshield*:
//! * It is very fast: we would observe a very quick increase in activity over time, resulting in
//! false-positive
//! * It is very slow: the model would have a bad recall for malwares, as they would have a very slow
//! activity
//!
//! That's why *Owlyshield* uses time-independant metric which is the number of driver messages received
//! from a driver.


use std::collections::HashSet;
use std::os::raw::{c_ulong, c_ulonglong};
use std::path::{Display, Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::{fmt, thread};
use std::fmt::Formatter;
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
use crate::prediction::input_tensors::{PredictionRow, VecvecCapped, VecvecCappedF32};
use crate::prediction::{Predictions, TfLite};
use crate::prediction::{PREDMTRXCOLS, PREDMTRXROWS};

/// GID state in real-time. This is a central structure.
///
/// This struct has several functions:
/// - Store the activity of a gid by aggregating the data received from the driver in real-time
/// - Calculate multiple metrics that will feed the prediction
/// - Decide when to predict, in order to balance the heavy computation cost associated with the need
/// for frequent calls to [crate::prediction::TfLite::make_prediction].
#[derive(Debug)]
pub struct ProcessRecord<'a> {
    /// Main process name.
    pub appname: String,
    /// Group Identifier: a unique number (maintained by the minifilter) identifying this family of precesses.
    pub gid: c_ulonglong,
    /// Set of pids in this family of processes.
    pub pids: HashSet<c_ulong>,
    /// Count of Read operations [crate::driver_com::IrpMajorOp::IrpRead]
    pub ops_read: u64,
    /// Count of SetInfo operations [crate::driver_com::IrpMajorOp::IrpSetInfo]
    pub ops_setinfo: u64,
    /// Count of Write operations [crate::driver_com::IrpMajorOp::IrpWrite]
    pub ops_written: u64,
    /// Count of Handle Creation operations [crate::driver_com::IrpMajorOp::IrpCreate]
    pub ops_open: u64,
    /// Total of bytes read
    pub bytes_read: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Total entropy read
    pub entropy_read: f64,
    /// Total entropy write
    pub entropy_written: f64,
    /// File descriptors read
    pub files_read: HashSet<FileId>,
    /// File descriptors renamed
    pub files_renamed: HashSet<FileId>,
    /// File descriptors created
    pub files_opened: HashSet<FileId>,
    /// File descriptors written
    pub files_written: HashSet<FileId>,
    /// File descriptors deleted
    pub files_deleted: HashSet<FileId>,
    /// File paths created
    pub fpaths_created: HashSet<String>,
    /// File paths updated (by a *setinfo* operation)
    pub fpaths_updated: HashSet<String>,
    /// Directories having files created
    pub dirs_with_files_created: HashSet<String>,
    /// Directories having files updated
    pub dirs_with_files_updated: HashSet<String>,
    /// Directories having files opened (a file handle has been created)
    pub dirs_with_files_opened: HashSet<String>,
    /// Unique extensions read count
    pub extensions_read: ExtensionsCount<'a>,
    /// Unique extensions written count
    pub extensions_written: ExtensionsCount<'a>,
    /// Path to the exe of the main process (the root)
    pub exepath: PathBuf,
    /// Process exe file still exists (father)?
    pub exe_exists: bool,
    /// Process execution state (Running, Suspended, Killed...)
    pub process_state: ProcessState,
    /// Has the process been classified as *malicious*?
    pub is_malicious: bool,
    /// Time of the main process start
    pub time_started: SystemTime,
    /// Time of the main process kill (if malicious)
    pub time_killed: Option<SystemTime>,
    /// Time of process suspended
    pub time_suspended: Option<SystemTime>,
    /// Number of directories (with files updated) clusters created
    pub clusters: usize,
    /// Deepest cluster size
    pub clusters_max_size: usize,
    /// Number of driver messages received for this Gid
    pub driver_msg_count: usize,

    config: &'a Config,
    /// Our capped-size matric to feed the input tensors (in [Self::eval]).
    pub prediction_matrix: VecvecCappedF32,
    /// History of past predictions, mainly used by [Self::is_to_predict].
    pub predictions: Predictions,
    /// CSVWriter to create the files used to train the model. Used with ```--features replay``` only.
    debug_csv_writer: CsvWriter,

    /// Used by [Self::eval] to communicate with a thread in charge of the heavy computations (clustering).
    tx: Sender<MultiThreadClustering>,
    /// Used by [Self::eval] to communicate with a thread in charge of the heavy computations (clustering).
    rx: Receiver<MultiThreadClustering>,
    /// Used by [Self::eval] to communicate with a thread in charge of the heavy computations (clustering).
    is_tread_clustering_running: bool,

    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_empty: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_tiny: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_small: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_medium: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_large: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_huge: HashSet<String>,

    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_empty: Vec<c_ulonglong>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_tiny: Vec<c_ulonglong>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_small: Vec<c_ulonglong>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_medium: Vec<c_ulonglong>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_large: Vec<c_ulonglong>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_huge: Vec<c_ulonglong>,

    /// Static Prediction
    pub prediction_static: Option<f32>,
}

/// A tuple-struct to communicate with the thread in charge of calculating the clusters.
#[derive(Debug)]
pub struct MultiThreadClustering {
    pub nb_clusters: usize,
    pub clusters_max_size: usize,
}

impl ProcessRecord<'_> {
    pub fn from<'a>(
        config: &'a Config,
        iomsg: &IOMessage,
        appname: String,
        exepath: PathBuf,
        prediction_static: Option<f32>
    ) -> ProcessRecord<'a> {
        let (tx, rx) = mpsc::channel::<MultiThreadClustering>();

        ProcessRecord {
            appname: appname,
            gid: iomsg.gid,
            pids: HashSet::new(),
            ops_read: 0,
            ops_setinfo: 0,
            ops_written: 0,
            ops_open: 0,
            bytes_read: 0,
            bytes_written: 0,
            entropy_read: 0.0,
            entropy_written: 0.0,
            files_read: HashSet::new(),
            files_renamed: HashSet::new(),
            files_opened: HashSet::new(),
            files_written: HashSet::new(),
            files_deleted: HashSet::new(),
            fpaths_created: HashSet::new(),
            fpaths_updated: HashSet::new(),
            dirs_with_files_created: HashSet::new(),
            dirs_with_files_updated: HashSet::new(),
            dirs_with_files_opened: HashSet::new(),
            extensions_read: ExtensionsCount::new(&config.extensions_list),
            extensions_written: ExtensionsCount::new(&config.extensions_list),
            exepath: exepath,
            exe_exists: true,
            process_state: ProcessState::Running,
            is_malicious: false,
            time_started: SystemTime::now(),
            time_killed: None,
            config: &config,
            prediction_matrix: VecvecCapped::new(PREDMTRXCOLS, PREDMTRXROWS),
            predictions: Predictions::new(),
            debug_csv_writer: CsvWriter::from(&config),
            driver_msg_count: 0,
            clusters: 0,
            clusters_max_size: 0,
            tx,
            rx,
            is_tread_clustering_running: false,
            file_size_empty: HashSet::new(),
            file_size_tiny: HashSet::new(),
            file_size_small: HashSet::new(),
            file_size_medium: HashSet::new(),
            file_size_large: HashSet::new(),
            file_size_huge: HashSet::new(),
            bytes_size_empty: Vec::new(),
            bytes_size_tiny: Vec::new(),
            bytes_size_small: Vec::new(),
            bytes_size_medium: Vec::new(),
            bytes_size_large: Vec::new(),
            bytes_size_huge: Vec::new(),
            prediction_static: prediction_static,
            time_suspended: None
        }
    }

    pub fn launch_thread_clustering(&self) {
        let tx = self.tx.to_owned();
        let dir_with_files_u = self.dirs_with_files_updated.clone();
        thread::spawn(move || {
            let cs = clustering(dir_with_files_u.clone());
            let res = MultiThreadClustering {
                nb_clusters: cs.len(),
                clusters_max_size: cs.iter().map(|c| c.size()).max().unwrap_or(0),
            };
            tx.send(res).unwrap();
        });
    }

    /// Entry point to call on new drivermsg.
    pub fn add_irp_record(&mut self, iomsg: &IOMessage) {
        self.driver_msg_count += 1;
        self.pids.insert(iomsg.pid.clone());
        self.exe_exists = iomsg.runtime_features.exe_still_exists;
        match IrpMajorOp::from_byte(iomsg.irp_op) {
            IrpMajorOp::IrpNone => {}
            IrpMajorOp::IrpRead => self.update_read(&iomsg),
            IrpMajorOp::IrpWrite => self.update_write(&iomsg),
            IrpMajorOp::IrpSetInfo => self.update_set(&iomsg),
            IrpMajorOp::IrpCreate => self.update_create(&iomsg),
            IrpMajorOp::IrpCleanUp => {}
        }
    }

    fn update_read(&mut self, iomsg: &IOMessage) {
        self.ops_read += 1;
        self.bytes_read += iomsg.mem_sized_used;
        self.files_read.insert(FileId::from(&FILE_ID_INFO {
            FileId: FILE_ID_128 {
                Identifier: iomsg.file_id_id,
            },
            VolumeSerialNumber: iomsg.file_id_vsn,
        })); //FileId::from(&drivermsg.file_id));
        self.extensions_read
            .add_cat_extension(&*String::from_utf16_lossy(&iomsg.extension));
        self.entropy_read =
            (iomsg.entropy * (iomsg.mem_sized_used as f64)) + self.entropy_read;
    }

    fn update_write(&mut self, iomsg: &IOMessage) {
        self.ops_written += 1;
        self.bytes_written += iomsg.mem_sized_used;
        let fpath = iomsg.filepathstr.clone(); //.to_string();
        self.fpaths_updated.insert(fpath.clone());
        self.files_written.insert(FileId::from(&FILE_ID_INFO {
            FileId: FILE_ID_128 {
                Identifier: iomsg.file_id_id,
            },
            VolumeSerialNumber: iomsg.file_id_vsn,
        })); //FileId::from(&drivermsg.file_id));
             //if let Some(dir) = &drivermsg.filepath.dirname() {
        if let Some(dir) = Some(
            Path::new(&iomsg.filepathstr)
                .parent()
                .unwrap_or(Path::new(r".\"))
                .to_string_lossy()
                .parse()
                .unwrap(),
        ) {
            self.dirs_with_files_updated.insert(dir);
        }
        self.extensions_written
            .add_cat_extension(&*String::from_utf16_lossy(&iomsg.extension));
        self.entropy_written =
            (iomsg.entropy * (iomsg.mem_sized_used as f64)) + self.entropy_written;
        self.sort_bytes(iomsg.mem_sized_used);
        self.sort_file_size(iomsg.file_size, &iomsg.filepathstr);
    }

    /// When
    fn update_set(&mut self, iomsg: &IOMessage) {
        self.ops_setinfo += 1;
        let file_location_enum: Option<FileLocationInfo> = num::FromPrimitive::from_u8(iomsg.file_location_info);
        let file_change_enum = num::FromPrimitive::from_u8(iomsg.file_change);
        let fpath = iomsg.filepathstr.clone(); //.to_string();
        match file_change_enum {
            Some(FileChangeInfo::FileChangeDeleteFile) => {
                self.files_deleted.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));

                self.fpaths_updated.insert(fpath.clone());
                if let Some(dir) = Some(
                    Path::new(&iomsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dirs_with_files_updated.insert(dir);
                }
            }
            Some(FileChangeInfo::FileChangeExtensionChanged) => {
                self.extensions_written
                    .add_cat_extension(&*String::from_utf16_lossy(&iomsg.extension));

                self.fpaths_updated.insert(fpath.clone());
                //if let Some(dir) = drivermsg.filepath.dirname() {
                if let Some(dir) = Some(
                    Path::new(&iomsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    self.dirs_with_files_updated.insert(dir);
                }
                self.files_renamed.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
            }
            Some(FileChangeInfo::FileChangeRenameFile) => {
                self.fpaths_updated.insert(fpath.clone());
                if let Some(dir) = Some(
                    Path::new(&iomsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dirs_with_files_updated.insert(dir);
                }
                self.files_renamed.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
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
            // Some(FileLocationInfo::FileMovedOut) => {
            //     //println!("MOVED OUT");
            //     self.file_paths_u.insert(fpath.clone());
            //     if let Some(dir) = Some(
            //         Path::new(&drivermsg.filepathstr)
            //             .parent()
            //             .unwrap_or(Path::new(r".\"))
            //             .to_string_lossy()
            //             .parse()
            //             .unwrap(),
            //     ) {
            //         //if let Some(dir) = drivermsg.filepath.dirname() {
            //         self.dir_with_files_u.insert(dir);
            //     }
            // }
            _ => {}
        }
    }

    fn update_create(&mut self, iomsg: &IOMessage) {
        self.ops_open += 1;
        self.extensions_written
            .add_cat_extension(&*String::from_utf16_lossy(&iomsg.extension));
        let file_change_enum = num::FromPrimitive::from_u8(iomsg.file_change);
        let fpath = iomsg.filepathstr.clone(); //.to_string();
        match file_change_enum {
            Some(FileChangeInfo::FileChangeNewFile) => {
                self.files_opened.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
                self.fpaths_created.insert(fpath); //todo
                if let Some(dir) = Some(
                    Path::new(&iomsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dirs_with_files_created.insert(dir);
                }
            }
            Some(FileChangeInfo::FileChangeOverwriteFile) => {
                //file is overwritten
                self.files_opened.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
            }
            Some(FileChangeInfo::FileChangeDeleteFile) => {
                //opened and deleted on close
                self.files_deleted.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                })); //FileId::from(&drivermsg.file_id));
                self.fpaths_updated.insert(fpath);
                if let Some(dir) = Some(
                    Path::new(&iomsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dirs_with_files_updated.insert(dir);
                }
            }
            Some(FileChangeInfo::FileOpenDirectory) => {
                if let Some(dir) = Some(
                    Path::new(&iomsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    //if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dirs_with_files_opened.insert(dir);
                }
            }
            _ => {}
        }
    }

    /// Sorts the number of bytes transferred according to the defined levels:
    /// * Empty	    (0 KB)
    /// * Tiny	    (0 – 16 KB)
    /// * Small	    (16 KB – 1 MB)
    /// * Medium    (1 – 128 MB)
    /// * Large	    (128 MB – 1 GB)
    /// * Huge	    (> 1 GB)
    fn sort_bytes(&mut self, bytes: c_ulonglong) {
        if bytes == 0 {
            self.bytes_size_empty.push(0);
        } else if bytes > 0 && bytes <= 16_000 {
            self.bytes_size_tiny.push(bytes);
        } else if bytes > 16_000 && bytes <= 1_000_000 {
            self.bytes_size_small.push(bytes);
        } else if bytes > 1_000_000 && bytes <= 128_000_000 {
            self.bytes_size_medium.push(bytes);
        } else if bytes > 128_000_000 && bytes <= 1_000_000_000 {
            self.bytes_size_large.push(bytes);
        } else if bytes > 1_000_000_000 {
            self.bytes_size_huge.push(bytes);
        }
    }

    /// Sorts the files by size according to the defined levels:
    /// * Empty	    (0 KB)
    /// * Tiny	    (0 – 16 KB)
    /// * Small	    (16 KB – 1 MB)
    /// * Medium    (1 – 128 MB)
    /// * Large	    (128 MB – 1 GB)
    /// * Huge	    (> 1 GB)
    fn sort_file_size(&mut self, fsize: i64, fpath: &String) {
        if fsize == 0 {
            self.file_size_empty.insert(fpath.clone());
        } else if fsize > 0 && fsize <= 16_000 {
            self.file_size_tiny.insert(fpath.clone());
        } else if fsize > 16_000 && fsize <= 1_000_000 {
            self.file_size_small.insert(fpath.clone());
        } else if fsize > 1_000_000 && fsize <= 128_000_000 {
            self.file_size_medium.insert(fpath.clone());
        } else if fsize > 128_000_000 && fsize <= 1_000_000_000 {
            self.file_size_large.insert(fpath.clone());
        } else if fsize > 1_000_000_000 {
            self.file_size_huge.insert(fpath.clone());
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

    fn ponderate_predictions(&self, rows_len: usize, prediction: f32) -> f32 {
        if let Some(prediction_static) = self.prediction_static {
            // eprintln!("exepath.display() = {:?}", self.exepath.display());
            // eprintln!("prediction = {:?}", prediction);
            // eprintln!("prediction_static = {:?}", prediction_static);
            // eprintln!("rows_len = {:?}", rows_len);
            // println!("################");
            match rows_len {
                0..=10 => { 0.8 * prediction_static + 0.2 * prediction }
                11..=20 => { 0.5 * prediction_static + 0.5 * prediction }
                _ => { 0.2 * prediction_static + 0.8 * prediction }
            }
        } else {
            prediction
        }
    }

    /// Manages computed features (calculated on a separate thread) and make a prediction if needed
    /// by [Self::is_to_predict].
    pub fn eval(&mut self, tflite: &TfLite) -> Option<(VecvecCappedF32, f32)> {
        let predict_row = PredictionRow::from(&self);

        if self.driver_msg_count % self.config.threshold_drivermsgs == 0 {
            self.prediction_matrix.push_row(predict_row.to_vec_f32()).unwrap();

            if !self.is_tread_clustering_running {
                self.launch_thread_clustering();
                self.is_tread_clustering_running = true;
                //println!("launch thread");
            } else {
                let received = self.rx.try_recv();
                if received.is_ok() {
                    let mt = received.unwrap();
                    //println!("received thread: {:?}", mt);
                    self.clusters = mt.nb_clusters;
                    self.clusters_max_size = mt.clusters_max_size;
                    self.is_tread_clustering_running = false;
                } else {
                    // println!("Waiting for thread");
                }
            }

            if self.prediction_matrix.rows_len() > 0 {
                if self.is_to_predict() {
                    let prediction = self.ponderate_predictions(self.prediction_matrix.rows_len(), tflite.make_prediction(&self.prediction_matrix));
                    //println!("PROC: {:?}", self);
                    //println!("MTRX: {:?}", self.predmtrx);
                    //println!("{}", prediction);
                    //println!("##########");
                    self.predictions.register_prediction(
                        SystemTime::now(),
                        self.files_written.len(),
                        prediction,
                    );
                    return Some((self.prediction_matrix.clone(), prediction));
                }
            }
        }
        None
    }

    /// Decides if a new prediction is required. Two parameters are considered:
    /// 1. The history of past predictions
    /// 2. The number of driver messages received for this particular gid, which is independant from
    /// the performances of the hardwares.
    ///
    /// A new gid is very frequently checked (many malwares don't wait to run their payload), whereas
    /// an old one is checked at regular intervals, in the unlikely case it would disguise for a
    /// long time (in terms of disk activity)
    fn is_to_predict(&self) -> bool {
        if self.bytes_written < 2_000_000 || self.files_opened.len() < 70 || self.files_written.len() < 40 {
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

/// A simple tuple-struct about Windows fileids
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct FileId {
    /// Volume identifier
    pub volume_serial: u64,
    /// Windows file id on 128 bits
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

#[derive(std::cmp::PartialEq, Debug)]
pub enum ProcessState {
    Running,
    Suspended,
    Killed,
}

impl fmt::Display for ProcessState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            ProcessState::Running => write!(f, "RUNNING"),
            ProcessState::Suspended => write!(f, "SUSPENDED"),
            ProcessState::Killed => write!(f, "KILLED"),
        }
    }
}

/// Structs and functions to manage a list of [ProcessRecord].
/// As of now, it's not multithreaded.
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
