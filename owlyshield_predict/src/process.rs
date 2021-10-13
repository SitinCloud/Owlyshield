use crate::actions_on_kill::ActionsOnKill;
use crate::config::Config;
use crate::csvwriter::CsvWriter;
use crate::driver_com::shared_def::*;
use crate::driver_com::IrpMajorOp;
use crate::extensions::{ExtensionCategory, ExtensionList, ExtensionsCount};
use crate::prediction::predmtrx::{MatrixF32, PredictionRow, VecvecCapped, VecvecCappedF32};
use crate::prediction::{PredictionValues, Predictions, TfLite};
use crate::utils::*;
use crate::whitelist::WhiteList;
use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_INFO;
use log::{debug, error, info, trace};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ops::Sub;
use std::os::raw::{c_ulong, c_ulonglong};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;
use sysinfo::{Pid, ProcessExt, SystemExt};

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
    pub is_malicious: bool,
    pub time_started: SystemTime,
    pub time_killed: Option<SystemTime>,

    config: &'a Config,
    predmtrx: VecvecCappedF32,
    predictions: Predictions,
    debug_csv_writer: CsvWriter,
}

impl ProcessRecord<'_> {
    pub fn from<'a>(
        config: &'a Config,
        drivermsg: &DriverMsg,
        appname: String,
        exepath: PathBuf,
    ) -> ProcessRecord<'a> {
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
            is_malicious: false,
            time_started: SystemTime::now(),
            time_killed: None,
            config: &config,
            predmtrx: VecvecCapped::new(21, 10),
            predictions: Predictions::new(),
            debug_csv_writer: CsvWriter::from(&config),
        }
    }

    pub fn add_irp_record(&mut self, drivermsg: &DriverMsg) {
        self.pids.insert(drivermsg.pid.clone());
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
        self.file_ids_r.insert(FileId::from(&drivermsg.file_id));
        self.extensions_count_r
            .add_cat_extension(&*String::from_utf16_lossy(&drivermsg.extension));
        self.sum_entropy_weight_r =
            (drivermsg.entropy * (drivermsg.mem_sized_used as f64)) + self.sum_entropy_weight_r;
    }

    fn update_write(&mut self, drivermsg: &DriverMsg) {
        self.total_bytes_w += drivermsg.mem_sized_used;
        let fpath = drivermsg.filepath.to_string();
        self.file_paths_u.insert(fpath);
        self.file_ids_w.insert(FileId::from(&drivermsg.file_id));
        if let Some(dir) = drivermsg.filepath.dirname() {
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
        let fpath = drivermsg.filepath.to_string();
        match file_change_enum {
            Some(FileChangeInfo::FileChangeDeleteFile) => {
                self.file_ids_d.insert(FileId::from(&drivermsg.file_id));

                self.file_paths_u.insert(fpath.clone());
                if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_u.insert(dir);
                }
            }
            Some(FileChangeInfo::FileChangeExtensionChanged) => {
                self.extensions_count_w
                    .add_cat_extension(&*String::from_utf16_lossy(&drivermsg.extension));

                self.file_paths_u.insert(fpath.clone());
                if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_u.insert(dir);
                }
                self.file_ids_rn.insert(FileId::from(&drivermsg.file_id));
                self.total_ops_rn += 1;
            }
            Some(FileChangeInfo::FileChangeRenameFile) => {
                self.file_paths_u.insert(fpath.clone());
                if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_u.insert(dir);
                }
                self.file_ids_rn.insert(FileId::from(&drivermsg.file_id));
                self.total_ops_rn += 1;
            }
            _ => {}
        }
        match file_location_enum {
            /*
            Some(FileLocationInfo::FileMovedIn) => {
                println!("MOVED IN");
                self.file_paths_c.insert(fpath.clone());
                if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_c.insert(dir);
                }
            }*/
            Some(FileLocationInfo::FileMovedOut) => {
                //println!("MOVED OUT");
                self.file_paths_u.insert(fpath.clone());
                if let Some(dir) = drivermsg.filepath.dirname() {
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
        let fpath = drivermsg.filepath.to_string();
        match file_change_enum {
            Some(FileChangeInfo::FileChangeNewFile) => {
                self.file_ids_c.insert(FileId::from(&drivermsg.file_id));
                self.file_paths_c.insert(fpath); //todo
                if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_c.insert(dir);
                }
            }
            Some(FileChangeInfo::FileChangeOverwriteFile) => {
                //file is overwritten
                self.file_ids_c.insert(FileId::from(&drivermsg.file_id));
            }
            Some(FileChangeInfo::FileChangeDeleteFile) => {
                //opened and deleted on close
                self.file_ids_d.insert(FileId::from(&drivermsg.file_id));
                self.file_paths_u.insert(fpath);
                if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_u.insert(dir);
                }
            }
            Some(FileChangeInfo::FileOpenDirectory) => {
                if let Some(dir) = drivermsg.filepath.dirname() {
                    self.dir_with_files_o.insert(dir);
                }
            }
            _ => {}
        }
    }

    pub fn eval(&mut self, tflite: &TfLite) -> Option<(VecvecCappedF32, f32)> {
        let now = SystemTime::now();
        let opt_last_prediction = self.predictions.get_last_prediction();
        let secondsdiff = match opt_last_prediction {
            None => now.duration_since(self.time_started),
            Some(pred) => now.duration_since(pred.0),
        }
        .unwrap()
        .as_secs_f32();

        //TODO Debug csv file should conditionally compiled
        let predict_row = PredictionRow::from(&self);
//        println!("Predict Row Struct {:?}", predict_row);
//        println!("Extensions_count_w: {:?}", self.extensions_count_w.categories_set);
        let vector = now.duration_since(self.time_started).unwrap().as_secs_f32() * 10f32;
        if self.debug_csv_writer.is_to_write() {
            self.debug_csv_writer
                .write_debug_csv_files(&self.appname, self.gid, vector, &predict_row)
                .unwrap_or_else(|_| debug!("Cannot write debug csv file"));
        }

        if secondsdiff > 0.5 {
            self.predmtrx.push_row(predict_row.to_vec_f32()).unwrap();

            if self.predmtrx.is_complete() {
                if self.is_to_predict(now, &opt_last_prediction) {
                    let prediction = tflite.make_prediction(&self.predmtrx);
                    //println!("PROC: {:?}", self);
                    println!("MTRX: {:?}", self.predmtrx);
                    println!("{}", prediction);
                    println!("##########");
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

    fn is_to_predict(
        &self,
        now: SystemTime,
        opt_last_prediction: &Option<PredictionValues>,
    ) -> bool {
        //return true; //Testing
        //println!("fids_ids_w {} {:?}", self.file_ids_w.len(), self.file_ids_w);
        if self.file_ids_w.len() < 10 || !self.predmtrx.is_complete() {
            // This second case should not happen
            false
        } else {
            if opt_last_prediction.is_none() {
                let seconds_since_launch = now.duration_since(self.time_started).unwrap().as_secs();
                return seconds_since_launch > 3;
            }
            let last_prediction = opt_last_prediction.unwrap();
            let file_ids_w_diff = self.file_ids_w.len() - last_prediction.1;
            let seconds_diff = now.duration_since(last_prediction.0).unwrap().as_secs();
            match (
                self.predictions.predictions_count(),
                seconds_diff,
                file_ids_w_diff,
            ) {
                (1..=5, fids, seconds) if fids > 30 && seconds > 2 => true,
                (5..=10, fids, seconds) if fids > 50 && seconds > 5 => true,
                (_, fids, _) if fids > 100 => true,
                _ => false,
            }
        }
    }

    fn exe_still_exists(&self) -> bool {
        self.exepath.exists()
    }

    fn is_process_still_running(&self) -> bool {
        for p in &self.pids {
            let pid = Pid::from_str(&p.to_string());
            if pid.is_ok() {
                return true;
            }
        }
        false
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
    use crate::process::ProcessRecord;
    use std::convert::TryInto;

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

        pub fn purge(&mut self) {
            self.procs
                .retain(|p| p.is_process_still_running() || p.time_killed.is_some());
        }
    }
}
