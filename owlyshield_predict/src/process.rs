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

use std::{fmt, thread};
use std::collections::HashSet;
use std::fmt::Formatter;
use std::ops::Mul;
use std::os::raw::{c_ulong, c_ulonglong};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant, SystemTime};

use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_128;
use bindings::Windows::Win32::Storage::FileSystem::FILE_ID_INFO;
use slc_paths::clustering::clustering;
use sysinfo::{Pid, ProcessExt, ProcessStatus, System, SystemExt};

use crate::driver_com::{DriveType, IrpMajorOp};
use crate::driver_com::DriveType::{DriveCDRom, DriveRemote, DriveRemovable};
use crate::driver_com::shared_def::*;
use crate::extensions::ExtensionsCount;

/// GID state in real-time. This is a central structure.
///
/// This struct has several functions:
/// - Store the activity of a gid by aggregating the data received from the driver in real-time
/// - Calculate multiple metrics that will feed the prediction
/// - Decide when to predict, in order to balance the heavy computation cost associated with the need
/// for frequent calls to [crate::prediction_malware::TfLiteMalware::make_prediction].
#[derive(Debug)]
pub struct ProcessRecord {
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
    pub extensions_read: ExtensionsCount,
    /// Unique extensions written count
    pub extensions_written: ExtensionsCount,
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

    /// Used by [Self::eval] to communicate with a thread in charge of the heavy computations (clustering).
    tx: Sender<MultiThreadClustering>,
    /// Used by [Self::eval] to communicate with a thread in charge of the heavy computations (clustering).
    rx: Receiver<MultiThreadClustering>,
    /// Used by [Self::eval] to communicate with a thread in charge of the heavy computations (clustering).
    is_thread_clustering_running: bool,
    last_thread_clustering_time: SystemTime,
    last_thread_clustering_duration: Duration,

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
    /// Count of Read operations [crate::driver_com::IrpMajorOp::IrpRead] on a shared (remote) drive
    pub on_shared_drive_read_count: u32,
    /// Count of Write operations [crate::driver_com::IrpMajorOp::IrpWrite] on a shared (remote) drive
    pub on_shared_drive_write_count: u32,
    /// Count of Read operations [crate::driver_com::IrpMajorOp::IrpRead] on a removable drive
    pub on_removable_drive_read_count: u32,
    /// Count of Write operations [crate::driver_com::IrpMajorOp::IrpWrite] on a removable drive
    pub on_removable_drive_write_count: u32,
}

/// A tuple-struct to communicate with the thread in charge of calculating the clusters.
#[derive(Debug)]
pub struct MultiThreadClustering {
    pub nb_clusters: usize,
    pub clusters_max_size: usize,
}

impl ProcessRecord {
    pub fn from<'a>(
        iomsg: &IOMessage,
        appname: String,
        exepath: PathBuf,
    ) -> ProcessRecord {
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
            extensions_read: ExtensionsCount::new(),
            extensions_written: ExtensionsCount::new(),
            exepath: exepath,
            exe_exists: true,
            process_state: ProcessState::Running,
            is_malicious: false,
            time_started: SystemTime::now(),
            time_killed: None,
            driver_msg_count: 0,
            clusters: 0,
            clusters_max_size: 0,
            tx,
            rx,
            is_thread_clustering_running: false,
            last_thread_clustering_time: SystemTime::now(),
            last_thread_clustering_duration: Duration::ZERO,
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
            time_suspended: None,
            on_shared_drive_read_count: 0,
            on_shared_drive_write_count: 0,
            on_removable_drive_read_count: 0,
            on_removable_drive_write_count: 0,
        }
    }

    fn launch_thread_clustering(&self) {
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

    fn update_clusters(&mut self) {
        if self.driver_msg_count % 100 == 0 {
            if self.is_to_cluster() {
                let start = Instant::now();
                self.launch_thread_clustering();
                self.is_thread_clustering_running = true;
                self.last_thread_clustering_time = SystemTime::now();
                self.last_thread_clustering_duration = start.elapsed();
            } else {
                let received = self.rx.try_recv();
                if received.is_ok() {
                    let mt = received.unwrap();
                    self.clusters = mt.nb_clusters;
                    self.clusters_max_size = mt.clusters_max_size;
                    self.is_thread_clustering_running = false;
                } else {
                    // println!("Waiting for thread");
                }
            }
        }
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
            _ => {}
        }
        self.update_clusters();
    }

    fn update_read(&mut self, iomsg: &IOMessage) {
        self.ops_read += 1;
        self.bytes_read += iomsg.mem_sized_used;
        self.files_read.insert(FileId::from(&FILE_ID_INFO {
            FileId: FILE_ID_128 {
                Identifier: iomsg.file_id_id,
            },
            VolumeSerialNumber: iomsg.file_id_vsn,
        }));
        self.extensions_read
            .add_cat_extension(&*String::from_utf16_lossy(&iomsg.extension));
        self.entropy_read = (iomsg.entropy * (iomsg.mem_sized_used as f64)) + self.entropy_read;
        match DriveType::from_filepath(iomsg.filepathstr.clone()) {
            DriveRemovable => self.on_removable_drive_read_count += 1,
            DriveRemote => self.on_shared_drive_read_count += 1,
            DriveCDRom => self.on_removable_drive_read_count += 1,
            _ => {}
        }
    }

    fn update_write(&mut self, iomsg: &IOMessage) {
        self.ops_written += 1;
        self.bytes_written += iomsg.mem_sized_used;
        let fpath = iomsg.filepathstr.clone();
        self.fpaths_updated.insert(fpath.clone());
        self.files_written.insert(FileId::from(&FILE_ID_INFO {
            FileId: FILE_ID_128 {
                Identifier: iomsg.file_id_id,
            },
            VolumeSerialNumber: iomsg.file_id_vsn,
        }));
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
        match DriveType::from_filepath(iomsg.filepathstr.clone()) {
            DriveRemovable => self.on_removable_drive_write_count += 1,
            DriveRemote => self.on_shared_drive_write_count += 1,
            DriveCDRom => self.on_removable_drive_write_count += 1,
            _ => {}
        }
    }

    fn update_set(&mut self, iomsg: &IOMessage) {
        self.ops_setinfo += 1;
        let file_change_enum = num::FromPrimitive::from_u8(iomsg.file_change);
        let fpath = iomsg.filepathstr.clone();
        match file_change_enum {
            Some(FileChangeInfo::FileChangeDeleteFile) => {
                self.files_deleted.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                }));

                self.fpaths_updated.insert(fpath.clone());
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
            }
            Some(FileChangeInfo::FileChangeExtensionChanged) => {
                self.extensions_written
                    .add_cat_extension(&*String::from_utf16_lossy(&iomsg.extension));

                self.fpaths_updated.insert(fpath.clone());
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
                }));
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
                    self.dirs_with_files_updated.insert(dir);
                }
                self.files_renamed.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                }));
            }
            _ => {}
        }
    }

    fn update_create(&mut self, iomsg: &IOMessage) {
        self.ops_open += 1;
        self.extensions_written
            .add_cat_extension(&*String::from_utf16_lossy(&iomsg.extension));
        let file_change_enum = num::FromPrimitive::from_u8(iomsg.file_change);
        let fpath = iomsg.filepathstr.clone();
        match file_change_enum {
            Some(FileChangeInfo::FileChangeNewFile) => {
                self.files_opened.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                }));
                self.fpaths_created.insert(fpath);
                if let Some(dir) = Some(
                    Path::new(&iomsg.filepathstr)
                        .parent()
                        .unwrap_or(Path::new(r".\"))
                        .to_string_lossy()
                        .parse()
                        .unwrap(),
                ) {
                    self.dirs_with_files_created.insert(dir);
                }
            }
            Some(FileChangeInfo::FileChangeOverwriteFile) => {
                // File is overwritten
                self.files_opened.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                }));
            }
            Some(FileChangeInfo::FileChangeDeleteFile) => {
                // Opened and deleted on close
                self.files_deleted.insert(FileId::from(&FILE_ID_INFO {
                    FileId: FILE_ID_128 {
                        Identifier: iomsg.file_id_id,
                    },
                    VolumeSerialNumber: iomsg.file_id_vsn,
                }));
                self.fpaths_updated.insert(fpath);
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

    fn _is_process_still_running(&self, system: &System) -> bool {
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

    /// Decides if a new clustering is required. Three parameters are considered:
    /// 1. Is the clustering thread running?
    /// 2. The last clustering time.
    /// 3. The last clustering duration.
    ///
    /// This function is to reduce the frequency of clustering on some applications whose clustering requires a lot of CPU.
    fn is_to_cluster(&self) -> bool {
        if !self.is_thread_clustering_running {
            return self.last_thread_clustering_time
                + self.last_thread_clustering_duration.mul(100)
                <= SystemTime::now();
        } else {
            false
        }
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

#[derive(PartialEq, Debug)]
pub enum ProcessState {
    Running,
    Suspended,
    _Killed,
}

impl fmt::Display for ProcessState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            ProcessState::Running => write!(f, "RUNNING"),
            ProcessState::Suspended => write!(f, "SUSPENDED"),
            ProcessState::_Killed => write!(f, "KILLED"),
        }
    }
}

#[cfg(test)]
#[doc(hidden)]
mod tests {
    use crate::driver_com::shared_def::RuntimeFeatures;
    use crate::extensions::ExtensionCategory::{
        Docs, Exe, Others
    };
    use crate::process::{FileId, ProcessRecord};
    use crate::IOMessage;
    use std::collections::HashSet;
    use std::os::raw::c_ulonglong;

    fn get_iomsgs() -> Vec<IOMessage> {
        Vec::from([
            IOMessage {
                extension : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [231, 14, 3, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30848,
                irp_op : 5,
                is_entropy_calc : 0,
                file_change : 0,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\173C426CDA68AF66D616B5C27D808FD8C6EB89AA".parse().unwrap(),
                gid : 1883,
                runtime_features: RuntimeFeatures::new(),
                file_size : 10899,
            },

            IOMessage {
                extension : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [184, 45, 0, 0, 0, 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30108,
                irp_op : 5,
                is_entropy_calc : 0,
                file_change : 0,
                file_location_info : 0,
                filepathstr : r"C:\Program Files\MyProgram\Images\logo-red.icos\DeliveryOptimization\Cache".parse().unwrap(),
                gid : 2008,
                runtime_features: RuntimeFeatures::new(),
                file_size : -1,
            },

            IOMessage {
                extension : [116, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [140, 20, 1, 0, 0, 0, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 94,
                entropy : 5.132623395052655,
                pid : 13192,
                irp_op : 2,
                is_entropy_calc : 1,
                file_change : 2,
                file_location_info : 0,
                filepathstr : r"C:\ProgramData\McAfee\WebAdvisor\WATaskManager.dll\log_0020005F003E001500060033005D.txt".parse().unwrap(),
                gid : 27,
                runtime_features: RuntimeFeatures::new(),
                file_size : 61086,
            },

            IOMessage {
                extension : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [241, 14, 3, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 16116,
                entropy : 5.966784127057974,
                pid : 30848,
                irp_op : 2,
                is_entropy_calc : 1,
                file_change : 2,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\1291463B146203711386759F4387CBD020F9C25F".parse().unwrap(),
                gid : 1883,
                runtime_features: RuntimeFeatures::new(),
                file_size : 16184,
            },

            IOMessage {
                extension : [105, 99, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [184, 45, 0, 0, 0, 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 218070,
                entropy : 2.948640431362244,
                pid : 30108,
                irp_op : 1,
                is_entropy_calc : 1,
                file_change : 0,
                file_location_info : 0,
                filepathstr : r"C:\Program Files\MyProgram\Images\logo-red.ico".parse().unwrap(),
                gid : 2008,
                runtime_features: RuntimeFeatures::new(),
                file_size : 218070,
            },

            IOMessage {
                extension : [101, 120, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [4, 31, 7, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 90112,
                entropy : 5.858913026451287,
                pid : 23812,
                irp_op : 1,
                is_entropy_calc : 1,
                file_change : 0,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\JetBrains\IntelliJIdea2022.1\tmp\sendctrlc.x64.B37C5E935F3DA60B2940592241F826DA.exe".parse().unwrap(),
                gid : 1883,
                runtime_features: RuntimeFeatures::new(),
                file_size : 90112,
            },

            IOMessage {
                extension : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [99, 88, 14, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30848,
                irp_op : 3,
                is_entropy_calc : 0,
                file_change : 6,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\B5C78DC28F7E98EF882C0BA6DC0CCB4FEFF5D25B".parse().unwrap(),
                gid : 1883,
                runtime_features: RuntimeFeatures::new(),
                file_size : -1,
            },

            IOMessage {
                extension : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [103, 88, 14, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30848,
                irp_op : 3,
                is_entropy_calc : 0,
                file_change : 6,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\95858FA1CCC13FA3E7E6D35C7FE6A8CF014CD91F".parse().unwrap(),
                gid : 1883,
                runtime_features: RuntimeFeatures::new(),
                file_size : -1,
            },

            IOMessage {
                extension : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [17, 69, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30848,
                irp_op : 4,
                is_entropy_calc : 0,
                file_change : 1,
                file_location_info : 1,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2".parse().unwrap(),
                gid : 1883,
                runtime_features: RuntimeFeatures::new(),
                file_size : 4096,
            },

            IOMessage {
                extension : [105, 99, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                file_id_vsn : 5374009898110646019,
                file_id_id : [184, 45, 0, 0, 0, 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30108,
                irp_op : 4,
                is_entropy_calc : 0,
                file_change : 0,
                file_location_info : 1,
                filepathstr : r"C:\Program Files\MyProgram\Images\logo-red.ico".parse().unwrap(),
                gid : 2008,
                runtime_features: RuntimeFeatures::new(),
                file_size : 218070,
            }
        ])
    }

    #[test]
    fn test_add_irp_record() {
        let iomsgs = get_iomsgs();
        let mut pr = ProcessRecord::from(
            &iomsgs[0],
            "".to_string(),
            "".parse().unwrap(),
        );

        for iomsg in iomsgs {
            pr.add_irp_record(&iomsg);
        }

        assert_eq!(pr.ops_read, 2);
        assert_eq!(pr.ops_setinfo, 2);
        assert_eq!(pr.ops_written, 2);
        assert_eq!(pr.ops_open, 4);
        assert_eq!(pr.bytes_read, 308182);
        assert_eq!(pr.bytes_written, 16210);
        assert_eq!(pr.entropy_read, 1170968.3895067428);
        assert_eq!(pr.entropy_written, 96643.15959080125);
        assert_eq!(
            pr.files_read,
            HashSet::from([
                FileId {
                    volume_serial: 5374009898110646019,
                    file_id: [184, 45, 0, 0, 0, 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()
                },
                FileId {
                    volume_serial: 5374009898110646019,
                    file_id: [4, 31, 7, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()
                }
            ])
        );
        assert_eq!(pr.files_renamed, HashSet::new());
        assert_eq!(pr.files_opened, HashSet::new());
        assert_eq!(
            pr.files_written,
            HashSet::from([
                FileId {
                    volume_serial: 5374009898110646019,
                    file_id: [241, 14, 3, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()
                },
                FileId {
                    volume_serial: 5374009898110646019,
                    file_id: [140, 20, 1, 0, 0, 0, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()
                }
            ])
        );
        assert_eq!(
            pr.files_deleted,
            HashSet::from([
                FileId {
                    volume_serial: 5374009898110646019,
                    file_id: [99, 88, 14, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()
                },
                FileId {
                    volume_serial: 5374009898110646019,
                    file_id: [103, 88, 14, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()
                }
            ])
        );
        assert_eq!(pr.fpaths_created, HashSet::new());
        assert_eq!(pr.fpaths_updated, HashSet::from([ r"C:\ProgramData\McAfee\WebAdvisor\WATaskManager.dll\log_0020005F003E001500060033005D.txt".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\95858FA1CCC13FA3E7E6D35C7FE6A8CF014CD91F".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\1291463B146203711386759F4387CBD020F9C25F".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\B5C78DC28F7E98EF882C0BA6DC0CCB4FEFF5D25B".to_string() ]));
        assert_eq!(pr.dirs_with_files_created, HashSet::new());
        assert_eq!(pr.dirs_with_files_updated, HashSet::from([ r"C:\ProgramData\McAfee\WebAdvisor\WATaskManager.dll".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries".to_string() ]));
        assert_eq!(
            pr.dirs_with_files_opened,
            HashSet::from([
                r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default"
                    .to_string()
            ])
        );

        assert_eq!(
            pr.extensions_read.categories_set.get(&Exe).unwrap(),
            &HashSet::from(["exe".to_string()])
        );
        assert_eq!(
            pr.extensions_read.categories_set.get(&Others).unwrap(),
            &HashSet::from(["ico".to_string()])
        );
        assert_eq!(
            pr.extensions_written.categories_set.get(&Docs).unwrap(),
            &HashSet::from(["txt".to_string()])
        );
        assert_eq!(
            pr.extensions_written.categories_set.get(&Others).unwrap(),
            &HashSet::from(["ico".to_string()])
        );
        assert_eq!(pr.file_size_empty, HashSet::new());
        assert_eq!(pr.file_size_tiny, HashSet::new());
        assert_eq!(pr.file_size_small, HashSet::from([ r"C:\ProgramData\McAfee\WebAdvisor\WATaskManager.dll\log_0020005F003E001500060033005D.txt".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\1291463B146203711386759F4387CBD020F9C25F".to_string() ]));
        assert_eq!(pr.file_size_medium, HashSet::new());
        assert_eq!(pr.file_size_large, HashSet::new());
        assert_eq!(pr.file_size_huge, HashSet::new());
        assert_eq!(pr.bytes_size_empty, Vec::<c_ulonglong>::new());
        assert_eq!(pr.bytes_size_tiny, [94].to_vec());
        assert_eq!(pr.bytes_size_small, [16116].to_vec());
        assert_eq!(pr.bytes_size_medium, Vec::<c_ulonglong>::new());
        assert_eq!(pr.bytes_size_large, Vec::<c_ulonglong>::new());
        assert_eq!(pr.bytes_size_huge, Vec::<c_ulonglong>::new());
        assert_eq!(pr.on_shared_drive_read_count, 0);
        assert_eq!(pr.on_shared_drive_write_count, 0);
        assert_eq!(pr.on_removable_drive_read_count, 0);
        assert_eq!(pr.on_removable_drive_write_count, 0);
    }
}
