mod predictor {
    use crate::config::Config;
    use crate::predictions::prediction::input_tensors::PredictionRow;
    use crate::predictions::prediction::input_tensors::VecvecCappedF32;
    use crate::predictions::prediction::{PREDMTRXCOLS, PREDMTRXROWS};
    use crate::predictions::prediction_malware::TfLiteMalware;
    use crate::predictions::prediction_static::TfLiteStatic;
    use crate::process::ProcessRecord;

    pub trait PredictorHandler {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32>;
    }

    pub struct PredictorHandlerBehavioural<'a> {
        config: &'a Config,
        pub timesteps: VecvecCappedF32,
        predictions_count: usize,
        tflite_malware: TfLiteMalware,
    }

    impl PredictorHandler for PredictorHandlerBehavioural<'_> {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            let timestep = PredictionRow::from(precord);
            self.timesteps.push_row(timestep.to_vec_f32()).unwrap();
            if self.timesteps.rows_len() > 0 {
                if self.is_prediction_required(precord) {
                    let prediction = self.tflite_malware.make_prediction(&self.timesteps);
                    return Some(prediction);
                }
            }
            None
        }
    }

    impl PredictorHandlerBehavioural<'_> {
        pub fn new(config: &Config) -> PredictorHandlerBehavioural {
            PredictorHandlerBehavioural {
                config,
                timesteps: VecvecCappedF32::new(PREDMTRXCOLS, PREDMTRXROWS),
                predictions_count: 0,
                tflite_malware: TfLiteMalware::new(),
            }
        }
        fn is_prediction_required(&self, precord: &ProcessRecord) -> bool {
            if precord.bytes_written < 2_000_000
                || precord.files_opened.len() < 70
                || precord.files_written.len() < 40
            {
                false
            } else {
                match self.predictions_count {
                    0..=3 => precord.driver_msg_count % self.config.threshold_drivermsgs == 0,
                    4..=10 => {
                        precord.driver_msg_count % (self.config.threshold_drivermsgs * 50) == 0
                    }
                    11..=50 => {
                        precord.driver_msg_count % (self.config.threshold_drivermsgs * 150) == 0
                    }
                    n if n > 100000 => false,
                    _ => precord.driver_msg_count % (self.config.threshold_drivermsgs * 300) == 0,
                }
            }
        }
    }

    pub struct PredictorHandlerStatic {
        predictor_static: TfLiteStatic,
        prediction: Option<f32>,
        is_prediction_calculated: bool,
    }

    impl PredictorHandler for PredictorHandlerStatic {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            if !self.is_prediction_calculated {
                self.prediction = self.predictor_static.make_prediction(&precord.exepath);
                self.is_prediction_calculated = true;
            }
            self.prediction
        }
    }

    impl PredictorHandlerStatic {
        pub fn new() -> PredictorHandlerStatic {
            PredictorHandlerStatic {
                predictor_static: TfLiteStatic::new(),
                prediction: None,
                is_prediction_calculated: false
            }
        }
    }

    pub struct PredictorMalware<'a> {
        pub predictor_behavioural: PredictorHandlerBehavioural<'a>,
        pub predictor_static: PredictorHandlerStatic,
    }

    impl PredictorHandler for PredictorMalware<'_> {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            let opt_pred_b = self.predictor_behavioural.predict(precord);
            let opt_pred_s = self.predictor_static.predict(precord);

            match (opt_pred_s, opt_pred_b) {
                (Some(pred_s), Some(pred_b)) => Some(self.ponderate_prediction(precord, pred_s, pred_b)),
                (Some(pred_s), None) => Some(pred_s),
                (None, Some(pred_b)) => Some(pred_b),
                _ => None
            }
        }
    }

    impl PredictorMalware<'_> {
        pub fn new<'a>(config: &'a Config) -> PredictorMalware<'a> {
            PredictorMalware {
                predictor_behavioural: PredictorHandlerBehavioural::new(config),
                predictor_static: PredictorHandlerStatic::new(),
            }
        }

        fn ponderate_prediction(&self, precord: &ProcessRecord, pred_s: f32, pred_b: f32) -> f32 {
            let ponderation = match precord.driver_msg_count {
                0..=20 => 0.0,
                21..=50 => 0.5,
                _ => 0.8
            };
            (1.0-ponderation) * pred_s + ponderation * pred_b
        }
    }
}

pub mod process_record_handling {
    use std::os::raw::c_ulonglong;
    use std::sync::mpsc::Sender;

    use bindings::Windows::Win32::System::Diagnostics::Debug::{
        DebugActiveProcess
    };

    use crate::actions_on_kill::ActionsOnKill;
    use crate::config::{Config, KillPolicy, Param};
    use crate::csvwriter::CsvWriter;
    use crate::predictions::prediction::input_tensors::PredictionRow;
    use crate::process::{ProcessRecord, ProcessState};
    use crate::worker::predictor::{
        PredictorHandler, PredictorMalware,
    };

    pub trait ProcessRecordIOHandler {
        fn handle_io(&mut self, process_record: &mut ProcessRecord);
    }

    pub struct ProcessRecordHandlerLive<'a> {
        config: &'a Config,
        tx_kill: Sender<c_ulonglong>,
        predictor_malware: PredictorMalware<'a>,
    }

    impl ProcessRecordIOHandler for ProcessRecordHandlerLive<'_> {
        fn handle_io(&mut self, precord: &mut ProcessRecord) {
            if let Some(prediction_behavioural) = self
                .predictor_malware
                .predict(precord)
            {
                println!("{} - {}", precord.appname, prediction_behavioural);
                if prediction_behavioural > self.config.threshold_prediction
                    || precord.appname.contains("TEST-OLRANSOM")
                {
                    println!("Ransomware Suspected!!!");
                    eprintln!("precord.gid = {:?}", precord.gid);
                    println!("{}", precord.appname);
                    println!("with {} certainty", prediction_behavioural);
                    println!(
                        "\nSee {}\\threats for details.",
                        self.config[Param::DebugPath]
                    );
                    println!(
                        "\nPlease update {}\\exclusions.txt if it's a false positive",
                        self.config[Param::ConfigPath]
                    );

                    match self.config.get_kill_policy() {
                        KillPolicy::Suspend => {
                            if precord.process_state != ProcessState::Suspended {
                                try_suspend(precord);
                            }
                        }
                        KillPolicy::Kill => {
                            self.tx_kill.send(precord.gid).unwrap();
                        }
                        KillPolicy::DoNothing => {}
                    }
                    ActionsOnKill::new().run_actions(
                        &self.config,
                        precord,
                        &self.predictor_malware.predictor_behavioural.timesteps,
                        prediction_behavioural,
                    );
                }
            }
        }
    }

    impl<'a> ProcessRecordHandlerLive<'a> {
        pub fn new(
            config: &'a Config,
            tx_kill: Sender<c_ulonglong>,
        ) -> ProcessRecordHandlerLive<'a> {
            ProcessRecordHandlerLive {
                config,
                tx_kill,
                predictor_malware: PredictorMalware::new(config),
            }
        }
    }

    pub struct ProcessRecordHandlerReplay {
        // predictor_behavioural: PredictorHandlerBehavioural<'a>,
        csvwriter: CsvWriter,
        timesteps_stride: usize,
    }

    impl ProcessRecordIOHandler for ProcessRecordHandlerReplay {
        fn handle_io(&mut self, precord: &mut ProcessRecord) {
            let timestep = PredictionRow::from(precord);
            if precord.driver_msg_count % self.timesteps_stride == 0 {
                self.csvwriter
                    .write_debug_csv_files(&precord.appname, precord.gid, &timestep)
                    .expect("Cannot write csv learn file");
            }
            // if let Some(prediction) = self.predictor_behavioural.predict(precord) {
            // if prediction > self.config.threshold_prediction {
            //     println!("Record {}: {}", precord.appname, prediction);
            //     println!("########");
            // }
            // }
        }
    }

    impl ProcessRecordHandlerReplay {
        pub fn new(config: &Config) -> ProcessRecordHandlerReplay {
            ProcessRecordHandlerReplay {
                // predictor_behavioural: PredictorHandlerBehavioural::new(config),
                csvwriter: CsvWriter::from(config),
                timesteps_stride: config.timesteps_stride,
            }
        }
    }

    fn try_suspend(proc: &mut ProcessRecord) {
        proc.process_state = ProcessState::Suspended;
        for pid in &proc.pids {
            unsafe {
                DebugActiveProcess(*pid as u32);
            }
        }
    }
}

mod process_records {
    use std::collections::HashMap;
    use std::os::raw::c_ulonglong;

    use crate::process::ProcessRecord;

    pub struct ProcessRecords {
        pub process_records: HashMap<c_ulonglong, ProcessRecord>,
    }

    impl ProcessRecords {
        pub fn new() -> ProcessRecords {
            ProcessRecords {
                process_records: HashMap::new(),
            }
        }

        pub fn get_precord_by_gid(&self, gid: c_ulonglong) -> Option<&ProcessRecord> {
            self.process_records.get(&gid)
        }

        pub fn get_precord_mut_by_gid(&mut self, gid: c_ulonglong) -> Option<&mut ProcessRecord> {
            self.process_records.get_mut(&gid)
        }

        pub fn insert_precord(&mut self, gid: c_ulonglong, precord: ProcessRecord) {
            self.process_records.insert(gid, precord);
        }
    }
}

pub mod worker {
    use std::path::{Path, PathBuf};

    use bindings::Windows::Win32::Foundation::{CloseHandle, HINSTANCE, PSTR};
    use bindings::Windows::Win32::System::Diagnostics::Debug::GetLastError;
    use bindings::Windows::Win32::System::ProcessStatus::K32GetModuleFileNameExA;
    use bindings::Windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    use windows::Handle;

    use crate::{IOMessage};
    use crate::config::{Config, Param};
    use crate::csvwriter::CsvWriter;
    use crate::process::ProcessRecord;
    use crate::whitelist::WhiteList;
    use crate::worker::process_record_handling::{
        ProcessRecordHandlerReplay, ProcessRecordIOHandler,
    };
    use crate::worker::process_records::ProcessRecords;

    pub trait IOMsgPostProcessor {
        fn postprocess(&mut self, iomsg: &mut IOMessage, precord: &ProcessRecord);
    }

    pub struct IOMsgPostProcessorWriter {
        csv_writer: CsvWriter,
    }

    impl IOMsgPostProcessor for IOMsgPostProcessorWriter {
        fn postprocess(&mut self, iomsg: &mut IOMessage, precord: &ProcessRecord) {
            iomsg.runtime_features.exepath = precord.exepath.clone();
            iomsg.runtime_features.exe_still_exists = true;
            let buf = rmp_serde::to_vec(&iomsg).unwrap();
            self.csv_writer
                .write_irp_csv_files(&buf)
                .expect("Cannot write irp file");
        }
    }

    impl IOMsgPostProcessorWriter {
        pub fn from(config: &Config) -> IOMsgPostProcessorWriter {
            let filename =
                &Path::new(&config[Param::DebugPath]).join(Path::new("drivermessages.txt"));
            IOMsgPostProcessorWriter {
                csv_writer: CsvWriter::from_path(filename),
            }
        }
    }

    pub struct Worker<'a> {
        whitelist: Option<&'a WhiteList>,
        process_records: ProcessRecords,
        process_record_handler: Option<Box<dyn ProcessRecordIOHandler + 'a>>,
        iomsg_postprocessors: Vec<Box<dyn IOMsgPostProcessor>>,
    }

    impl<'a> Worker<'a> {
        pub fn new() -> Worker<'a> {
            Worker {
                whitelist: None,
                process_records: ProcessRecords::new(),
                process_record_handler: None,
                iomsg_postprocessors: vec![],
            }
        }

        pub fn whitelist(mut self, whitelist: &'a WhiteList) -> Worker<'a> {
            self.whitelist = Some(&whitelist);
            self
        }

        pub fn process_record_handler(
            mut self,
            phandler: Box<dyn ProcessRecordIOHandler + 'a>,
        ) -> Worker<'a> {
            self.process_record_handler = Some(phandler);
            self
        }

        pub fn register_iomsg_postprocessor(
            mut self,
            postprecessor: Box<dyn IOMsgPostProcessor>,
        ) -> Worker<'a> {
            self.iomsg_postprocessors.push(postprecessor);
            self
        }

        pub fn build(self) -> Worker<'a> {
            self
        }

        pub fn new_replay(config: &'a Config, whitelist: &'a WhiteList) -> Worker<'a> {
            Worker {
                whitelist: Some(whitelist),
                process_records: ProcessRecords::new(),
                process_record_handler: Some(Box::new(ProcessRecordHandlerReplay::new(config))),
                iomsg_postprocessors: vec![],
            }
        }

        pub fn process_io(&mut self, iomsg: &mut IOMessage) {
            self.register_precord(iomsg);
            if let Some(precord) = self.process_records.get_precord_mut_by_gid(iomsg.gid) {
                precord.add_irp_record(iomsg);
                if let Some(process_record_handler) = &mut self.process_record_handler {
                    process_record_handler.handle_io(precord);
                }
                for postprocessor in &mut self.iomsg_postprocessors {
                    postprocessor.postprocess(iomsg, precord);
                }
            }
        }

        fn register_precord(&mut self, iomsg: &mut IOMessage) {
            match self.process_records.get_precord_by_gid(iomsg.gid) {
                None => {
                    if let Some(exepath) = self.exepath_from_pid(iomsg) {
                        let appname = self
                            .appname_from_exepath(&exepath)
                            .unwrap_or(String::from("DEFAULT"));
                        if !self.is_app_whitelisted(&appname) {
                            if !exepath
                                .parent()
                                .unwrap_or(Path::new("/"))
                                .starts_with(r"C:\Windows\System32")
                            {
                                let precord = ProcessRecord::from(
                                    iomsg,
                                    appname,
                                    exepath.clone(),
                                );
                                self.process_records.insert_precord(iomsg.gid, precord);
                            }
                        }
                    }
                }
                Some(_) => {}
            }
        }

        fn is_app_whitelisted(&self, appname: &str) -> bool {
            match self.whitelist {
                None => false,
                Some(wl) => wl.is_app_whitelisted(appname),
            }
        }

        fn exepath_from_pid(&self, iomsg: &IOMessage) -> Option<PathBuf> {
            let pid = iomsg.pid.clone() as u32;
            unsafe {
                let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if handle.is_invalid() || handle.0 == 0 {
                    //println!("ERROR: Invalid Handle: {} - {}", drivermsg.pid, GetLastError().0);
                } else {
                    let mut buffer: Vec<u8> = Vec::new();
                    buffer.resize(1024, 0);
                    let res = K32GetModuleFileNameExA(
                        handle,
                        HINSTANCE(0),
                        PSTR(buffer.as_mut_ptr()),
                        1024,
                    );
                    if res == 0 {
                        let _errorcode = GetLastError().0;
                    } else {
                        let pathbuf = PathBuf::from(
                            String::from_utf8_unchecked(buffer).trim_matches(char::from(0)),
                        );
                        return Some(pathbuf);
                    }
                    CloseHandle(handle);
                }
            }
            None
        }

        fn appname_from_exepath(&self, exepath: &PathBuf) -> Option<String> {
            if let Some(filename) = exepath.file_name() {
                Some(filename.to_string_lossy().to_string())
            } else {
                None
            }
        }
    }
}
