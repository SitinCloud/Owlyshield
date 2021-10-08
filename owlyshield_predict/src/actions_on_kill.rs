use crate::config::{Config, Param};
use crate::notifications::toast;
use crate::prediction::predmtrx::{MatrixF32, VecvecCappedF32};
use crate::process::ProcessRecord;
use crate::utils::TIME_FORMAT;
use chrono::{DateTime, Local, Utc};
use log::{error, info, trace};
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

pub struct ActionsOnKill<'a> {
    actions: Vec<Box<dyn ActionOnKill>>,
    config: &'a Config,
}

pub struct WriteReportFile();

pub struct PostReport();

pub struct ToastIncident();

pub trait ActionOnKill {
    fn run(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        pred_mtrx: &VecvecCappedF32,
        prediction: f32,
    ) -> Result<(), Box<dyn Error>>;
}

impl ActionsOnKill<'_> {
    pub fn from(config: &Config) -> ActionsOnKill {
        ActionsOnKill {
            actions: vec![
                Box::new(WriteReportFile()),
                Box::new(PostReport()),
                Box::new(ToastIncident()),
            ],
            config: config,
        }
    }

    pub fn run_actions(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        pred_mtrx: &VecvecCappedF32,
        prediction: f32,
    ) {
        for action in &self.actions {
            action
                .run(config, proc, pred_mtrx, prediction)
                .unwrap_or_else(|e| error!("Error with post_kill action: {}", e));
        }
    }
}

impl ActionOnKill for WriteReportFile {
    fn run(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        _prediction: f32,
    ) -> Result<(), Box<dyn Error>> {
        let now: DateTime<Local> = SystemTime::now().into();
        let snow = now.format(TIME_FORMAT).to_string();
        let report_dir = Path::new(&config[Param::ConfigPath]).join("menaces");
        if !report_dir.exists() {
            error!(
                "Cannot Write report file: dir does not exist: {}",
                report_dir.to_str().unwrap()
            );
        } else {
            let temp = report_dir.join(Path::new(&format!(
                "{}_{}_report.txt",
                &proc.appname.replace(".", "_"),
                snow
            )));
            let report_path = temp.to_str().unwrap_or("");
            println!("{}", report_path);
            let mut file = File::create(Path::new(&report_path))?;
            let stime_started: DateTime<Local> = proc.time_started.into();
            file.write_all(format!("Ransomware detected: {}\n", proc.appname).as_bytes())?;
            file.write_all(
                format!("Started at {}\n", stime_started.format(TIME_FORMAT)).as_bytes(),
            )?;
            file.write_all(
                format!(
                    "Killed at {}\n",
                    DateTime::<Local>::from(proc.time_killed.unwrap_or(SystemTime::now()))
                        .format(TIME_FORMAT)
                )
                .as_bytes(),
            )?;
            file.write_all(b"Files modified:")?;
            for f in &proc.file_paths_u {
                file.write_all(format!("{:?}\n", f).as_bytes())?;
            }
        }

        Ok(())
    }
}

impl ActionOnKill for PostReport {
    fn run(
        &self,
        _config: &Config,
        _proc: &ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        _prediction: f32,
    ) -> Result<(), Box<dyn Error>> {
        //TODO
        Ok(())
    }
}

impl ActionOnKill for ToastIncident {
    fn run(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        _prediction: f32,
    ) -> Result<(), Box<dyn Error>> {
        toast(config, &format!("Ransomware detected! {}", proc.appname));
        Ok(())
    }
}

impl Debug for ActionsOnKill<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionsOnKill").finish()
    }
}
