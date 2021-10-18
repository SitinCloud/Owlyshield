use crate::actions_on_kill::ActionsOnKill;
use crate::config;
use crate::config::{Config, Param};
use crate::csvwriter::CsvWriter;
use crate::driver_com::shared_def::{C_DriverMsg, DriverMsg, RuntimeFeatures};
use crate::driver_com::Driver;
use crate::prediction::predmtrx::VecvecCappedF32;
use crate::prediction::TfLite;
use crate::process::procs::Procs;
use crate::process::ProcessRecord;
use crate::whitelist::WhiteList;
use log::{error, info, trace};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use sysinfo::{Pid, ProcessExt, RefreshKind, SystemExt};

pub fn process_irp<'a>(
    driver: &Driver,
    config: &'a Config,
    whitelist: &'a WhiteList,
    procs: &mut Procs<'a>,
    tflite: &TfLite,
    drivermsg: &DriverMsg,
) -> bool {
    // continue ? Processes without path should be ignored
    let mut opt_index = procs.get_by_gid_index(drivermsg.gid);
    if opt_index.is_none() {
        if let Some((appname, exepath)) = appname_from_pid(drivermsg) {
            if !whitelist.is_app_whitelisted(&appname) {
                println!("ADD RECORD {} - {}", drivermsg.gid, appname);
                let record = ProcessRecord::from(&config, drivermsg, appname, exepath);
                procs.add_record(record);
                opt_index = procs.get_by_gid_index(drivermsg.gid);
            }
        }
    }
    if opt_index.is_some() {
        let proc = procs.procs.get_mut(opt_index.unwrap()).unwrap();
        proc.add_irp_record(drivermsg);
        //println!("RECORD - {:?}", proc.appname);
        if let Some((predmtrx, prediction)) = proc.eval(tflite) {
            if prediction > 0.5 || proc.appname.contains("TEST-OLRANSOM")
            //|| proc.appname.contains("msedge.exe") //For testing
            {
                try_kill(&driver, &config, proc, &predmtrx, prediction);
            }
        }
        true
    } else {
        false
    }
}

pub fn process_irp_deser<'a>(
    config: &'a Config,
    whitelist: &'a WhiteList,
    procs: &mut Procs<'a>,
    drivermsg: &DriverMsg,
) {
    let mut opt_index = procs.get_by_gid_index(drivermsg.gid);
    if opt_index.is_none() {
        let appname = drivermsg.runtime_features.app_name.clone();
        let exepath = drivermsg.runtime_features.exepath.clone();
        if !whitelist.is_app_whitelisted(&appname) {
            println!("ADD RECORD {} - {}", drivermsg.gid, appname);
            let record = ProcessRecord::from(&config, drivermsg, appname, exepath);
            procs.add_record(record);
            opt_index = procs.get_by_gid_index(drivermsg.gid);
        }
    }
    if opt_index.is_some() {
        let proc = procs.procs.get_mut(opt_index.unwrap()).unwrap();
        proc.add_irp_record(drivermsg);
        proc.write_learn_csv();
    }
}

fn appname_from_pid(drivermsg: &DriverMsg) -> Option<(String, PathBuf)> {
    let s = sysinfo::System::new_with_specifics(RefreshKind::new().with_processes());
    if let Some(pidproc) = s.processes().get(&(drivermsg.pid.clone() as Pid)) {
        Some((String::from(pidproc.name()), pidproc.exe().to_path_buf()))
    } else {
        None
    }
}

fn try_kill(
    driver: &Driver,
    config: &Config,
    proc: &mut ProcessRecord,
    pred_mtrx: &VecvecCappedF32,
    prediction: f32,
) {
    let hres = driver.try_kill(proc.gid).expect("Cannot kill process");
    if hres.is_err() {
        error!("Cannot kill process {} with gid {}", proc.appname, proc.gid);
    }
    proc.time_killed = Some(SystemTime::now());
    let actions_on_kill = ActionsOnKill::from(&config);
    actions_on_kill.run_actions(&config, &proc, pred_mtrx, prediction);
}

pub fn save_irp<'a>(
    config: &'a Config,
    procs: &mut Procs<'a>,
    path: &Path,
    c_drivermsg: &C_DriverMsg,
) {
    let irp_csv = path;
    let mut irp_csv_writer;
    irp_csv_writer = CsvWriter::from_path(irp_csv);
    let mut drivermsg = DriverMsg::from(&c_drivermsg);

    let mut opt_index = procs.get_by_gid_index(c_drivermsg.gid);
    if opt_index.is_none() {
        if let Some((appname, exepath)) = appname_from_pid(&drivermsg) {
            drivermsg.runtime_features.app_name = appname.clone();
            let record = ProcessRecord::from(&config, &drivermsg, appname.clone(), exepath);
            procs.add_record(record);
            opt_index = procs.get_by_gid_index(c_drivermsg.gid);
        }
    }
    if opt_index.is_some() {
        let proc = procs.procs.get_mut(opt_index.unwrap()).unwrap();
        proc.add_irp_record(&drivermsg);
        let runtime_features = RuntimeFeatures {
            app_name: proc.appname.clone(),
            exepath: proc.exepath.clone(),
            exe_still_exists: proc.exe_still_exists,
        };
        drivermsg.runtime_features = runtime_features;
    }
    if !drivermsg.runtime_features.app_name.is_empty() {
        let buf = rmp_serde::to_vec(&drivermsg).unwrap();
        irp_csv_writer
            .write_irp_csv_files(&buf)
            .expect("Cannot write irps file");
    }
}
