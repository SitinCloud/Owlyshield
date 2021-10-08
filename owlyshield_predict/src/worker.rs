use crate::actions_on_kill::ActionsOnKill;
use crate::config::{Config, Param};
use crate::driver_com::shared_def::DriverMsg;
use crate::driver_com::Driver;
use crate::prediction::predmtrx::VecvecCappedF32;
use crate::prediction::TfLite;
use crate::process::procs::Procs;
use crate::process::ProcessRecord;
use crate::whitelist::WhiteList;
use std::error::Error;
use std::path::PathBuf;
use std::time::SystemTime;
use sysinfo::{Pid, ProcessExt, RefreshKind, SystemExt};
use log::{error, info, trace};

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
        if let Some((predmtrx, prediction)) = proc.eval(tflite) {
            if prediction > 0.5
                || proc.appname.contains("TEST-OLRANSOM")
            {
                try_kill(&driver, &config, proc, &predmtrx, prediction);
            }
        }
        true
    } else {
        false
    }
}

fn appname_from_pid(drivermsg: &DriverMsg) -> Option<(String, PathBuf)> {
    //appname, exepath
    //    let s = sysinfo::System::new_all();
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
