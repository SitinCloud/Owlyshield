use crate::actions_on_kill::ActionsOnKill;
use crate::config;
use crate::config::{Config, Param};
use crate::csvwriter::CsvWriter;
use crate::driver_com::shared_def::{CDriverMsg, DriverMsg, RuntimeFeatures};
use crate::driver_com::Driver;
use crate::prediction::predmtrx::VecvecCappedF32;
use crate::prediction::TfLite;
use crate::process::procs::Procs;
use crate::process::ProcessRecord;
use crate::whitelist::WhiteList;
use bindings::Windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, PSTR};
use bindings::Windows::Win32::System::Diagnostics::Debug::GetLastError;
use bindings::Windows::Win32::System::LibraryLoader::GetModuleFileNameA;
use bindings::Windows::Win32::System::ProcessStatus::K32GetModuleFileNameExA;
use bindings::Windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use log::{error, info, trace};
use std::collections::HashMap;
use std::error::Error;
use std::os::raw::c_ulong;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use sysinfo::{Pid, ProcessExt, RefreshKind, SystemExt};

pub fn process_irp<'a>(
    driver: &Driver,
    config: &'a Config,
    whitelist: &'a WhiteList,
    procs: &mut Procs<'a>,
    tflite: &TfLite,
    drivermsg: &mut DriverMsg,
) -> bool {
    // continue ? Processes without path should be ignored
    let mut opt_index = procs.get_by_gid_index(drivermsg.gid);
    if opt_index.is_none() {
        //        if let Some((appname, exepath)) = appname_from_pid(drivermsg) {
        if let Some(exepath) = exepath_from_pid(drivermsg) {
            drivermsg.runtime_features.exepath = exepath.clone();
            drivermsg.runtime_features.exe_still_exists = true;
            let appname = appname_from_exepath(&exepath).unwrap_or(String::from("DEFAULT"));
            if !whitelist.is_app_whitelisted(&appname) {
                //println!("ADD RECORD {} - {}", drivermsg.gid, appname);
                let record = ProcessRecord::from(&config, drivermsg, appname, exepath.clone());
                procs.add_record(record);
                opt_index = procs.get_by_gid_index(drivermsg.gid);
            }
        } else {
            drivermsg.runtime_features.exe_still_exists = false;
        }
    }
    if opt_index.is_some() {
        let proc = procs.procs.get_mut(opt_index.unwrap()).unwrap();
        proc.add_irp_record(drivermsg);
        //println!("RECORD - {:?}", proc.appname);
        proc.write_learn_csv(); //debug
        if let Some((predmtrx, prediction)) = proc.eval(tflite) {
            if prediction > 0.5 || proc.appname.contains("TEST-OLRANSOM")
            //|| proc.appname.contains("msedge.exe") //For testing
            {
                println!("Ransomware Suspected!!!");
                println!("{}", proc.appname);
                println!("with {} certainty", prediction);
                println!("\nSee {}\\menaces for details.", config[Param::DebugPath]);
                println!("\nPlease update {}\\exclusions.txt if it's a false positive", config[Param::ConfigPath]);
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
    tflite: &TfLite,
    drivermsg: &DriverMsg,
) {
    let mut opt_index = procs.get_by_gid_index(drivermsg.gid);
    if opt_index.is_none() {
        let exepath = drivermsg.runtime_features.exepath.clone();
        let appname = appname_from_exepath(&exepath).unwrap_or(String::from("DEFAULT"));
        //if appname.contains("Virus") {
        //println!("ADD RECORD {} - {}", drivermsg.gid, appname);
        let record = ProcessRecord::from(&config, drivermsg, appname, exepath);
        procs.add_record(record);
        opt_index = procs.get_by_gid_index(drivermsg.gid);
        // }
    }
    if opt_index.is_some() {
        let proc = procs.procs.get_mut(opt_index.unwrap()).unwrap();
        proc.add_irp_record(drivermsg);
        proc.write_learn_csv();
        if let Some((predmtrx, prediction)) = proc.eval(tflite) {
            if prediction > 0.5 {
                println!("Record {}: {}", proc.appname, prediction);
                //println!("Matrinx");
                //println!("{:?}", predmtrx.elems);
                println!("########");
            }
        }
    }
}

fn exepath_from_pid(drivermsg: &DriverMsg) -> Option<PathBuf> {
    let pid = drivermsg.pid.clone() as u32;
    //println!("PID {}", pid);
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if handle.is_invalid() || handle.0 == 0 {
            //println!("ERROR: Invalid Handle: {} - {}", drivermsg.pid, GetLastError().0);
        } else {
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(1024, 0);
            //println!("HANDLE is {:?}", handle);
            // let res = GetModuleFileNameA(HINSTANCE(handle.0), PSTR(buffer.as_mut_ptr()), 1024);
            let res =
                K32GetModuleFileNameExA(handle, HINSTANCE(0), PSTR(buffer.as_mut_ptr()), 1024);
            if res == 0 {
                let _errorcode = GetLastError().0;
                /*if errorcode != 31 {
                    println!("ERROR: {} - {:?}", errorcode, drivermsg);
                }*/
            } else {
                let pathbuf =
                    PathBuf::from(String::from_utf8_unchecked(buffer).trim_matches(char::from(0)));
                //println!("PATHBUF: {:?}", pathbuf);
                //println!("FILENAME: {}", appname_from_exepath(&pathbuf).unwrap_or("DEFAULT".parse().unwrap()));
                return Some(pathbuf);
            }
            CloseHandle(handle);
        }
    }
    None
}

fn appname_from_exepath(exepath: &PathBuf) -> Option<String> {
    if let Some(filename) = exepath.file_name() {
        Some(filename.to_string_lossy().to_string())
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
    path: &Path,
    pids_exepaths: &mut HashMap<c_ulong, PathBuf>,
    c_drivermsg: &CDriverMsg,
) {
    let irp_csv = path;
    let mut irp_csv_writer;
    irp_csv_writer = CsvWriter::from_path(irp_csv);
    let mut drivermsg = DriverMsg::from(&c_drivermsg);

    let o_exepath: Option<PathBuf>;

    if let Some(exepath) = exepath_from_pid(&drivermsg) {
        pids_exepaths.insert(drivermsg.pid, exepath.clone()); //because pids can be reused
        o_exepath = Some(exepath)
    } else {
        o_exepath = pids_exepaths.get(&drivermsg.pid).cloned();
    }

    if let Some(exepath) = o_exepath {
        let exepath_exists = exepath.exists();
        let runtime_features = RuntimeFeatures {
            exepath: exepath,
            exe_still_exists: exepath_exists,
        };
        drivermsg.runtime_features = runtime_features;
        let buf = rmp_serde::to_vec(&drivermsg).unwrap();
        irp_csv_writer
            .write_irp_csv_files(&buf)
            .expect("Cannot write irps file");
    }
}
