use std::collections::HashMap;
use std::os::raw::{c_ulong, c_ulonglong};
use std::path::{Path, PathBuf};
use std::{fs, thread, time};
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};

use bindings::Windows::Win32::Foundation::{CloseHandle, HINSTANCE, PSTR};
use bindings::Windows::Win32::System::Diagnostics::Debug::GetLastError;
use bindings::Windows::Win32::System::ProcessStatus::K32GetModuleFileNameExA;
use bindings::Windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use bindings::Windows::Win32::System::Diagnostics::Debug::{DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit};
use log::error;

use crate::actions_on_kill::ActionsOnKill;
use crate::config::{Config, KillPolicy, Param};
use crate::csvwriter::CsvWriter;
use crate::driver_com::shared_def::{CDriverMsg, IOMessage, RuntimeFeatures};
use crate::driver_com::Driver;
use crate::prediction::input_tensors::VecvecCappedF32;
use crate::prediction_malware::TfLiteMalware;
use crate::prediction_static::TfLiteStatic;
use crate::prediction_novelty::TfLiteNovelty;
use crate::process::procs::Procs;
use crate::process::{ProcessRecord, ProcessState};
use crate::whitelist::WhiteList;

pub fn process_drivermessage<'a>(
    tx_kill: &Sender<c_ulonglong>,
    config: &'a Config,
    whitelist: &'a WhiteList,
    procs: &mut Procs<'a>,
    predictions_static: &mut HashMap<String, f32>,
    tflite_malware: &TfLiteMalware,
    tflite_static: &TfLiteStatic,
    tflite_novelty: &TfLiteNovelty,
    iomsg: &mut IOMessage,
) -> Result<(), ()> {
    // continue ? Processes without path should be ignored
    let mut opt_index = procs.get_by_gid_index(iomsg.gid);
    if opt_index.is_none() {
        if let Some(exepath) = exepath_from_pid(iomsg) {
            iomsg.runtime_features.exepath = exepath.clone();
            iomsg.runtime_features.exe_still_exists = true;
            let appname = appname_from_exepath(&exepath).unwrap_or(String::from("DEFAULT"));
            if !whitelist.is_app_whitelisted(&appname) {
                if !exepath.parent().unwrap_or(Path::new("/")).starts_with(r"C:\Windows\System32") {
                    let record = ProcessRecord::from(&config, iomsg, appname, exepath.clone(), tflite_static.make_prediction(&exepath));
                    procs.add_record(record);
                    opt_index = procs.get_by_gid_index(iomsg.gid);
                }
            }
        } else {
            iomsg.runtime_features.exe_still_exists = false;
        }
    }
    if opt_index.is_some() {
        let mut procs_tmp = procs.procs.lock().unwrap();
        let mut proc = procs_tmp.get_mut(opt_index.unwrap()).unwrap();
        proc.add_irp_record(iomsg);

        if cfg!(feature = "malware") {
            process_drivermessage_malware(&tx_kill, &config, &whitelist, &mut proc, predictions_static, &tflite_malware, &tflite_static, iomsg).unwrap();
        }
        if cfg!(feature = "novelty") {
            process_drivermessage_novelty(&tx_kill, &config, &whitelist, &mut proc, predictions_static, &tflite_novelty, iomsg).unwrap();
        }
        Ok(())
    } else {
        Err(())
    }
}

pub fn process_drivermessage_malware<'a>(
    tx_kill: &Sender<c_ulonglong>,
    config: &'a Config,
    whitelist: &'a WhiteList,
    proc: &mut ProcessRecord<'a>,
    predictions_static: &mut HashMap<String, f32>,
    tflite_malware: &TfLiteMalware,
    tflite_static: &TfLiteStatic,
    iomsg: &mut IOMessage,
) -> Result<(), ()> {
    if let Some((predmtrx, prediction)) = proc.eval_malware(tflite_malware) {
        println!("{} - {}", proc.appname, prediction);
        if prediction > config.threshold_prediction || proc.appname.contains("TEST-OLRANSOM")
        // || proc.appname.contains("msedge.exe") //For testing
        {
            println!("Ransomware Suspected!!!");
            eprintln!("proc.gid = {:?}", proc.gid);
            println!("{}", proc.appname);
            println!("with {} certainty", prediction);
            println!("\nSee {}\\threats for details.", config[Param::DebugPath]);
            println!(
                "\nPlease update {}\\exclusions.txt if it's a false positive",
                config[Param::ConfigPath]
            );

            match config.get_kill_policy() {
                KillPolicy::Suspend => {
                    if proc.process_state != ProcessState::Suspended {
                        try_suspend(proc);
                    }
                }
                KillPolicy::Kill => { tx_kill.send(proc.gid).unwrap();/* try_kill(driver, proc)*/ }
            }
            ActionsOnKill::new().run_actions(&config, &proc, &predmtrx, prediction);
        }
    }
    Ok(())
}

pub fn process_drivermessage_novelty<'a>(
    tx_kill: &Sender<c_ulonglong>,
    config: &'a Config,
    whitelist: &'a WhiteList,
    proc: &mut ProcessRecord<'a>,
    predictions_static: &mut HashMap<String, f32>,
    tflite_novelty: &TfLiteNovelty,
    iomsg: &mut IOMessage,
) -> Result<(), ()> {
    if let Some((predmtrx, prediction)) = proc.eval_novelty(tflite_novelty) {
        println!("{} - {}", proc.appname, prediction);
        if prediction > config.threshold_prediction || proc.appname.contains("TEST-OLRANSOM")
        // || proc.appname.contains("msedge.exe") // For testing
        {
            println!("Novelty : Ransomware Suspected!!!");
            eprintln!("proc.gid = {:?}", proc.gid);
            println!("{}", proc.appname);
            println!("with {} certainty", prediction);
            println!("\nSee {}\\threats for details.", config[Param::DebugPath]);
            println!(
                "\nPlease update {}\\exclusions.txt if it's a false positive",
                config[Param::ConfigPath]
            );

            match config.get_kill_policy() {
                KillPolicy::Suspend => {
                    if proc.process_state != ProcessState::Suspended {
                        try_suspend(proc);
                    }
                }
                KillPolicy::Kill => { tx_kill.send(proc.gid).unwrap(); }
            }
            ActionsOnKill::new().run_actions(&config, &proc, &predmtrx, prediction);
        }
    }
    Ok(())
}

pub fn process_drivermessage_replay<'a>(
    config: &'a Config,
    procs: &mut Procs<'a>,
    tflite_malware: &TfLiteMalware,
    iomsg: &IOMessage,
) {
    let mut opt_index = procs.get_by_gid_index(iomsg.gid);
    if opt_index.is_none() {
        let exepath = iomsg.runtime_features.exepath.clone();
        let appname = appname_from_exepath(&exepath).unwrap_or(String::from("DEFAULT"));
        let record = ProcessRecord::from(&config, iomsg, appname, exepath, None);
        procs.add_record(record);
        opt_index = procs.get_by_gid_index(iomsg.gid);
    }
    if opt_index.is_some() {
        let mut procs_tmp = procs.procs.lock().unwrap();
        let proc = procs_tmp.get_mut(opt_index.unwrap()).unwrap();
        proc.add_irp_record(iomsg);
        proc.write_learn_csv();
        if let Some((_predmtrx, prediction)) = proc.eval_malware(tflite_malware) {
            if prediction > config.threshold_prediction {
                println!("Record {}: {}", proc.appname, prediction);
                println!("########");
            }
        }
    }
}

fn exepath_from_pid(iomsg: &IOMessage) -> Option<PathBuf> {
    let pid = iomsg.pid.clone() as u32;
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if handle.is_invalid() || handle.0 == 0 {
            //println!("ERROR: Invalid Handle: {} - {}", drivermsg.pid, GetLastError().0);
        } else {
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(1024, 0);
            let res = K32GetModuleFileNameExA(handle, HINSTANCE(0), PSTR(buffer.as_mut_ptr()), 1024);
            if res == 0 {
                let _errorcode = GetLastError().0;
            } else {
                let pathbuf =
                    PathBuf::from(String::from_utf8_unchecked(buffer).trim_matches(char::from(0)));
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

fn try_suspend(
    proc: &mut ProcessRecord,
) {
    proc.process_state = ProcessState::Suspended;
    for pid in &proc.pids {
        unsafe {
                DebugActiveProcess(*pid as u32);
        }
    }
}

fn try_awake(proc: &mut ProcessRecord, kill_proc_on_exit: bool) {
    for pid in &proc.pids {
        unsafe {
            DebugSetProcessKillOnExit(kill_proc_on_exit);
            DebugActiveProcessStop(*pid as u32);
        }
    }
    proc.process_state = ProcessState::Running;
}

fn try_kill(
    driver: &Driver,
    proc: &mut ProcessRecord,
) {
    let hres = driver.try_kill(proc.gid).expect("Cannot kill process");
    if hres.is_err() {
        error!("Cannot kill process {} with gid {}", proc.appname, proc.gid);
    }
    proc.process_state = ProcessState::Killed;
    proc.time_killed = Some(SystemTime::now());
}

pub fn record_drivermessage<'a>(
    path: &Path,
    pids_exepaths: &mut HashMap<c_ulong, PathBuf>,
    c_drivermsg: &CDriverMsg,
) {
    let irp_csv = path;
    let mut irp_csv_writer;
    irp_csv_writer = CsvWriter::from_path(irp_csv);
    let mut iomsg = IOMessage::from(&c_drivermsg);

    let o_exepath: Option<PathBuf>;

    if let Some(exepath) = exepath_from_pid(&iomsg) {
        pids_exepaths.insert(iomsg.pid, exepath.clone()); //because pids can be reused
        o_exepath = Some(exepath)
    } else {
        o_exepath = pids_exepaths.get(&iomsg.pid).cloned();
    }

    if let Some(exepath) = o_exepath {
        let exepath_exists = exepath.exists();
        let runtime_features = RuntimeFeatures {
            exepath: exepath,
            exe_still_exists: exepath_exists,
        };
        iomsg.runtime_features = runtime_features;
        let buf = rmp_serde::to_vec(&iomsg).unwrap();
        irp_csv_writer
            .write_irp_csv_files(&buf)
            .expect("Cannot write irps file");
    }
    iomsg.file_size = match PathBuf::from(&c_drivermsg.filepath.to_string_ext(c_drivermsg.extension)).metadata() {
        Ok(f) => f.len() as i64,
        Err(e) => -1,
    }
}

/// Kills processes that have been long suspended (120s).
/// Commercial feature: awakes suspended processes on end user command.
pub fn process_suspended_procs<'a>(tx_kill: &Sender<c_ulonglong>, config: &Config, procs: &mut Procs<'a>) {
    let now = SystemTime::now();
    for proc in &mut procs.procs.lock().unwrap().iter_mut() {
        if proc.process_state == ProcessState::Suspended {
            if now.duration_since(proc.time_suspended.unwrap_or(now)).unwrap_or(Duration::from_secs(0)) > Duration::from_secs(120) {
                try_awake(proc, true);
                tx_kill.send(proc.gid).unwrap();
                ActionsOnKill::new().run_actions(&config, &proc, &proc.prediction_matrix.clone(), proc.predictions.get_last_prediction().unwrap_or(0.0));
            }
        }
    }

    let command_files_path = Path::new(&config[Param::ConfigPath]).join("tmp");
    if command_files_path.exists() {
        for command_file_dir_entry in fs::read_dir(command_files_path).unwrap() {
            let pbuf_command_file = command_file_dir_entry.unwrap().path();
            if pbuf_command_file.is_file() {
                if let Some(ostr_fname) = pbuf_command_file.file_name() {
                    if let Some(fname) = ostr_fname.to_str() {
                        if let Some( (command, str_gid) ) = fname.split_once("_") {
                            if let Ok(gid) = str_gid.parse::<u64>() {
                                if let Some(proc_index) = procs.get_by_gid_index(gid) {
                                    let mut procs_tmp = procs.procs.lock().unwrap();
                                    let proc = procs_tmp.get_mut(proc_index).unwrap();
                                    match command {
                                        "A" => {
                                            try_awake(proc, false);
                                        }
                                        "K" => {
                                            try_awake(proc, true);
                                            tx_kill.send(proc.gid).unwrap();
                                        }
                                        &_ => {}
                                    }
                                    if ! fs::remove_file(pbuf_command_file.as_path()).is_ok() {
                                        println!("cannot remove");
                                        eprintln!("pbuf_command_file = {:?}", pbuf_command_file);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
