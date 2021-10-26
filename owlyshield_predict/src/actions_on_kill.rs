use crate::config::{Config, Param};
use crate::notifications::toast;
use crate::prediction::predmtrx::{MatrixF32, VecvecCappedF32};
use crate::process::ProcessRecord;
use crate::utils::{FILE_TIME_FORMAT, LONG_TIME_FORMAT, TIME_FORMAT};
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

pub struct WriteReportHtmlFile();

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
                Box::new(WriteReportHtmlFile()),
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
        let snow = now.format(FILE_TIME_FORMAT).to_string();
        let report_dir = Path::new(&config[Param::ConfigPath]).join("menaces");
        if !report_dir.exists() {
            error!(
                "Cannot Write report file: dir does not exist: {}",
                report_dir.to_str().unwrap()
            );
        } else {
            let temp = report_dir.join(Path::new(&format!(
                "{}_{}_report_{}.log",
                &proc.appname.replace(".", "_"),
                snow,
                &proc.gid,
            )));
            let report_path = temp.to_str().unwrap_or("");
            println!("{}", report_path);
            let mut file = File::create(Path::new(&report_path))?;
            let stime_started: DateTime<Local> = proc.time_started.into();
            file.write_all(b"Owlyshield report file\n\n")?;
            file.write_all(format!("Ransomware detected running from: {}\n\n", proc.appname).as_bytes())?;
            file.write_all(
                format!("Started at {}\n", stime_started.format(LONG_TIME_FORMAT)).as_bytes(),
            )?;
            file.write_all(
                format!(
                    "Killed at {}\n\n",
                    DateTime::<Local>::from(proc.time_killed.unwrap_or(SystemTime::now()))
                        .format(LONG_TIME_FORMAT)
                )
                .as_bytes(),
            )?;
            file.write_all(b"Files modified:\n")?;
            for f in &proc.file_paths_u {
                file.write_all(format!("\t{:?}\n", f).as_bytes())?;
            }
        }
        Ok(())
    }
}

impl ActionOnKill for WriteReportHtmlFile {
    fn run(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        _prediction: f32,
    ) -> Result<(), Box<dyn Error>> {
        let now: DateTime<Local> = SystemTime::now().into();
        let snow = now.format(FILE_TIME_FORMAT).to_string();
        let report_dir = Path::new(&config[Param::ConfigPath]).join("menaces");
        if !report_dir.exists() {
            error!(
                "Cannot Write report file: dir does not exist: {}",
                report_dir.to_str().unwrap()
            );
        } else {
            let temp = report_dir.join(Path::new(&format!(
                "{}_{}_report_{}.html",
                &proc.appname.replace(".", "_"),
                snow,
                &proc.gid,
            )));
            let report_path = temp.to_str().unwrap_or("");
            println!("{}", report_path);
            let mut file = File::create(Path::new(&report_path))?;
            let stime_started: DateTime<Local> = proc.time_started.into();
            file.write_all(b"<!DOCTYPE html><html><head>")?;
            file.write_all(format!("<title>Owlyshield Report {}</title><link rel='icon' href='https://static.thenounproject.com/png/3420953-200.png'/><meta name='viewport' content='width=device-width, initial-scale=1'>\n", proc.gid).as_bytes())?;
            file.write_all(b"<style>body{font-family: Arial;}.tab{overflow: hidden;border: 1px solid #ccc;background-color: #f1f1f1;}.tab button{background-color: inherit;    float: inherit;    border: none;    outline: none;    cursor: pointer;    padding: 14px 16px;    transition: 0.3s;    font-size: 17px;    width: 33%;}.tab button:hover{    background-color: #ddd;}.tab button.active{	background-color: #ccc;}.tabcontent{	display: none;	padding: 6px 12px;/*border: 1px solid #ccc;border-top: none;*/}table{	width: 80%;	align: center;	margin-left: auto;	margin-right: auto;}th{	background-color: red;}select{	width: 100%;    align: center;	margin-left: auto;	margin-right: auto;}</style>")?;
            file.write_all(b"</head><body>\n")?;
            file.write_all(b"<table><tr><th><h1><b>Owlyshield detected a </b><span style='color: white;'>ransomware</span><b>!</b></h1></th></tr></table>\n")?;
            file.write_all(format!("</br><table><tr><td style='text-align: center;'><h3>Ransomware detected running from: <span style='color: red;'>{}</span></h3></td></tr><tr valign='top'><td style='text-align: left;'><ul><li>Started on<b> {}</b></li><li>Killed on<b> {}</b></li></ul></tr></table>\n", proc.exepath.to_string_lossy().to_string(), stime_started.format(LONG_TIME_FORMAT), DateTime::<Local>::from(proc.time_killed.unwrap_or(SystemTime::now())).format(LONG_TIME_FORMAT)).as_bytes())?;
            file.write_all(b"<table><tr><td><div class='tab'>\n")?;
            // file.write_all(b"<button class="tablinks" onclick="openTab(event,'instructions')" id="defaultOpen">Instructions</button>")?;
            file.write_all(format!("<button class='tablinks' onclick=\"openTab(event,'files_u')\">Files updated ({})</button>\n", &proc.file_paths_u.len()).as_bytes());
            file.write_all(format!("<button class='tablinks' onclick=\"openTab(event,'files_c')\">Files created ({})</button>\n", &proc.file_paths_c.len()).as_bytes());
            file.write_all(b"</div></td></tr></table>\n")?;
            file.write_all(b"<div id='files_u' class='tabcontent'><table><tr><td><select name='files_u' size='30' multiple='multiple'>\n")?;
            for f in &proc.file_paths_u {
                file.write_all(format!("<option value='{}'>{}</option>\n", f, f).as_bytes())?;
            }
            file.write_all(b"</select></td></tr></table></div>\n")?;
            file.write_all(b"<div id='files_c' class='tabcontent'><table><tr><td><select name='files_u' size='30' multiple='multiple'>\n")?;
            for f in &proc.file_paths_c {
                file.write_all(format!("<option value='{}'>{}</option>\n", f, f).as_bytes())?;
            }
            file.write_all(b"</select></td></tr></table></div>\n")?;
            file.write_all(b"<script>function openTab(evt, tab) {	var i, tabcontent, tablinks;	tabcontent = document.getElementsByClassName('tabcontent');	for (i = 0; i < tabcontent.length; i++) {		tabcontent[i].style.display = 'none';	}	tablinks = document.getElementsByClassName('tablinks');	for (i = 0; i < tablinks.length; i++) {		tablinks[i].className = tablinks[i].className.replace(' active', '');	}	document.getElementById(tab).style.display = 'block';	evt.currentTarget.className += ' active';}document.getElementById('defaultOpen').click();</script>\n")?;
            file.write_all(b"</body></html>")?;
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
