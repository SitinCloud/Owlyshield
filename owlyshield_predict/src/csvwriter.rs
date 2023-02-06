//! Used to dump ProcessRecords to a csv file to create Learning samples that will be used to train the model.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use chrono::{DateTime, Utc};

use crate::config::{Config, Param};
use crate::predictions::prediction::input_tensors::Timestep;

#[derive(Debug)]
pub struct CsvWriter {
    last_write_time: Option<SystemTime>,
    path: PathBuf,
    separator: String,
}

impl CsvWriter {
    pub fn from(config: &Config) -> CsvWriter {
        CsvWriter {
            last_write_time: None,
            path: Path::new(&config[Param::DebugPath]).join(Path::new("learn.csv")),
            separator: String::from(";"),
        }
    }

    pub fn from_path(path: &Path) -> CsvWriter {
        CsvWriter {
            last_write_time: None,
            path: PathBuf::from(path),
            separator: String::from(";"),
        }
    }

    pub fn write_debug_csv_files(
        &mut self,
        appname: &str,
        gid: u64,
        predrow: &Timestep,
        time: SystemTime,
    ) -> Result<(), std::io::Error> {
        let predrow_vec = predrow.to_vec_f32();
        let datetime : DateTime<Utc> = time.into();
        let mut process_vec = vec![String::from(appname), gid.to_string(), datetime.to_rfc3339()];
        process_vec.append(&mut Self::vec_to_vecstring(&predrow_vec));

        let process_vec_csv =
            Self::vec_to_string_sep(self, &process_vec).unwrap() + &*String::from("\n");

        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.path)?;

        file.write_all(process_vec_csv.as_bytes())?;
        self.last_write_time = Some(SystemTime::now());
        Ok(())
    }

    pub fn write_irp_csv_files(&mut self, drivermsgs: &[u8]) -> Result<(), std::io::Error> {
        let process_vec_csv = drivermsgs.to_owned();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.path)?;

        file.write_all(process_vec_csv.as_slice())?;
        file.write_all(&[255u8, 0u8, 13u8, 10u8])
            .expect("Error marshalling driver message");
        self.last_write_time = Some(SystemTime::now());
        Ok(())
    }

    fn vec_to_string_sep<T: std::fmt::Display>(&self, v: &[T]) -> Option<String> {
        let vlen = v.len();
        if vlen == 0 {
            None
        } else {
            let mut res = String::new();
            for vi in v.iter().take(vlen - 1) {
                res += &*(vi.to_string() + &self.separator);
            }
            res += &*v[vlen - 1].to_string();
            Some(res)
        }
    }

    fn vec_to_vecstring<T: std::fmt::Display>(v: &[T]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }
}
