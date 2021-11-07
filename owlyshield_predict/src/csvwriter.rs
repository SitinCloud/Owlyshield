//! This crate is used to dump ProcessRecords to a csv file to create Learning samples that will be used to train the model.

use std::fs;
use std::io::Write;
use std::os::raw::c_ulonglong;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::config::{Config, Param};
use crate::prediction::predmtrx::PredictionRow;

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
            //path: Path::new(&config[Param::PredPath]).to_path_buf(),
            path: Path::new(&config[Param::DebugPath])
                .join(Path::new("learn.csv"))
                .to_path_buf(),
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
        gid: c_ulonglong,
        predrow: &PredictionRow,
    ) -> Result<(), std::io::Error> {
        //        println!("CALLED");
        let predrow_vec = predrow.to_vec_f32();
        let mut process_vec = vec![String::from(appname), gid.to_string()];
        process_vec.append(&mut Self::vec_to_vecstring(&predrow_vec));

        let process_vec_csv =
            Self::vec_to_string_sep(&self, &process_vec).unwrap() + &*String::from("\n");
        //       println!("{}", process_vec_csv);

        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.path)?;

        file.write_all(process_vec_csv.as_bytes())?;
        self.last_write_time = Some(SystemTime::now());
        Ok(())
    }

    pub fn write_irp_csv_files(
        &mut self,
        drivermsgs: &Vec<u8>, //&String//&Vec<u8>,
    ) -> Result<(), std::io::Error> {
        let process_vec_csv = drivermsgs.clone();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.path)?;

        file.write_all(process_vec_csv.as_slice())?;
        file.write(&vec![255u8, 0u8, 13u8, 10u8])
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
            for i in 0..vlen - 1 {
                res += &*(v[i].to_string() + &self.separator);
            }
            res += &*v[vlen - 1].to_string();
            Some(res)
        }
    }

    fn vec_to_vecstring<T: std::fmt::Display>(v: &[T]) -> Vec<String> {
        v.into_iter().map(|x| x.to_string()).collect()
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//
//     #[test]
//     fn should_display_vec_as_csv() {
//         let v = vec![1, 2, 3, 4, 5];
//         let res = "1;2;3;4;5";
//         assert_eq!(vec_to_string_sep(&v, ";").unwrap(), res);
//     }
// }
