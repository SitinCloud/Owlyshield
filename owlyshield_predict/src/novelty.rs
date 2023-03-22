use std::path::PathBuf;
use chrono::{DateTime, Local};
use serde::{Serialize, Deserialize};
use crate::process::ProcessRecord;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
struct Cluster {
    mode: String,
    path: Option<String>,
    taille: usize,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Rule {
    appname: String,
    exepath: String,
    clusters: Vec<Cluster>,
    pub update_time: Option<DateTime<Local>>,
    pub driver_msg_count: usize,
    pub steps: usize,
}
impl Rule {
    pub fn from(precord: &ProcessRecord) -> Self {
        let now = Local::now();
        Rule {
            appname: precord.appname.as_str().to_string(),
            exepath: precord.exepath.as_path().display().to_string(),
            clusters: vec![],
            update_time: Some(now),
            driver_msg_count: precord.driver_msg_count,
            steps: 100, //TODO I/O steps
        }
    }

    pub fn learn(&mut self, precord: &mut ProcessRecord) -> &mut Self {
        let _app_file = precord.appname.replace(".", "_");
        let mut mode = String::new();
        if precord.ops_read > 0 {
            mode = mode + "r";
        }
        if precord.ops_written > 0 {
            mode = mode + "w";
        }
        // if precord.ops_setinfo > 0 {
        //     mode = mode + "s";
        // }
        // if precord.ops_open > 0 {
        //     mode = mode + "o";

        self.exepath = precord.exepath.as_path().display().to_string();
        if mode.ne("") {
            self.clusters.clear();
            for cluster in &precord.clusters {
                self.clusters.push(
                    Cluster {
                        mode: mode.clone(),
                        taille: cluster.size(),
                        path: Some(cluster.root()),
                    }
                );
            }
        }
        self.driver_msg_count = precord.driver_msg_count;
        self
    }

    pub fn get_files(rules_dir: &str) -> Vec<String> {
        let mut files: Vec<String> = Vec::new();
        let paths = std::fs::read_dir(rules_dir).unwrap();
        for path in paths {
            let p = path.unwrap().path();
            let f = p.file_stem().unwrap().to_os_string().into_string().unwrap();
            files.push(f);
        }
        files
    }

    pub fn deserialize_yml_file(path: PathBuf) -> Rule {
        let yaml = std::fs::read_to_string(path).expect("Should have been able to read the file");
        let values: Rule = serde_yaml::from_str(yaml.as_str()).unwrap();
        values
    }

    pub fn serialize_yml_file(path: PathBuf, rule: Rule) {
        let value = serde_yaml::to_string(&rule).unwrap();
        std::fs::write(path, value).expect("TODO: panic message");
    }
}
