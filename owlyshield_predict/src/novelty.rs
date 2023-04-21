use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use chrono::{DateTime, Local};
use serde::{Serialize, Deserialize};
use crate::process::ProcessRecord;
use crate::shared_def::FileId;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
struct Cluster {
    mode: String,
    path: Option<String>,
    cardinality: usize,
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
            steps: 100,
        }
    }

    pub fn learn(&mut self, precord: &mut ProcessRecord) -> Rule {
        let mut res = self.clone();
        let _app_file = precord.appname.replace('.', "_");
        let mut mode = String::new();
        if precord.ops_read > 0 {
            mode += "r";
        }
        if precord.ops_written > 0 {
            mode += "w";
        }
        if precord.ops_setinfo > 0 {
            mode = mode + "s";
        }

        res.exepath = precord.exepath.as_path().display().to_string();
        if mode.ne("") {
            res.clusters.clear();
            for cluster in &precord.clusters {
                res.clusters.push(
                    Cluster {
                        mode: mode.clone(),
                        cardinality: cluster.size(),
                        path: Some(cluster.root()),
                    }
                );
            }
        }
        res.driver_msg_count = precord.driver_msg_count;
        res
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

    pub fn distance(&self, newrule: &Rule, precord: &ProcessRecord) -> Vec<ClusterDistance> {
        let mut res = Vec::new();
        let rule_clusters: HashSet<PathBuf> = self.clusters.iter().map(|c| PathBuf::from(c.path.as_ref().unwrap())).collect();
        let newrule_clusters: HashSet<PathBuf> = newrule.clusters.iter().map(|c| PathBuf::from(c.path.as_ref().unwrap())).collect();
        let clusters_diff: HashSet<_> = newrule_clusters.difference(&rule_clusters).collect();

        for rule_cluster in &rule_clusters {
            let rule_cluster_set = precord.dirs_content.set_recur(rule_cluster);
            for newcluster in &clusters_diff {
                if !DirectoriesContent::is_child_of(rule_cluster, newcluster) {
                    // new cluster is not subcluster : may happen if program recently started; In that case, distance should be zero.
                    let newcluster_set = precord.dirs_content.set_recur(newcluster);
                    let union_count = rule_cluster_set.union(&newcluster_set).count() as f32;
                    let inter_count = rule_cluster_set.intersection(&newcluster_set).count() as f32;

                    res.push(ClusterDistance {
                        dir1: rule_cluster.to_path_buf(),
                        dir2: newcluster.to_path_buf(),
                        distance: 1f32 - inter_count / union_count,
                    });
                }
            }
        }

        if !res.is_empty() {
            dbg!(&res);
        }
        res
    }
}

#[derive(Debug)]
pub struct DirectoriesContent {
    dirs: HashMap<PathBuf, HashSet<FileId>>,
}

impl DirectoriesContent {
    pub fn new() -> DirectoriesContent {
        DirectoriesContent {
            dirs: HashMap::new()
        }
    }

    pub fn insert(&mut self, path: PathBuf, fileid: FileId) {
        if !self.dirs.contains_key(&path) {
            self.dirs.insert(path, HashSet::from([fileid]));
        } else {
            self.dirs.get_mut(&path).unwrap().insert(fileid);
        }
    }

    pub fn set_recur(&self, path: &Path) -> HashSet<FileId> {
        let mut res: HashSet<FileId> = HashSet::new();
        for dir in self.dirs.keys() {
            if Self::is_child_of(path, dir) || path == dir {
                let test = self.dirs.get(dir).unwrap().clone();
                res = res.union(&test).cloned().collect();
            }
        }
        res
    }

    pub fn is_child_of(parent: &Path, child_candidate: &Path) -> bool {
        let parent = parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf());
        let child_candidate = child_candidate.canonicalize().unwrap_or_else(|_| child_candidate.to_path_buf());

        child_candidate
            .ancestors()
            .any(|ancestor| ancestor == parent)
    }
}

#[derive(Debug)]
pub struct ClusterDistance {
    pub dir1: PathBuf,
    pub dir2: PathBuf,
    pub distance: f32,
}