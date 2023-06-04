use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use chrono::{DateTime, Local};
use serde::{Serialize, Deserialize};
use serde_json::{from_reader, to_writer};
use crate::process::ProcessRecord;
use crate::shared_def::{FileId, IOMessage, IrpMajorOp};

#[derive(Serialize, Deserialize, Debug)]
pub struct StateSave {
    pub dirs_content: DirectoriesContent,
    pub driver_msg_count: usize,
}

impl StateSave {
    pub fn new(precord: &ProcessRecord) -> StateSave {
        StateSave {
            dirs_content: precord.dirs_content.clone(),
            driver_msg_count: precord.driver_msg_count,
        }
    }

    pub fn load_file(path: &Path) -> Result<StateSave, Box<dyn Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let res = from_reader(reader)?;
        Ok(res)
    }

    pub fn save_file(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        to_writer(writer, self)?;
        Ok(())
    }

    pub fn update_precord(&self, precord: &mut ProcessRecord) {
        precord.dirs_content = self.dirs_content.clone();
        precord.driver_msg_count = self.driver_msg_count;
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
struct RuleCluster {
    // mode: String,
    pub path: Option<String>,
    cardinality: usize,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Rule {
    appname: String,
    exepath: String,
    clusters: Vec<RuleCluster>,
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

    pub fn is_clusters_empty(&self) -> bool {
        self.clusters.is_empty()
    }

    fn get_cluster(&self, target_path: &Path) -> Option<&RuleCluster> {
        self.clusters.iter().find(|cluster| {
            match &cluster.path {
                Some(path) => path == target_path.to_str().unwrap(),
                None => false,
            }
        })
    }

    fn replace_cluster(&mut self, target_path: &Path, new_cluster: RuleCluster) {
        if let Some(index) = self.clusters.iter().position(|cluster| match &cluster.path {
            Some(path) => path == target_path.to_str().unwrap(),
            None => false,
        }) {
            self.clusters[index] = new_cluster;
        }
    }

    /// Replace subclusters (with jaccard distance 0) by old ones
    pub fn replace_subclusters(&mut self, oldrule: &Rule, distances: &[ClusterDistance]) {
        for distance in distances {
            if distance.distance == 0.0 {
                if let Some(old_cluster) = oldrule.get_cluster(&distance.dir1) {
                    let new_cluster = old_cluster.clone();
                    self.replace_cluster(&distance.dir2, new_cluster);
                }
            }
        }
    }

    pub fn learn(&mut self, precord: &mut ProcessRecord) -> Rule {
        let mut res = self.clone();
        let _app_file = precord.appname.replace('.', "_");

        res.exepath = precord.exepath.as_path().display().to_string();
        res.clusters.clear();
        //Clusters to RuleClusters
        for cluster in &precord.clusters {
            res.clusters.push(
                RuleCluster {
                    // mode: mode.clone(),
                    cardinality: cluster.size(),
                    path: Some(cluster.root()),
                }
            );
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

        if !clusters_diff.is_empty() {
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
        }
        res
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DirectorySubTree {
    root: PathBuf,
    fileids: HashSet<FileId>,
    optypes: HashSet<IrpMajorOp>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirectoriesContent {
    // extensionList: ExtensionList,
    dirs_fileids: HashMap<PathBuf, HashSet<FileId>>,
    dirs_optypes: HashMap<PathBuf, HashSet<IrpMajorOp>>,
    // dirs_filetypes: HashMap<PathBuf, HashSet<ExtensionCategory>>,
}

impl DirectoriesContent {
    pub fn new() -> DirectoriesContent {
        DirectoriesContent {
            // extensionList: ExtensionList::new(),
            dirs_fileids: HashMap::new(),
            dirs_optypes: HashMap::new(),
            // dirs_filetypes: HashMap::new(),
        }
    }

    pub fn insert(&mut self, path: PathBuf, iomsg: &IOMessage) {
        let fileid = iomsg.file_id_id;
        let operation_type = IrpMajorOp::from_byte(iomsg.irp_op);
        if !self.dirs_fileids.contains_key(&path) {
            self.dirs_fileids.insert(path.clone(), HashSet::from([fileid]));
            self.dirs_optypes.insert(path.clone(), HashSet::from([operation_type]));
            // self.dirs_filetypes.insert(path, HashSet::from([self.extensionList.get_extension_category(&iomsg.extension)]));
        } else {
            self.dirs_fileids.get_mut(&path).unwrap().insert(fileid);
            self.dirs_optypes.get_mut(&path).unwrap().insert(operation_type);
            // self.dirs_filetypes.get_mut(&path).unwrap().insert(self.extensionList.get_extension_category(&iomsg.extension));
        }
    }

    /// Determines the set of unique `FileId`s associated with a given directory path and its subdirectories.
    ///
    /// This function will traverse through the collection of directories stored in the instance (`self.dirs`).
    /// For each directory in `self.dirs`, it will check if the directory is a child of the provided path or if the directory is the same as the provided path.
    /// If either of these conditions is met, the `FileId`s associated with this directory are added to the result set.
    ///
    /// Note that this function effectively calculates the recursive set of `FileId`s for a given path, including those from subdirectories.
    ///
    /// # Arguments
    ///
    /// * `path` - A `Path` reference representing the parent directory path for which associated `FileId`s are to be found.
    ///
    /// # Returns
    ///
    /// This function returns a `HashSet<FileId>` representing unique `FileId`s associated with the provided directory path and its subdirectories.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let path = Path::new("/path/to/directory");
    /// let file_ids = obj.set_recur(&path);
    /// println!("The file ids associated with the directory and its subdirectories are: {:?}", file_ids);
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the provided directory path does not exist in `self.dirs`.
    pub fn set_recur(&self, path: &Path) -> HashSet<FileId> {
        let mut res: HashSet<FileId> = HashSet::new();
        for dir in self.dirs_fileids.keys() {
            if Self::is_child_of(path, dir) || path == dir {
                let fileids = self.dirs_fileids.get(dir).unwrap().clone();
                res = res.union(&fileids).cloned().collect();
            }
        }
        res
    }

    pub fn build_dir_subtree(&self, path: &Path) -> DirectorySubTree {
        let mut fileids_union = HashSet::new();
        let mut optypes_union = HashSet::new();
        for dir in self.dirs_fileids.keys() {
            if Self::is_child_of(path, dir) || path == dir {
                let fileids = self.dirs_fileids.get(dir).unwrap().clone();
                let optypes = self.dirs_optypes.get(dir).unwrap().clone();
                fileids_union = fileids_union.union(&fileids).cloned().collect();
                optypes_union = optypes_union.union(&optypes).cloned().collect();
            }
        }

        DirectorySubTree {
            root: path.into(),
            fileids: fileids_union,
            optypes: optypes_union,
        }
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