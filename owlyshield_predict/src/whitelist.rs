use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;

#[derive(Debug)]
pub struct WhiteList {
    whitelist: HashSet<String>,
}

impl WhiteList {
    pub fn from(path: &Path) -> Result<WhiteList, std::io::Error> {
        let mut whitelist = HashSet::new();
        let lines = Self::load(path)?;
        for l in lines {
            whitelist.insert(l?);
        }
        let res = WhiteList { whitelist };
        Ok(res)
    }

    pub fn is_app_whitelisted(&self, appname: &str) -> bool {
        self.whitelist.contains(appname)
    }

    fn load(path: &Path) -> Result<io::Lines<io::BufReader<File>>, std::io::Error> {
        let file = File::open(path)?;
        let lines = io::BufReader::new(file).lines();
        Ok(lines)
    }
}
