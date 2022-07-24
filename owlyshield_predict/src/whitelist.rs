use std::{io, thread, time};
use std::collections::HashSet;
use std::fs::File;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct WhiteList {
    whitelist: Arc<Mutex<HashSet<String>>>,
    path: Arc<PathBuf>,
}

impl WhiteList {
    pub fn from(path: &Path) -> Result<WhiteList, std::io::Error> {
        let mut whitelist = HashSet::new();
        let lines = Self::load(path)?;
        for l in lines {
            whitelist.insert(l?);
        }
        let res = WhiteList {
            whitelist: Arc::new(Mutex::new(whitelist)),
            path: Arc::new(PathBuf::from(path)),
        };
        Ok(res)
    }

    pub fn is_app_whitelisted(&self, appname: &str) -> bool {
        self.whitelist.lock().unwrap().contains(appname)
    }

    pub fn refresh_periodically(&self) {
        let whitelist_bis = Arc::clone(&self.whitelist);
        let path_bis = Arc::clone(&self.path);
        thread::spawn(move || loop {
            let res_lines = Self::load(&path_bis);
            {
                let mut set_whitelist = whitelist_bis.lock().unwrap();
                if let Ok(lines) = res_lines {
                    set_whitelist.clear();
                    for l in lines {
                        (*set_whitelist).insert(l.unwrap_or_else(|_| String::new()));
                    }
                }
            }
            thread::sleep(time::Duration::from_secs(10));
        });
    }

    fn load(path: &Path) -> Result<io::Lines<io::BufReader<File>>, std::io::Error> {
        let file = File::open(path)?;
        let lines = io::BufReader::new(file).lines();
        Ok(lines)
    }
}
