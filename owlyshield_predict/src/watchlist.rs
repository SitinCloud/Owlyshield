use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{thread, time};

#[derive(Debug)]
pub struct WatchList {
    watchlist: Arc<Mutex<HashSet<String>>>,
    path: Arc<PathBuf>,
}

impl WatchList {
    pub fn from(path: &Path) -> Result<WatchList, std::io::Error> {
        let mut watchlist: HashSet<String> = HashSet::new();
        let yaml = std::fs::read_to_string(path).expect("Should have been able to read the file");
        let wl: Vec<String> = serde_yaml::from_str(yaml.as_str()).unwrap();

        for w in wl {
            watchlist.insert(w);
        }
        let res = WatchList {
            watchlist: Arc::new(Mutex::new(watchlist)),
            path: Arc::new(PathBuf::from(path)),
        };
        Ok(res)
    }

    pub fn is_app_watchlisted(&self, appname: &str) -> bool {
        self.watchlist.lock().unwrap().contains(appname)
    }

    pub fn refresh_periodically(&self) {
        let watchlist_bis = Arc::clone(&self.watchlist);
        let path_bis = Arc::clone(&self.path);
        thread::spawn(move || loop {
            let res_lines = Self::load(&path_bis);
            {
                let mut set_watchlist = watchlist_bis.lock().unwrap();
                if let Ok(lines) = res_lines {
                    set_watchlist.clear();
                    for l in lines {
                        (*set_watchlist).insert(l);
                    }
                }
            }
            thread::sleep(time::Duration::from_secs(10));
        });
    }

    fn load(path: &Path) -> Result<HashSet<String>, std::io::Error> {
        let yaml = std::fs::read_to_string(path).expect("Should have been able to read the file");
        let lines: HashSet<String> = serde_yaml::from_str(yaml.as_str()).unwrap();
        Ok(lines)
    }
}
