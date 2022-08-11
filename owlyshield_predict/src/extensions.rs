use std::collections::{HashMap, HashSet};

use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::extensions::ExtensionCategory::*;

#[derive(Debug)]
pub struct ExtensionsCount {
    pub categories_set: HashMap<ExtensionCategory, HashSet<String>>,
    pub extensionlist: ExtensionList,
}

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, EnumIter)]
pub enum ExtensionCategory {
    Docs,
    Config,
    Archives,
    Database,
    Code,
    Exe,
    Email,
    PasswordVault,
    Event,
    Others,
}

#[derive(Debug)]
pub struct ExtensionList {
    pub categories: HashMap<ExtensionCategory, Vec<&'static str>>,
}

impl ExtensionList {
    pub fn new() -> ExtensionList {
        let doc = vec![
            "doc", "docx", "docb", "docm", "pdf", "djvu", "odt", "xls", "xlsx", "csv", "tsv",
            "ppt", "pptx", "pst", "ost", "msg", "eml", "vsd", "vsdx", "txt", "rtf", "jpeg", "jpg",
            "png", "gif", "tiff", "tif", "bmp", "raw", "psd", "svg", "mp3", "flac", "alac", "wav",
            "aac", "ogg", "wma", "mp4", "mkv", "wmv", "flv", "mpg", "avi",
        ];
        let config = vec!["ini", "inf", "json", "yaml", "yml", "xml"];
        let archive = vec!["zip", "rar", "7z", "gz", "tgz", "tar", "gzip", "dat"];
        let database = vec![
            "db", "sql", "sqlitedb", "sqlite", "sqlite3", "dbf", "fdb", "mdb", "mde", "ora",
            "abbdb", "abbde", "odb", "sdf", "mdf", "ldf", "ndf", "kdbx",
        ];
        let code = vec![
            "iso", "jar", "c", "h", "hpp", "cpp", "cxx", "hxx", "java", "class", "php", "js",
            "html", "sh", "asp", "sh", "jar", "rb", "jsp", "cs", "vb", "pl", "py", "rst",
        ];
        let exe = vec!["exe", "dll"];
        let email = vec!["eml", "email"];
        let password_vault = vec![
            "1pux",
            "opvault",
            "agilekeychain",
            "kdb",
            "kdbx",
            "pwrep",
            "pgpf",
            "psw",
            "passwordwallet4",
            "pswx",
        ];
        let event = vec!["evtx"];
        let others = vec![];

        let mut categories = HashMap::new();
        categories.insert(Docs, doc);
        categories.insert(Config, config);
        categories.insert(Archives, archive);
        categories.insert(Database, database);
        categories.insert(Code, code);
        categories.insert(Exe, exe);
        categories.insert(Email, email);
        categories.insert(PasswordVault, password_vault);
        categories.insert(Event, event);
        categories.insert(Others, others);

        ExtensionList { categories }
    }

    pub fn get_extension_category(&self, extension: &str) -> ExtensionCategory {
        let extension_low = &extension.to_lowercase();
        for (k, v) in &self.categories {
            if v.contains(&&**extension_low) {
                return *k;
            }
        }
        Others
    }
}

impl ExtensionsCount {
    pub fn new() -> ExtensionsCount {
        let mut cats_entries: HashMap<ExtensionCategory, HashSet<String>> = HashMap::new();
        for cat in ExtensionCategory::iter() {
            cats_entries.insert(cat, HashSet::new());
        }
        ExtensionsCount {
            categories_set: cats_entries,
            extensionlist: ExtensionList::new(),
        }
    }

    pub fn count_all(&self) -> usize {
        ExtensionCategory::iter()
            .map(|c| self.categories_set[&c].len())
            .sum()
    }

    pub fn count_category(&self, cat: ExtensionCategory) -> usize {
        self.categories_set[&cat].len()
    }

    pub fn add_cat_extension(&mut self, extension: &str) {
        let extension = extension.trim_matches(char::from(0));
        if !extension.is_empty() {
            let extension_category = self.extensionlist.get_extension_category(extension);
            let val = self.categories_set.get_mut(&extension_category).unwrap();
            val.insert(String::from(extension));
        }
    }
}
