use crate::extensions::ExtensionCategory::*;
use std::collections::{HashMap, HashSet};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Debug)]
pub struct ExtensionsCount<'a> {
    categories_count: HashMap<ExtensionCategory, usize>,
    extensionlist: &'a ExtensionList,
}

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, EnumIter)]
pub enum ExtensionCategory {
    Docs,
    Config,
    Archives,
    Database,
    Code,
    Exe,
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
        let others = vec![];

        let mut categories = HashMap::new();
        categories.insert(Docs, doc);
        categories.insert(Config, config);
        categories.insert(Archives, archive);
        categories.insert(Database, database);
        categories.insert(Code, code);
        categories.insert(Exe, exe);
        categories.insert(Others, others);

        ExtensionList {
            categories: categories,
        }
    }

    pub fn get_extension_category(&self, extension: &str) -> ExtensionCategory {
        let extension_low = &extension.to_lowercase();
        for (k, v) in &self.categories {
            if v.contains(&&**extension_low) {
                return *k;
            }
        }
        return Others;
    }
}

impl ExtensionsCount<'_> {
    pub fn new(extensionlist: &ExtensionList) -> ExtensionsCount {
        let mut cats_count: HashMap<ExtensionCategory, usize> = HashMap::new();
        for cat in ExtensionCategory::iter() {
            cats_count.insert(cat, 0);
        }
        ExtensionsCount {
            categories_count: cats_count,
            extensionlist: extensionlist,
        }
    }

    pub fn count_all(&self) -> usize {
        ExtensionCategory::iter()
            .map(|c| self.categories_count[&c])
            .sum()
    }

    pub fn count_category(&self, cat: ExtensionCategory) -> usize {
        self.categories_count[&cat]
    }

    pub fn add_count(&mut self, cat: &ExtensionCategory) {
        self.categories_count
            .insert(*cat, self.categories_count.get(cat).unwrap() + 1);
    }

    pub fn add_count_ext(&mut self, extension: &str) {
        &self.add_count(&self.extensionlist.get_extension_category(extension));
    }
}
