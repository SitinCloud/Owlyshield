use std::collections::{HashMap, HashSet};
use serde::Serialize;

use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::extensions::ExtensionCategory::*;

#[derive(Debug)]
pub struct ExtensionsCount {
    pub categories_set: HashMap<ExtensionCategory, HashSet<String>>,
    pub extensionlist: ExtensionList,
}

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, EnumIter, Serialize)]
pub enum ExtensionCategory {
    DocsMedia,
    Config,
    Archives,
    Database,
    Code,
    Exe,
    Email,
    PasswordVault,
    Logs,
    Others,
}

#[derive(Debug)]
pub struct ExtensionList {
    pub categories: HashMap<ExtensionCategory, Vec<&'static str>>,
}

impl ExtensionList {
    pub fn new() -> ExtensionList {
        let documents_media = vec![
            // Documents
            "pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx",
            "odt", "odp", "ods", "rtf", "txt", "csv",
            "md", "markdown", // Markdown files
            "tex", // LaTeX files
            "epub", // E-book files

            // Images
            "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp",
            "psd", // Photoshop files
            "ai", // Adobe Illustrator files

            // Audio
            "mp3", "wav", "flac", "aac", "ogg", "wma",

            // Video
            "mp4", "avi", "mkv", "mov", "wmv", "flv"
        ];
        let config = vec![
            "env", // Environment variables
            "ini", "conf", // General configuration files
            "cfg", "config", // Application configuration files
            "properties", "yml", "yaml", // Configuration files for specific applications or frameworks
            "htaccess" // Apache configuration files
        ];
        let archive = vec!["zip", "rar", "7z", "gz", "tgz", "tar", "gzip", "tar.gz"];
        let database = vec![
            "sql",
            "mdb", "accdb", // Microsoft Access
            "frm", "myd", "myi", "ibd", // MySQL
            "backup", "dump", // PostgreSQL
            "db", "sqlite", "sqlite3", // SQLite
            "dbf", "ora", // Oracle Database
            "bson", // MongoDB
        ];
        let code = vec![
            "c", "h",
            "cpp", "hpp", "cc", "hh",
            "java", "jar",
            "py", "pyc", "pyd",
            "js",
            "yml",
            "html", "htm",
            "css",
            "php", "phtml",
            "rb",
            "swift",
            "kt", "kts",
            "m", "mm",
            "cs",
            "go",
            "rs",
            "ts",
            "jsp",
            "asp", "aspx", "ascx",
            "jsx",
            "vue",

            // Development Tools
            "vscode-settings.json", "vscode-workspace", "vscodeignore",
            "gitignore", "gitattributes",
            "sublime-project", "sublime-workspace",
            "project", "classpath", "settings/",
            "gradle", "idea/", "iml",
            "xcodeproj", "xcworkspace", "pbxproj",
        ];
        let executables = vec![
            "exe", // Windows executable
            "app", // macOS application
            "sh", "bash", "bat", // Script files
            "jar", // Java executable
            "py", // Python script
            "class", // Java class file
            "dll", "so", // Shared libraries
            "msi", "rpm", "deb", "dmg", "pkg", // Installer packages
            "apk", // Android application package
            "ipa", // iOS application package
        ];
        let email = vec![
            "eml", // Standard email message format
            "msg", // Microsoft Outlook message format
            "pst", // Outlook data file
            "mbox", // Unix mailbox format
            "emlx", // Apple Mail message format
            "ics", // iCalendar file format for calendar events
            "vcf" // vCard file format for contact information
        ];
        let password_vault = vec![
            "kdb", "kdbx", // KeePass
            "pws", "psafe3", // Password Safe
            "1pif", "1password", // 1Password
            "opvault", // AgileBits 1Password vault
            "bitwarden", // Bitwarden vault
            "lastpass", // LastPass vault
            "dashlane", // Dashlane vault
            "keepassx", "keepassxc" // KeePassX, KeePassXC
        ];
        let logs = vec![
            "log", // Plain text log files
            "xml", "json", // Structured log formats
            "tsv", // Log data in tabular format
            "syslog", "journald", // System logs
            "evt", "evtx", // Windows Event logs
            "access", // Apache access logs
            "error", // Apache error logs
            "audit", // Linux audit logs
            "w3c", // IIS logs
            "nginx", // Nginx logs
            "asl", // Apple System Log
            "aslremote", // Apple Remote System Log
            "etl", // Event Tracing for Windows log
        ];
        let others = vec![
            "sys", // Windows system file
            "cmd", // Windows command script file
            "ps1", // PowerShell script file
            "wsf", // Windows Script File
            "reg", // Windows registry file
            "inf", // Windows setup information file
            "chm", // Compiled HTML Help file
            "hlp", // Windows Help file
            "pem", "cer", "crt", "key", "pfx", // SSL certificate files
            "der", "csr", // Certificate-related files
            "ipa", // iOS application package
            "bak", "old", // Backup files
            "temp", "swp", // Temporary files
            "lock", // Lock files
            "cache", // Cache files
            "tmp", // Temporary files
            "part", // Partially downloaded files
            "crdownload", // Chrome partially downloaded file
            "torrent", // Torrent file
            "iso", "img", // Disk image files
            "bin", "cue", "mdf", "nrg", // CD/DVD image files
            "rom", "bios", // BIOS firmware files
        ];

        let mut categories = HashMap::new();
        categories.insert(DocsMedia, documents_media);
        categories.insert(Config, config);
        categories.insert(Archives, archive);
        categories.insert(Database, database);
        categories.insert(Code, code);
        categories.insert(Exe, executables);
        categories.insert(Email, email);
        categories.insert(PasswordVault, password_vault);
        categories.insert(Logs, logs);
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
