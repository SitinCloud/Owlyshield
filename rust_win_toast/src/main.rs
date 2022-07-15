use std::cmp::Ordering;
use std::env;
use std::path::Path;
use std::process::Command;
use winrt_notification::{Duration, IconCrop, Sound, Toast};

fn main() {
    for argument in env::args() {
        println!("arg {}", argument);
    }
    let arguments: Vec<String> = env::args().collect();
    match env::args().len().cmp(&3) {
        Ordering::Equal => {
            Toast::new(Toast::POWERSHELL_APP_ID)
                .title(&arguments[1])
                .text1(&arguments[2])
                .sound(Some(Sound::SMS))
                .duration(Duration::Short)
                .show()
                .expect("unable to toast");
        }
        Ordering::Greater => {
            let logo = if env::args().len() > 4 {
                &arguments[3]
            } else {
                ""
            };
            let app = if env::args().len() > 5 {
                &arguments[4]
            } else {
                Toast::POWERSHELL_APP_ID
            };
            let log = &arguments[env::args().len() - 1];
            Toast::new(app)
                .title(&arguments[1])
                .text1(&arguments[2])
                .icon(Path::new(logo), IconCrop::Square, "")
                .sound(Some(Sound::SMS))
                .duration(Duration::Short)
                .show()
                .expect("unable to toast");
            if log.ends_with(".html") || log.ends_with(".txt") || log.ends_with(".log") {
                if cfg!(target_os = "windows") {
                    Command::new("cmd")
                        .arg("/C")
                        .arg(log)
                        .output()
                        .expect("failed to execute process")
                } else {
                    Command::new("sh")
                        .arg("-c")
                        .arg(log)
                        .output()
                        .expect("failed to execute process")
                };
            }
        }
        _ => {
            println!("bad number of args");
        }
    }
}
