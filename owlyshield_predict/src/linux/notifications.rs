use crate::Logging;
use crate::config::Config;

pub fn notify(_config: &Config, message: &str, _report_path: &str) -> Result<(), String> {
    Logging::alert(message);
    println!("{}", message);
    Ok(())
}
