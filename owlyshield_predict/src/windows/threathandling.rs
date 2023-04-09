use crate::logging::Logging;
use crate::process::{ProcessRecord, ProcessState};
use crate::worker::threat_handling::ThreatHandler;
use windows::Win32::System::Diagnostics::Debug::DebugActiveProcess;
use crate::driver_com::Driver;

pub struct WindowsThreatHandler {
    driver: Driver
}

impl WindowsThreatHandler {
    pub fn from(driver: Driver) -> WindowsThreatHandler {
        WindowsThreatHandler {
            driver
        }
    }
}

impl ThreatHandler for WindowsThreatHandler {
    fn suspend(&self, proc: &mut ProcessRecord) {
        proc.process_state = ProcessState::Suspended;
        for pid in &proc.pids {
            unsafe {
                DebugActiveProcess(*pid);
            }
        }
    }

    fn kill(&self, gid: u64) {
        let proc_handle = self.driver.try_kill(gid).unwrap();
        println!("Killed Process with Handle {}", proc_handle.0);
        Logging::alert(format!("Killed Process with Handle {}", proc_handle.0).as_str());
    }
}