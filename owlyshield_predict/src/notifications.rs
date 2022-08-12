use std::path::Path;
use std::ptr::null_mut;

use log::error;
use widestring::{U16CString, U16String};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, BOOL, HANDLE};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityIdentification, TokenPrimary, SECURITY_ATTRIBUTES, TOKEN_ALL_ACCESS,
};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CREATE_NEW_CONSOLE, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::config::{Config, Param};

#[cfg(feature = "service")]
pub fn toast(config: &Config, message: &str, report_path: &str) -> Result<(), String> {
    let toastapp_dir = Path::new(&config[Param::UtilsPath]);
    let toastapp_path = toastapp_dir.join("RustWindowsToast.exe");
    let app_id = &config[Param::AppId];
    let logo_path = Path::new(&config[Param::ConfigPath])
        .parent()
        .unwrap()
        .join("logo.ico");
    let toastapp_args = format!(
        " \"Owlyshield\" \"{}\" \"{}\" \"{}\" \"{}\"",
        message,
        logo_path.to_str().unwrap_or(""),
        app_id,
        report_path
    );

    let mut error_msg = String::new();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        let sessionid = WTSGetActiveConsoleSessionId();
        let mut service_token = HANDLE(0);
        let mut token = HANDLE(0);
        if WTSQueryUserToken(sessionid, std::ptr::addr_of_mut!(service_token)).as_bool() {
            if !DuplicateTokenEx(
                service_token,
                TOKEN_ALL_ACCESS,
                null_mut() as *mut SECURITY_ATTRIBUTES,
                SecurityIdentification,
                TokenPrimary,
                &mut token,
            )
            .as_bool()
            {
                CloseHandle(service_token);
                error!("Toast(): cannot duplicate token");
                return Err("Toast(): cannot duplicate token".to_string());
            }
            CloseHandle(service_token);
            if !CreateProcessAsUserW(
                token,
                PCWSTR(str_to_pcwstr(toastapp_path.to_str().unwrap()).into_raw()),
                PWSTR(str_to_pwstr(&toastapp_args).into_vec().as_mut_ptr()),
                null_mut(),
                null_mut(),
                BOOL(0),
                CREATE_NEW_CONSOLE.0,
                null_mut(),
                PCWSTR(str_to_pcwstr(toastapp_dir.to_str().unwrap()).into_raw()),
                std::ptr::addr_of_mut!(si),
                std::ptr::addr_of_mut!(pi),
            )
            .as_bool()
            {
                error!("Toast(): cannot launch process: {}", GetLastError().0);
                error_msg = format!("Toast(): cannot query user token: {}", GetLastError().0);
            }
            CloseHandle(token);
        } else {
            error!("Toast(): cannot query user token: {}", GetLastError().0);
            error_msg = format!("Toast(): cannot query user token: {}", GetLastError().0);
        }
    }
    if error_msg.is_empty() {
        Ok(())
    } else {
        Err(error_msg)
    }
}

#[cfg(not(feature = "service"))]
pub fn toast(config: &Config, message: &str, report_path: &str) -> Result<(), String> {
    let toastapp_dir = Path::new(&config[Param::UtilsPath]);
    let toastapp_path = toastapp_dir.join("RustWindowsToast.exe");
    let app_id = &config[Param::AppId];
    let logo_path = Path::new(&config[Param::ConfigPath])
        .parent()
        .unwrap()
        .join("logo.ico");
    let toastapp_args = [
        "Owlyshield",
        message,
        logo_path.to_str().unwrap_or(""),
        app_id,
        report_path,
    ];

    std::process::Command::new(toastapp_path)
        .args(toastapp_args)
        .output()
        .expect("failed to execute process");
    Ok(())
}

fn str_to_pcwstr(str: &str) -> U16CString {
    U16CString::from_str(str).unwrap()
}

fn str_to_pwstr(str: &str) -> U16String {
    U16String::from_str(str)
}
