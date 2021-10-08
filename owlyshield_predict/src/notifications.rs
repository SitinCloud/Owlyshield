use crate::config::{Config, Param};
use bindings::Windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, PWSTR};
use bindings::Windows::Win32::Security::*;
use bindings::Windows::Win32::System::Diagnostics::Debug::GetLastError;
use bindings::Windows::Win32::System::RemoteDesktop::*;
use bindings::Windows::Win32::System::Threading::CreateProcessAsUserW;
use bindings::Windows::Win32::System::Threading::CREATE_NEW_CONSOLE;
use bindings::Windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};
use log::{error, info, trace};
use std::path::Path;
use std::ptr::{null, null_mut};
use widestring::{U16CString, UCString, WideString};

pub fn toast(config: &Config, message: &str) {
    let toastapp_dir = Path::new(&config[Param::UtilsPath]);
    let toastapp_path = toastapp_dir.join("RustWindowsToast.exe");
    let toastapp_args = format!(" \"Owlyshield\" \"{}\"", message);

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
                error!("Toast(): cannot duplicate token")
            }
            CloseHandle(service_token);
            if !CreateProcessAsUserW(
                token,
                PWSTR(str_to_pwstr(toastapp_path.to_str().unwrap()).into_raw()),
                PWSTR(str_to_pwstr(&toastapp_args).into_raw()),
                null_mut(),
                null_mut(),
                BOOL(0),
                CREATE_NEW_CONSOLE.0,
                null_mut(),
                PWSTR(str_to_pwstr(&toastapp_dir.to_str().unwrap()).into_raw()),
                std::ptr::addr_of_mut!(si),
                std::ptr::addr_of_mut!(pi),
            )
            .as_bool()
            {
                error!("Toast(): cannot launch process: {}", GetLastError().0);
            }
            CloseHandle(token);
        } else {
            error!("Toast(): cannot query user token: {}", GetLastError().0);
        }
    }
}

pub fn str_to_pwstr(str: &str) -> UCString<u16> {
    U16CString::from_str(str).unwrap()
}
