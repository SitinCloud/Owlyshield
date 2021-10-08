
fn main() {
    windows::build! (
        Windows::Win32::Storage::InstallableFileSystems::{FilterSendMessage, FilterConnectCommunicationPort},
        Windows::Win32::Foundation::{BOOL, CloseHandle, E_ACCESSDENIED/*, HINSTANCE*/},
        Windows::Win32::Storage::FileSystem::FILE_ID_INFO,
        Windows::Win32::System::Threading::CreateProcessAsUserW,
        Windows::Win32::System::Threading::PROCESS_CREATION_FLAGS,
        Windows::Win32::System::RemoteDesktop::WTSQueryUserToken,
        Windows::Win32::Security::DuplicateTokenEx,
        Windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId,
        Windows::Win32::System::Diagnostics::Debug::{GetLastError, WIN32_ERROR},
        //Windows::Win32::Security::{TOKEN_ALL_ACCESS, TokenPrimary, SecurityIdentification},

        //Windows::Win32::System::LibraryLoader::GetModuleFileNameExA
	);

}
