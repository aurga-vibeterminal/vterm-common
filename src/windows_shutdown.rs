use std::io;

use windows_sys::Win32::System::Threading::SetProcessShutdownParameters;

const LAST_APPLICATION_SHUTDOWN_LEVEL: u32 = 0x100;

/// Ask Windows to notify this process after applications with the default
/// shutdown priority. This does not veto or block logoff/shutdown.
pub fn set_process_shutdown_last() -> io::Result<()> {
    if unsafe { SetProcessShutdownParameters(LAST_APPLICATION_SHUTDOWN_LEVEL, 0) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Threading::GetProcessShutdownParameters;

    #[test]
    fn sets_the_last_application_shutdown_level() {
        unsafe {
            let mut previous_level = 0;
            let mut previous_flags = 0;
            assert_ne!(
                GetProcessShutdownParameters(&mut previous_level, &mut previous_flags),
                0
            );

            set_process_shutdown_last().unwrap();

            let mut level = 0;
            let mut flags = 0;
            assert_ne!(GetProcessShutdownParameters(&mut level, &mut flags), 0);
            assert_eq!(level, LAST_APPLICATION_SHUTDOWN_LEVEL);
            assert_eq!(flags, 0);

            assert_ne!(
                SetProcessShutdownParameters(previous_level, previous_flags),
                0
            );
        }
    }
}
