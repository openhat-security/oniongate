//! Hide console windows for Windows child processes.
//!
//! Status polls, the tray, and the clearnet watch spawn console-subsystem
//! tools (`powershell.exe`, `reg.exe`, `tasklist.exe`, `taskkill.exe`,
//! `tor.exe`, …) on a short interval. Without `CREATE_NO_WINDOW`, Windows
//! allocates a visible System32 console for every spawn and the desktop is
//! unusable.

/// Win32 `CREATE_NO_WINDOW` — do not allocate a console for the child.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Apply platform flags so a short-lived console tool stays invisible.
pub trait HideConsole {
    fn hide_console(&mut self) -> &mut Self;
}

#[cfg(windows)]
impl HideConsole for std::process::Command {
    fn hide_console(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

#[cfg(not(windows))]
impl HideConsole for std::process::Command {
    fn hide_console(&mut self) -> &mut Self {
        self
    }
}

#[cfg(windows)]
impl HideConsole for tokio::process::Command {
    fn hide_console(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

#[cfg(not(windows))]
impl HideConsole for tokio::process::Command {
    fn hide_console(&mut self) -> &mut Self {
        self
    }
}
