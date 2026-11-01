//! The client / daemon transport: one connection per command, length-prefixed JSON frames (u32 little-endian length,
//! then the UTF-8 JSON object). Windows: a named pipe `\\.\pipe\dcp2-<sha256(root)[:16]>`; elsewhere a Unix socket
//! build/dcp-daemon.sock. The daemon's address and its random key are in build/dcp-daemon.json: only a client that
//! can read the project's build directory can talk to its daemon.

use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// The daemon's address of a project root.
pub fn address(root: &Path) -> String {
    #[cfg(windows)]
    {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(root.to_string_lossy().to_lowercase().as_bytes());
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        format!(r"\\.\pipe\dcp2-{}", &hex[..16])
    }
    #[cfg(not(windows))]
    {
        root.join("build").join("dcp-daemon.sock").to_string_lossy().into_owned()
    }
}

/// build/dcp-daemon.json of a project root.
pub fn info_path(root: &Path) -> PathBuf {
    root.join("build").join("dcp-daemon.json")
}

pub fn send(w: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let b = serde_json::to_vec(v)?;
    let mut msg = Vec::with_capacity(4 + b.len());
    msg.extend_from_slice(&(b.len() as u32).to_le_bytes());
    msg.extend_from_slice(&b);
    w.write_all(&msg)?;
    w.flush()
}

pub fn recv(r: &mut impl Read) -> std::io::Result<Value> {
    let mut n = [0u8; 4];
    r.read_exact(&mut n)?;
    let n = u32::from_le_bytes(n) as usize;
    if n > 1 << 30 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b)?;
    serde_json::from_slice(&b).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// A connected stream of either side.
pub type Conn = std::fs::File;

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    use std::os::windows::io::FromRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateNamedPipeW(name: *const u16, open_mode: u32, pipe_mode: u32, max: u32, out_buf: u32, in_buf: u32, timeout: u32, sa: *mut c_void) -> *mut c_void;
        fn ConnectNamedPipe(h: *mut c_void, ov: *mut c_void) -> i32;
        fn DisconnectNamedPipe(h: *mut c_void) -> i32;
        fn FlushFileBuffers(h: *mut c_void) -> i32;
        fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
        fn GetLastError() -> u32;
    }

    const PIPE_ACCESS_DUPLEX: u32 = 3;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
    const ERROR_PIPE_CONNECTED: u32 = 535;
    const ERROR_PIPE_BUSY: i32 = 231;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The server's side: instances of one pipe name; the first one claims the name (a second daemon of the same
    /// project fails here).
    pub struct Listener {
        name: Vec<u16>,
        next: Option<*mut c_void>,
    }

    impl Listener {
        pub fn bind(addr: &str) -> std::io::Result<Listener> {
            let name = wide(addr);
            let h = Self::instance(&name, true)?;
            Ok(Listener { name, next: Some(h) })
        }

        fn instance(name: &[u16], first: bool) -> std::io::Result<*mut c_void> {
            let flags = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
            let h = unsafe { CreateNamedPipeW(name.as_ptr(), flags, PIPE_REJECT_REMOTE_CLIENTS, 255, 1 << 16, 1 << 16, 0, std::ptr::null_mut()) };
            if h as isize == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(h)
        }

        /// The next client (the pipe instance it connected to); a fresh instance is made at once, so a client
        /// arriving meanwhile connects and waits for its turn.
        pub fn accept(&mut self) -> std::io::Result<Server> {
            let h = match self.next.take() {
                Some(h) => h,
                None => Self::instance(&self.name, false)?,
            };
            let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if !ok {
                let e = std::io::Error::last_os_error();
                unsafe { DisconnectNamedPipe(h) };
                self.next = Some(h);
                return Err(e);
            }
            self.next = Self::instance(&self.name, false).ok();
            Ok(Server { h, file: Some(unsafe { std::fs::File::from_raw_handle(h) }) })
        }
    }

    /// A connected server instance: closed (flushed, disconnected) when dropped.
    pub struct Server {
        h: *mut c_void,
        file: Option<std::fs::File>,
    }

    impl Server {
        pub fn file(&mut self) -> &mut std::fs::File {
            self.file.as_mut().unwrap()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            unsafe {
                FlushFileBuffers(self.h);
                DisconnectNamedPipe(self.h);
            }
            self.file.take(); // closes the handle
        }
    }

    /// The client's side: open the pipe, waiting while every instance is busy (another command runs).
    pub fn connect(addr: &str) -> std::io::Result<std::fs::File> {
        let name = wide(addr);
        loop {
            match std::fs::OpenOptions::new().read(true).write(true).open(addr) {
                Ok(f) => return Ok(f),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    unsafe { WaitNamedPipeW(name.as_ptr(), 0xFFFF_FFFF) };
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(not(windows))]
mod sys {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::fd::{FromRawFd, IntoRawFd};

    pub struct Listener(UnixListener);

    impl Listener {
        pub fn bind(addr: &str) -> std::io::Result<Listener> {
            if UnixStream::connect(addr).is_ok() {
                return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "a daemon runs already"));
            }
            let _ = std::fs::remove_file(addr);
            Ok(Listener(UnixListener::bind(addr)?))
        }

        pub fn accept(&mut self) -> std::io::Result<Server> {
            let (s, _) = self.0.accept()?;
            Ok(Server(unsafe { std::fs::File::from_raw_fd(s.into_raw_fd()) }))
        }
    }

    pub struct Server(std::fs::File);

    impl Server {
        pub fn file(&mut self) -> &mut std::fs::File {
            &mut self.0
        }
    }

    pub fn connect(addr: &str) -> std::io::Result<std::fs::File> {
        let s = UnixStream::connect(addr)?;
        Ok(unsafe { std::fs::File::from_raw_fd(s.into_raw_fd()) })
    }
}

pub use sys::{connect, Listener, Server};
