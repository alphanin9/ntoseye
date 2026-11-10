//! The client end of a Windows named pipe, for KD over the guest COM port
//! Hyper-V serves at a pipe (`Set-VMComPort -Path \\.\pipe\NAME`).
//!
//! The handle is opened for overlapped I/O, as [`super::transport`] needs
//! what a Unix socket gives it: a read that gives up after a timeout, and a
//! second handle (the break-in writer) whose write is not held behind the
//! pump's read, which a synchronous handle would serialize.

use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, GENERIC_READ,
    GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

/// How long [`PipeStream::connect`] waits for a pipe whose one instance
/// another client holds.
const BUSY_WAIT_MS: u32 = 2000;

pub struct PipeStream {
    pipe: Arc<OwnedHandle>,
    /// One event per direction, so a clone's write never signals a read.
    read_event: OwnedHandle,
    write_event: OwnedHandle,
    read_timeout: Option<Duration>,
}

impl PipeStream {
    pub fn connect(path: &str) -> io::Result<Self> {
        let wide: Vec<u16> = std::ffi::OsStr::new(path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let open = || unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        let mut handle = open();
        if handle == INVALID_HANDLE_VALUE
            && io::Error::last_os_error().raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
            && unsafe { WaitNamedPipeW(wide.as_ptr(), BUSY_WAIT_MS) } != 0
        {
            handle = open();
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Self::with_pipe(
            Arc::new(unsafe { OwnedHandle::from_raw_handle(handle) }),
            None,
        )
    }

    fn with_pipe(pipe: Arc<OwnedHandle>, read_timeout: Option<Duration>) -> io::Result<Self> {
        Ok(Self {
            pipe,
            read_event: manual_reset_event()?,
            write_event: manual_reset_event()?,
            read_timeout,
        })
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Self::with_pipe(Arc::clone(&self.pipe), self.read_timeout)
    }

    /// As [`std::os::unix::net::UnixStream::set_read_timeout`]: `None`
    /// waits indefinitely, and a read that times out fails `WouldBlock`.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot set a zero duration timeout",
            ));
        }
        self.read_timeout = timeout;
        Ok(())
    }

    fn handle(&self) -> HANDLE {
        self.pipe.as_raw_handle()
    }
}

fn manual_reset_event() -> io::Result<OwnedHandle> {
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(event) })
}

fn overlapped(event: &OwnedHandle) -> OVERLAPPED {
    // SAFETY: OVERLAPPED is plain data; all-zero is its documented start state.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.as_raw_handle();
    overlapped
}

/// Wait out an operation `issued` started on `overlapped`, giving up after
/// `timeout`. The operation is always complete (or cancelled) on return, so
/// the buffer and `overlapped` it borrowed are free again.
fn finish(
    pipe: HANDLE,
    overlapped: &mut OVERLAPPED,
    issued: bool,
    timeout: Option<Duration>,
) -> io::Result<usize> {
    let mut transferred = 0u32;
    if !issued {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(error);
        }
        let millis = timeout.map_or(INFINITE, |timeout| {
            u32::try_from(timeout.as_millis())
                .unwrap_or(INFINITE - 1)
                .clamp(1, INFINITE - 1)
        });
        match unsafe { WaitForSingleObject(overlapped.hEvent, millis) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                // Cancelled or not, the operation must be reaped before the
                // buffer goes back to the caller; it may have completed in
                // the meantime, and then its bytes are the read's.
                unsafe { CancelIoEx(pipe, overlapped) };
                if unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 1) } != 0 {
                    return Ok(transferred as usize);
                }
                let error = io::Error::last_os_error();
                return Err(
                    if error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
                        io::Error::new(io::ErrorKind::WouldBlock, "named pipe read timed out")
                    } else {
                        error
                    },
                );
            }
            _ => {
                unsafe { CancelIoEx(pipe, overlapped) };
                unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 1) };
                return Err(io::Error::last_os_error());
            }
        }
    }
    if unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred as usize)
}

impl Read for PipeStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut overlapped = overlapped(&self.read_event);
        let len = u32::try_from(output.len()).unwrap_or(u32::MAX);
        let issued = unsafe {
            ReadFile(
                self.handle(),
                output.as_mut_ptr(),
                len,
                null_mut(),
                &mut overlapped,
            )
        } != 0;
        match finish(self.handle(), &mut overlapped, issued, self.read_timeout) {
            // The server closing its end (the VM powered off) is end of
            // stream, as a Unix socket reports it.
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(0),
            result => result,
        }
    }
}

impl Write for PipeStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let mut overlapped = overlapped(&self.write_event);
        let len = u32::try_from(input.len()).unwrap_or(u32::MAX);
        let issued = unsafe {
            WriteFile(
                self.handle(),
                input.as_ptr(),
                len,
                null_mut(),
                &mut overlapped,
            )
        } != 0;
        finish(self.handle(), &mut overlapped, issued, None)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Instant;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    /// A synchronous one-instance server, as Hyper-V's COM port pipe is.
    fn server(name: &str) -> OwnedHandle {
        let wide: Vec<u16> = std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                null(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        unsafe { OwnedHandle::from_raw_handle(handle) }
    }

    fn unique_name() -> String {
        format!(
            r"\\.\pipe\ntoseye-test-{}-{:?}",
            std::process::id(),
            Instant::now()
        )
    }

    /// The break-in writer's write gets through while the pump's read waits
    /// on the same pipe, and the read then times out on its own.
    #[test]
    fn a_clone_writes_while_a_read_waits_and_the_read_times_out() {
        let name = unique_name();
        let server = server(&name);
        let mut client = PipeStream::connect(&name).unwrap();
        unsafe { ConnectNamedPipe(server.as_raw_handle(), null_mut()) };
        let mut writer = client.try_clone().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();

        let reader = thread::spawn(move || {
            let start = Instant::now();
            let error = client.read(&mut [0u8; 1]).unwrap_err();
            (error.kind(), start.elapsed())
        });
        thread::sleep(Duration::from_millis(50));
        writer.write_all(b"b").unwrap();

        let mut byte = [0u8; 1];
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                server.as_raw_handle(),
                byte.as_mut_ptr(),
                1,
                &mut read,
                null_mut(),
            )
        };
        assert!(ok != 0 && read == 1 && byte == *b"b");
        let (kind, waited) = reader.join().unwrap();
        assert_eq!(kind, io::ErrorKind::WouldBlock);
        assert!(waited >= Duration::from_millis(250), "{waited:?}");
    }

    /// The server closing its end ends the stream.
    #[test]
    fn a_closed_server_is_end_of_stream() {
        let name = unique_name();
        let server = server(&name);
        let mut client = PipeStream::connect(&name).unwrap();
        unsafe { ConnectNamedPipe(server.as_raw_handle(), null_mut()) };
        drop(server);
        assert_eq!(client.read(&mut [0u8; 4]).unwrap(), 0);
    }
}
