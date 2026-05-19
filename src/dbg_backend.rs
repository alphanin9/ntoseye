use std::time::Duration;

use crate::error::Result;
use crate::gdb::RegisterMap;

/// Backend-neutral stop event
pub struct StopEvent {
    /// Backend thread/vCPU id, if the stop packet provided one
    pub thread_id: Option<String>,
}

/// Debug transport abstraction; memory access stays on `/dev/kvm`
pub trait DebugBackend {
    fn register_map(&self) -> &RegisterMap;

    fn read_registers(&mut self) -> Result<Vec<u8>>;
    fn write_registers(&mut self, data: &[u8]) -> Result<()>;

    fn set_breakpoint(&mut self, addr: u64) -> Result<()>;
    fn remove_breakpoint(&mut self, addr: u64) -> Result<()>;

    fn supports_process_breakpoints(&self) -> bool {
        false
    }

    /// Notify the backend about a breakpoint patched outside `set_breakpoint`
    fn note_breakpoint_installed(&mut self, _addr: u64) {}
    fn note_breakpoint_uninstalled(&mut self, _addr: u64) {}

    fn continue_execution(&mut self) -> Result<()>;
    fn step(&mut self) -> Result<()>;
    fn interrupt(&mut self) -> Result<()>;

    /// Block until the target stops
    fn wait_for_stop(&mut self) -> Result<StopEvent>;

    /// Poll for a stop
    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>>;

    fn get_thread_list(&mut self) -> Result<Vec<String>>;
    fn set_current_thread(&mut self, thread_id: &str) -> Result<()>;

    /// Return the currently stopped thread
    fn get_stopped_thread_id(&mut self) -> Result<String>;

    fn is_running(&self) -> bool;
}
