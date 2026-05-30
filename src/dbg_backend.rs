use std::time::Duration;

use crate::error::Result;
use crate::gdb::RegisterMap;

/// Backend-neutral stop event
pub struct StopEvent {
    /// Backend thread/vCPU id, if the stop packet provided one
    pub thread_id: Option<String>,
    /// Human-readable stop/exit reason, if the backend provided one
    pub summary: Option<String>,
    /// True if the debug target exited, was terminated, or reports no resumed threads
    pub target_exited: bool,
}

/// Debug transport abstraction; memory access stays on `/dev/kvm`
pub trait DebugBackend {
    fn register_map(&self) -> &RegisterMap;

    fn read_registers(&mut self) -> Result<Vec<u8>>;
    fn write_registers(&mut self, data: &[u8]) -> Result<()>;

    fn set_breakpoint(&mut self, addr: u64) -> Result<()>;
    fn remove_breakpoint(&mut self, addr: u64) -> Result<()>;

    fn set_hardware_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(crate::error::Error::NotSupported)
    }

    fn remove_hardware_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(crate::error::Error::NotSupported)
    }

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

    /// Run a QEMU monitor command through the gdbstub, if this backend supports it.
    fn monitor_command(&mut self, _command: &str) -> Result<String> {
        Err(crate::error::Error::NotSupported)
    }

    fn is_running(&self) -> bool;
}

#[cfg(test)]
pub mod fake {
    //! A deterministic in-memory [`DebugBackend`] for tests. It records
    //! breakpoint and continue/step activity and serves a scripted queue of
    //! stop events, so backend-neutral logic can be exercised without a guest.

    use std::collections::{BTreeSet, VecDeque};
    use std::time::Duration;

    use super::{DebugBackend, StopEvent};
    use crate::error::Result;
    use crate::gdb::{RegisterInfo, RegisterMap};

    pub struct FakeBackend {
        register_map: RegisterMap,
        registers: Vec<u8>,
        pub software_breakpoints: BTreeSet<u64>,
        pub hardware_breakpoints: BTreeSet<u64>,
        running: bool,
        current_thread: String,
        threads: Vec<String>,
        stop_queue: VecDeque<StopEvent>,
        pub continue_count: usize,
        pub step_count: usize,
        pub interrupt_count: usize,
    }

    impl FakeBackend {
        /// Backend with `rsp`/`rip`/`cr3` registers laid out contiguously.
        pub fn new() -> Self {
            let register_map = RegisterMap::from_registers(vec![
                RegisterInfo {
                    name: "rsp".into(),
                    offset: 0,
                    size: 8,
                    regnum: 0,
                },
                RegisterInfo {
                    name: "rip".into(),
                    offset: 8,
                    size: 8,
                    regnum: 1,
                },
                RegisterInfo {
                    name: "cr3".into(),
                    offset: 16,
                    size: 8,
                    regnum: 2,
                },
            ]);
            Self {
                register_map,
                registers: vec![0u8; 24],
                software_breakpoints: BTreeSet::new(),
                hardware_breakpoints: BTreeSet::new(),
                running: false,
                current_thread: "1".into(),
                threads: vec!["1".into()],
                stop_queue: VecDeque::new(),
                continue_count: 0,
                step_count: 0,
                interrupt_count: 0,
            }
        }

        pub fn set_register(&mut self, name: &str, value: u64) {
            self.register_map
                .write_u64(name, &mut self.registers, value)
                .unwrap();
        }

        pub fn queue_stop(&mut self, event: StopEvent) {
            self.stop_queue.push_back(event);
        }
    }

    impl DebugBackend for FakeBackend {
        fn register_map(&self) -> &RegisterMap {
            &self.register_map
        }

        fn read_registers(&mut self) -> Result<Vec<u8>> {
            Ok(self.registers.clone())
        }

        fn write_registers(&mut self, data: &[u8]) -> Result<()> {
            self.registers = data.to_vec();
            Ok(())
        }

        fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
            self.software_breakpoints.insert(addr);
            Ok(())
        }

        fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
            self.software_breakpoints.remove(&addr);
            Ok(())
        }

        fn set_hardware_breakpoint(&mut self, addr: u64) -> Result<()> {
            self.hardware_breakpoints.insert(addr);
            Ok(())
        }

        fn remove_hardware_breakpoint(&mut self, addr: u64) -> Result<()> {
            self.hardware_breakpoints.remove(&addr);
            Ok(())
        }

        fn continue_execution(&mut self) -> Result<()> {
            self.continue_count += 1;
            self.running = true;
            Ok(())
        }

        fn step(&mut self) -> Result<()> {
            self.step_count += 1;
            Ok(())
        }

        fn interrupt(&mut self) -> Result<()> {
            self.interrupt_count += 1;
            self.running = false;
            Ok(())
        }

        fn wait_for_stop(&mut self) -> Result<StopEvent> {
            self.running = false;
            Ok(self.stop_queue.pop_front().unwrap_or(StopEvent {
                thread_id: Some(self.current_thread.clone()),
                summary: None,
                target_exited: false,
            }))
        }

        fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
            match self.stop_queue.pop_front() {
                Some(event) => {
                    self.running = false;
                    Ok(Some(event))
                }
                None => Ok(None),
            }
        }

        fn get_thread_list(&mut self) -> Result<Vec<String>> {
            Ok(self.threads.clone())
        }

        fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
            self.current_thread = thread_id.to_string();
            Ok(())
        }

        fn get_stopped_thread_id(&mut self) -> Result<String> {
            Ok(self.current_thread.clone())
        }

        fn is_running(&self) -> bool {
            self.running
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeBackend;
    use super::{DebugBackend, StopEvent};
    use std::time::Duration;

    #[test]
    fn tracks_software_breakpoint_lifecycle() {
        let mut backend = FakeBackend::new();
        backend.set_breakpoint(0x1000).unwrap();
        backend.set_breakpoint(0x2000).unwrap();
        assert_eq!(backend.software_breakpoints.len(), 2);

        backend.remove_breakpoint(0x1000).unwrap();
        assert!(!backend.software_breakpoints.contains(&0x1000));
        assert!(backend.software_breakpoints.contains(&0x2000));
    }

    #[test]
    fn hardware_breakpoints_are_tracked_separately() {
        let mut backend = FakeBackend::new();
        backend.set_hardware_breakpoint(0x4000).unwrap();
        backend.set_breakpoint(0x5000).unwrap();
        assert!(backend.hardware_breakpoints.contains(&0x4000));
        assert!(!backend.software_breakpoints.contains(&0x4000));
        backend.remove_hardware_breakpoint(0x4000).unwrap();
        assert!(backend.hardware_breakpoints.is_empty());
    }

    #[test]
    fn continue_then_wait_delivers_queued_stop_and_clears_running() {
        let mut backend = FakeBackend::new();
        backend.queue_stop(StopEvent {
            thread_id: Some("3".into()),
            summary: Some("breakpoint".into()),
            target_exited: false,
        });

        backend.continue_execution().unwrap();
        assert!(backend.is_running());
        assert_eq!(backend.continue_count, 1);

        let event = backend.wait_for_stop().unwrap();
        assert_eq!(event.thread_id.as_deref(), Some("3"));
        assert!(!backend.is_running());
    }

    #[test]
    fn try_wait_returns_none_until_a_stop_is_queued() {
        let mut backend = FakeBackend::new();
        backend.continue_execution().unwrap();
        assert!(backend.try_wait_for_stop(Duration::ZERO).unwrap().is_none());
        assert!(backend.is_running());

        backend.queue_stop(StopEvent {
            thread_id: None,
            summary: None,
            target_exited: true,
        });
        let event = backend.try_wait_for_stop(Duration::ZERO).unwrap().unwrap();
        assert!(event.target_exited);
        assert!(!backend.is_running());
    }

    #[test]
    fn registers_round_trip_through_register_map() {
        let mut backend = FakeBackend::new();
        backend.set_register("rsp", 0xdead_beef);
        backend.set_register("rip", 0xfeed_face);

        let regs = backend.read_registers().unwrap();
        let map = backend.register_map();
        assert_eq!(map.read_u64("rsp", &regs).unwrap(), 0xdead_beef);
        assert_eq!(map.read_u64("rip", &regs).unwrap(), 0xfeed_face);
    }
}
