use std::time::Duration;

use crate::error::Result;
use crate::gdb::RegisterMap;
use crate::types::VirtAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BugcheckInfo {
    pub code: u32,
    pub parameters: [u64; 4],
    pub driver: Option<String>,
}

/// Backend-neutral stop event
pub struct StopEvent {
    /// Backend execution-context id, if the stop packet provided one
    pub thread_id: Option<String>,
    /// Backend exception/status code, when the stop packet carries one
    pub exception_code: Option<u32>,
    /// Program counter reported by the stop packet, when available
    pub program_counter: Option<u64>,
    /// Set when the stop was surfaced because the guest is processing a
    /// bugcheck (KD load-symbols teardown caught by the backend)
    pub is_bugcheck: bool,
    /// Structured bugcheck details decoded from KD debug output, when the
    /// target provided them before the stop packet
    pub bugcheck: Option<BugcheckInfo>,
    /// Set when the transport observed the target reset its KD packet stream,
    /// which usually means the guest rebooted and debugger state must be rebuilt.
    pub target_reloaded: bool,
    /// Kernel/module base reported by the stop packet, when available.
    pub target_kernel_base_hint: Option<VirtAddr>,
    /// Set when this stop was caused by a debugger-generated assist break-in
    /// during a target refresh/reconnect sequence, rather than by a user break
    /// or target exception.
    pub assisted_breakin: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugCapability {
    MemoryIntrospection,
    ExecutionControl,
    InterruptTarget,
    SingleStep,
    ReadRegisters,
    WriteRegisters,
    ThreadList,
    ThreadSelection,
    KernelBreakpoints,
    UserModeBreakpoints,
    TargetReloadDetection,
    KernelBaseHint,
    BugcheckDetection,
    BugcheckDetails,
    DebugOutput,
}

impl DebugCapability {
    pub fn label(self) -> &'static str {
        match self {
            Self::MemoryIntrospection => "memory introspection",
            Self::ExecutionControl => "execution control",
            Self::InterruptTarget => "target interrupt",
            Self::SingleStep => "single step",
            Self::ReadRegisters => "register read",
            Self::WriteRegisters => "register write",
            Self::ThreadList => "context enumeration",
            Self::ThreadSelection => "context selection",
            Self::KernelBreakpoints => "kernel breakpoints",
            Self::UserModeBreakpoints => "usermode breakpoints",
            Self::TargetReloadDetection => "target reload detection",
            Self::KernelBaseHint => "kernel base hint",
            Self::BugcheckDetection => "bugcheck stop detection",
            Self::BugcheckDetails => "bugcheck details",
            Self::DebugOutput => "debug output",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendCapability {
    pub capability: DebugCapability,
    pub supported: bool,
}

impl BackendCapability {
    pub fn supported(capability: DebugCapability) -> Self {
        Self {
            capability,
            supported: true,
        }
    }

    pub fn unsupported(capability: DebugCapability) -> Self {
        Self {
            capability,
            supported: false,
        }
    }
}

/// Debug transport abstraction; memory access stays on `/dev/kvm`
pub trait DebugBackend {
    fn register_map(&self) -> &RegisterMap;

    fn read_registers(&mut self) -> Result<Vec<u8>>;
    fn write_registers(&mut self, data: &[u8]) -> Result<()>;

    fn set_breakpoint(&mut self, addr: u64) -> Result<()>;
    fn remove_breakpoint(&mut self, addr: u64) -> Result<()>;

    fn supports_user_mode_breakpoints(&self) -> bool {
        false
    }

    fn optional_capabilities(&self) -> Vec<BackendCapability> {
        vec![
            BackendCapability {
                capability: DebugCapability::UserModeBreakpoints,
                supported: self.supports_user_mode_breakpoints(),
            },
            BackendCapability::unsupported(DebugCapability::TargetReloadDetection),
            BackendCapability::unsupported(DebugCapability::KernelBaseHint),
            BackendCapability::unsupported(DebugCapability::BugcheckDetection),
            BackendCapability::unsupported(DebugCapability::BugcheckDetails),
            BackendCapability::unsupported(DebugCapability::DebugOutput),
        ]
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        let mut capabilities = vec![
            BackendCapability::supported(DebugCapability::MemoryIntrospection),
            BackendCapability::supported(DebugCapability::ExecutionControl),
            BackendCapability::supported(DebugCapability::InterruptTarget),
            BackendCapability::supported(DebugCapability::SingleStep),
            BackendCapability::supported(DebugCapability::ReadRegisters),
            BackendCapability::supported(DebugCapability::WriteRegisters),
            BackendCapability::supported(DebugCapability::ThreadList),
            BackendCapability::supported(DebugCapability::ThreadSelection),
            BackendCapability::supported(DebugCapability::KernelBreakpoints),
        ];
        capabilities.extend(self.optional_capabilities());
        capabilities
    }

    /// Notify the backend about a breakpoint patched outside `set_breakpoint`
    fn note_breakpoint_installed(&mut self, _addr: u64) {}
    fn note_breakpoint_uninstalled(&mut self, _addr: u64) {}

    /// Notify the backend about guest rediscovery progress after a transport
    /// reload. Backends can use this to tune reconnect assistance while booting.
    fn note_target_rediscovery_pending(&mut self) {}
    fn note_target_rediscovery_complete(&mut self) {}

    /// Best-effort kernel base reported by the transport after a target reload.
    /// KD provides this via GetVersion; transports without a native answer return
    /// None and let the KVM-side guest scanner discover the kernel normally.
    fn target_kernel_base_hint(&mut self) -> Result<Option<VirtAddr>> {
        Ok(None)
    }

    fn continue_execution(&mut self) -> Result<()>;
    fn step(&mut self) -> Result<()>;
    fn interrupt(&mut self) -> Result<StopEvent>;

    /// Block until the target stops
    fn wait_for_stop(&mut self) -> Result<StopEvent>;

    /// Poll for a stop
    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>>;

    fn thread_list(&mut self) -> Result<Vec<String>>;
    fn set_current_thread(&mut self, thread_id: &str) -> Result<()>;

    /// Return the currently stopped execution context
    fn stopped_thread_id(&mut self) -> Result<String>;

    fn is_running(&self) -> bool;

    /// Best-effort target cleanup before the frontend exits.
    ///
    /// `leave_running` means the frontend wants the guest executing after exit.
    /// Backends with background servicing threads can override this to make
    /// teardown explicit instead of relying on `Drop` timing.
    fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
        if leave_running && !self.is_running() {
            self.continue_execution()?;
        }
        Ok(())
    }

    /// Return (and clear) whether a kernel module/driver loaded or unloaded since
    /// the last call, used to invalidate module-dependent caches (driver
    /// completions). Default `false`: backends without a load event rely instead
    /// on the per-stop module-list diff.
    fn take_modules_changed(&mut self) -> bool {
        false
    }
}
