use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{Guest, ModuleSymbolLoadReport, ProcessInfo, StructRef, WinObject},
    host::KvmHandle,
    symbols::{ParsedType, SymbolIndex, SymbolStore, TypeInfo},
    types::{Dtb, PageTableEntry, Value, VirtAddr},
};

pub struct DebuggerContext {
    pub kvm: Arc<KvmHandle>,
    pub symbols: Arc<SymbolStore>,
    pub guest: Guest,
    pub current_process: Option<WinObject>,
    pub current_process_info: Option<ProcessInfo>,
    context_dtb_override: Option<Dtb>,
    pub registers: Option<HashMap<String, u64>>,
    /// Windows thread metadata for the currently inspected live vCPU context.
    pub current_windows_thread: Option<ThreadInfo>,
    /// User-defined convenience variables (`$name`), sticky for the session
    pub user_vars: HashMap<String, UserVar>,
    /// Volatile result slots (`$0`, `$1`, ...) repopulated by the most recent
    /// result-producing command (search, ev, ...)
    pub results: Vec<u64>,
    /// The command that produced the current result slots, for `vars`
    pub results_origin: Option<String>,
}

const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// A user-defined convenience variable and the expression it was defined from
#[derive(Debug, Clone)]
pub struct UserVar {
    pub value: u64,
    pub source: String,
}

pub struct BuiltinVar {
    pub name: &'static str,
    pub value: u64,
    pub source: &'static str,
}

#[derive(Debug, Clone)]
pub struct DriverObjectInfo {
    pub name: String,
    pub object: VirtAddr,
    pub driver_start: VirtAddr,
    pub driver_size: u64,
    pub device_object: VirtAddr,
    pub driver_unload: VirtAddr,
}

#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub ethread: VirtAddr,
    pub kthread: VirtAddr,
    pub tid: Option<u64>,
    pub pid: Option<u64>,
    pub process_name: Option<String>,
    pub eprocess: Option<VirtAddr>,
    pub state: Option<u8>,
    pub wait_reason: Option<u8>,
    pub priority: Option<u8>,
    pub base_priority: Option<u8>,
    pub wait_irql: Option<u8>,
    pub kernel_stack_resident: Option<bool>,
    pub start_address: Option<VirtAddr>,
    pub win32_start_address: Option<VirtAddr>,
    pub teb: Option<VirtAddr>,
    pub kernel_stack: Option<VirtAddr>,
    pub stack_base: Option<VirtAddr>,
    pub stack_limit: Option<VirtAddr>,
    pub trap_frame: Option<VirtAddr>,
    pub pending_irps: Option<Vec<VirtAddr>>,
}

impl ThreadInfo {
    pub fn pseudo_register_value(&self, name: &str) -> Option<u64> {
        match name.to_ascii_lowercase().as_str() {
            "thread" | "ethread" => Some(self.ethread.0),
            "kthread" => Some(self.kthread.0),
            "tid" => self.tid,
            "pid" => self.pid,
            "proc" | "process" | "eprocess" => self.eprocess.map(|addr| addr.0),
            "teb" => self.teb.map(|addr| addr.0),
            "threadstart" | "startaddress" => self.start_address.map(|addr| addr.0),
            "win32start" | "win32startaddress" => self.win32_start_address.map(|addr| addr.0),
            "kernelstack" => self.kernel_stack.map(|addr| addr.0),
            "stackbase" => self.stack_base.map(|addr| addr.0),
            "stacklimit" => self.stack_limit.map(|addr| addr.0),
            "trapframe" => self.trap_frame.map(|addr| addr.0),
            "priority" => self.priority.map(u64::from),
            "basepriority" => self.base_priority.map(u64::from),
            "waitirql" => self.wait_irql.map(u64::from),
            "stackresident" | "kernelstackresident" => {
                self.kernel_stack_resident.map(|resident| resident as u64)
            }
            _ => None,
        }
    }
}

pub fn kthread_state_name(state: u8) -> &'static str {
    match state {
        0 => "Initialized",
        1 => "Ready",
        2 => "Running",
        3 => "Standby",
        4 => "Terminated",
        5 => "Waiting",
        6 => "Transition",
        7 => "DeferredReady",
        8 => "GateWaitObsolete",
        9 => "WaitingForProcessInSwap",
        _ => "?",
    }
}

pub fn wait_reason_name(reason: u8) -> &'static str {
    match reason {
        0 => "Executive",
        1 => "FreePage",
        2 => "PageIn",
        3 => "PoolAllocation",
        4 => "DelayExecution",
        5 => "Suspended",
        6 => "UserRequest",
        7 => "WrExecutive",
        8 => "WrFreePage",
        9 => "WrPageIn",
        10 => "WrPoolAllocation",
        11 => "WrDelayExecution",
        12 => "WrSuspended",
        13 => "WrUserRequest",
        14 => "WrEventPair",
        15 => "WrQueue",
        16 => "WrLpcReceive",
        17 => "WrLpcReply",
        18 => "WrVirtualMemory",
        19 => "WrPageOut",
        20 => "WrRendezvous",
        21 => "WrKeyedEvent",
        22 => "WrTerminated",
        23 => "WrProcessInSwap",
        24 => "WrCpuRateControl",
        25 => "WrCalloutStack",
        26 => "WrKernel",
        27 => "WrResource",
        28 => "WrPushLock",
        29 => "WrMutex",
        30 => "WrQuantumEnd",
        31 => "WrDispatchInt",
        32 => "WrPreempted",
        33 => "WrYieldExecution",
        34 => "WrFastMutex",
        35 => "WrGuardedMutex",
        36 => "WrRundown",
        37 => "WrAlertByThreadId",
        38 => "WrDeferredPreempt",
        _ => "?",
    }
}

#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub protection: Option<u64>,
    pub vad_type: Option<u64>,
    pub private_memory: Option<bool>,
    pub commit_charge: Option<u64>,
    pub details: Option<String>,
}

impl MemoryRegionInfo {
    pub fn size(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
}

struct ObjectNameLayout {
    body_offset: u64,
    info_mask_offset: u64,
    name_info_size: u64,
    name_offset: u64,
}

struct ObjectDirectoryLayout {
    buckets_offset: u64,
    bucket_count: u64,
    chain_offset: u64,
    object_offset: u64,
    name_offset: Option<u64>,
}

pub struct DebuggerStartupMessage {
    pub build_number: Value<u16>,
    pub base_address: VirtAddr,
    pub loaded_module_list: VirtAddr,
}

pub struct DebuggerReloadReport {
    pub previous_base_address: VirtAddr,
    pub startup: Option<DebuggerStartupMessage>,
    pub symbol_report: Option<ModuleSymbolLoadReport>,
    pub symbol_error: Option<String>,
}

pub struct AttachReport {
    pub name: String,
    pub symbol_report: ModuleSymbolLoadReport,
}

pub struct DebuggerPte {
    name: String, // TODO maybe enum instead?
    address: VirtAddr,
    value: PageTableEntry,
}

pub struct DebuggerPteTraversal {
    pub address: VirtAddr,
    pub pxe: DebuggerPte,
    pub ppe: DebuggerPte,
    pub pde: Option<DebuggerPte>,
    pub pte: Option<DebuggerPte>,
}

impl DebuggerContext {
    pub fn new() -> Result<Self> {
        let kvm = Arc::new(KvmHandle::new()?);
        let symbols = Arc::new(SymbolStore::new());
        let guest = Guest::new(kvm.clone(), symbols.clone())?;

        // load symbols for all kernel modules (ntoskrnl is already loaded, this adds others)
        let _ = guest.load_all_kernel_module_symbols(&kvm, &symbols);

        Ok(Self {
            kvm,
            symbols,
            guest,
            current_process: None,
            current_process_info: None,
            context_dtb_override: None,
            registers: None,
            current_windows_thread: None,
            user_vars: HashMap::new(),
            results: Vec::new(),
            results_origin: None,
        })
    }

    pub fn current_process(&self) -> &WinObject {
        match &self.current_process {
            Some(p) => p,
            None => &self.guest.ntoskrnl,
        }
    }

    pub fn attach(&mut self, pid: u64) -> Result<AttachReport> {
        let processes = self.guest.enumerate_processes()?;
        let process_info = processes
            .iter()
            .find(|p| p.pid == pid)
            .ok_or(Error::ProcessNotFound(pid))?
            .clone();

        self.attach_process_info(process_info)
    }

    pub fn attach_process_info(&mut self, process_info: ProcessInfo) -> Result<AttachReport> {
        let name = process_info.name.clone();

        let symbol_report =
            self.guest
                .load_all_process_module_symbols(&self.kvm, &self.symbols, &process_info);

        let winobj = self.guest.winobj_from_process_info(&process_info)?;

        self.current_process = Some(winobj);
        self.current_process_info = Some(process_info);
        self.clear_context_dtb_override();
        self.clear_current_windows_thread_context();
        Ok(AttachReport {
            name,
            symbol_report: symbol_report?,
        })
    }

    pub fn detach(&mut self) {
        self.clear_context_dtb_override();
        self.clear_current_windows_thread_context();
        self.current_process = None;
        self.current_process_info = None;
    }

    pub fn set_context_dtb_override(&mut self, dtb: Dtb) {
        self.context_dtb_override = Some(Self::normalize_cr3(dtb));
    }

    pub fn clear_context_dtb_override(&mut self) {
        self.context_dtb_override = None;
    }

    pub fn normalize_cr3(cr3: u64) -> Dtb {
        cr3 & CR3_PAGE_MASK
    }

    pub fn set_current_windows_thread_context(&mut self, thread: ThreadInfo) {
        self.current_windows_thread = Some(thread);
    }

    pub fn clear_current_windows_thread_context(&mut self) {
        self.current_windows_thread = None;
    }

    pub fn current_thread_pseudo_register(&self, name: &str) -> Option<u64> {
        let thread = self.current_windows_thread.as_ref()?;
        thread.pseudo_register_value(name)
    }

    pub fn builtin_variable_value(&self, name: &str) -> Option<u64> {
        let name = name.trim_start_matches('$').to_ascii_lowercase();
        if let Some(value) = self.current_thread_pseudo_register(&name) {
            return Some(value);
        }

        match name.as_str() {
            "dtb" => Some(self.current_dtb()),
            "ntbase" | "kernelbase" => Some(self.guest.ntoskrnl.base_address.0),
            "processbase" | "imagebase" => self.current_process.as_ref().map(|p| p.base_address.0),
            "processdtb" => self.current_process_info.as_ref().map(|p| p.dtb),
            "attachedeprocess" | "attachedprocess" => {
                self.current_process_info.as_ref().map(|p| p.eprocess_va.0)
            }
            "attachedpid" => self.current_process_info.as_ref().map(|p| p.pid),
            "eprocess" | "process" => self.current_process_info.as_ref().map(|p| p.eprocess_va.0),
            "pid" => self.current_process_info.as_ref().map(|p| p.pid),
            _ => None,
        }
    }

    pub fn builtin_variables(&self) -> Vec<BuiltinVar> {
        let mut vars = vec![
            BuiltinVar {
                name: "dtb",
                value: self.current_dtb(),
                source: "current address space",
            },
            BuiltinVar {
                name: "ntbase",
                value: self.guest.ntoskrnl.base_address.0,
                source: "kernel base",
            },
        ];

        if let Some(process) = &self.current_process_info {
            vars.extend([
                BuiltinVar {
                    name: "processbase",
                    value: self
                        .current_process
                        .as_ref()
                        .map(|p| p.base_address.0)
                        .unwrap_or(0),
                    source: "attached process image base",
                },
                BuiltinVar {
                    name: "processdtb",
                    value: process.dtb,
                    source: "attached process DTB",
                },
                BuiltinVar {
                    name: "attachedeprocess",
                    value: process.eprocess_va.0,
                    source: "attached process EPROCESS",
                },
                BuiltinVar {
                    name: "attachedpid",
                    value: process.pid,
                    source: "attached process PID",
                },
            ]);
            // pid/eprocess fall back to the attached process when no thread
            // context shadows them; keep the listing in sync with evaluation
            if self.current_windows_thread.is_none() {
                vars.extend([
                    BuiltinVar {
                        name: "eprocess",
                        value: process.eprocess_va.0,
                        source: "attached process EPROCESS",
                    },
                    BuiltinVar {
                        name: "pid",
                        value: process.pid,
                        source: "attached process PID",
                    },
                ]);
            }
        }

        if let Some(thread) = &self.current_windows_thread {
            let mut push = |name, value: Option<u64>, source| {
                if let Some(value) = value {
                    vars.push(BuiltinVar {
                        name,
                        value,
                        source,
                    });
                }
            };
            push("thread", Some(thread.ethread.0), "current Windows ETHREAD");
            push("ethread", Some(thread.ethread.0), "current Windows ETHREAD");
            push("kthread", Some(thread.kthread.0), "current Windows KTHREAD");
            push("tid", thread.tid, "current Windows TID");
            push("pid", thread.pid, "current Windows PID");
            push(
                "eprocess",
                thread.eprocess.map(|addr| addr.0),
                "current thread EPROCESS",
            );
            push(
                "process",
                thread.eprocess.map(|addr| addr.0),
                "current thread EPROCESS",
            );
            push("teb", thread.teb.map(|addr| addr.0), "current thread TEB");
            push(
                "threadstart",
                thread.start_address.map(|addr| addr.0),
                "current thread start address",
            );
            push(
                "win32start",
                thread.win32_start_address.map(|addr| addr.0),
                "current thread Win32 start address",
            );
            push(
                "kernelstack",
                thread.kernel_stack.map(|addr| addr.0),
                "current thread kernel stack",
            );
            push(
                "stackbase",
                thread.stack_base.map(|addr| addr.0),
                "current thread stack base",
            );
            push(
                "stacklimit",
                thread.stack_limit.map(|addr| addr.0),
                "current thread stack limit",
            );
            push(
                "trapframe",
                thread.trap_frame.map(|addr| addr.0),
                "current thread trap frame",
            );
        }

        vars
    }

    pub fn set_results(&mut self, results: Vec<u64>, origin: impl Into<String>) {
        self.results = results;
        self.results_origin = Some(origin.into());
    }

    pub fn reload_guest_with_kernel_base_hint(
        &mut self,
        kernel_base_hint: Option<VirtAddr>,
    ) -> Result<DebuggerReloadReport> {
        let previous_base_address = self.guest.ntoskrnl.base_address;
        let previous_dtb = self.guest.ntoskrnl.dtb();
        let guest = Guest::new_with_kernel_base_hint(
            self.kvm.clone(),
            self.symbols.clone(),
            kernel_base_hint,
        )?;
        let new_dtb = guest.ntoskrnl.dtb();

        self.symbols.clear_modules_for_dtb(previous_dtb);
        self.symbols.clear_modules_for_dtb(new_dtb);
        self.guest = guest;
        self.detach();
        self.clear_context_dtb_override();
        self.registers = None;
        self.clear_current_windows_thread_context();

        let (symbol_report, symbol_error) = match self
            .guest
            .load_all_kernel_module_symbols(&self.kvm, &self.symbols)
        {
            Ok(report) => (Some(report), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let startup = self.startup_message_data().ok();

        Ok(DebuggerReloadReport {
            previous_base_address,
            startup,
            symbol_report,
            symbol_error,
        })
    }

    pub fn current_kernel_mapping_is_valid(&self) -> bool {
        let memory = self.guest.ntoskrnl.memory();
        let mut signature = [0u8; 2];
        memory
            .read_bytes(self.guest.ntoskrnl.base_address, &mut signature)
            .is_ok_and(|()| signature == *b"MZ")
    }

    pub fn rediscovered_kernel_identity_changed(&self) -> Result<bool> {
        let guest = Guest::new(self.kvm.clone(), self.symbols.clone())?;
        Ok(
            guest.ntoskrnl.base_address != self.guest.ntoskrnl.base_address
                || guest.ntoskrnl.dtb() != self.guest.ntoskrnl.dtb(),
        )
    }

    pub fn refresh_kernel_module_symbols(&self) -> Result<ModuleSymbolLoadReport> {
        self.guest
            .load_missing_kernel_module_symbols(&self.kvm, &self.symbols)
    }

    pub fn current_dtb(&self) -> Dtb {
        if let Some(dtb) = self.context_dtb_override {
            return dtb;
        }
        match &self.current_process {
            Some(p) => p.dtb(),
            None => self.guest.ntoskrnl.dtb(),
        }
    }

    /// Open a fluent cursor over a kernel struct (ntoskrnl's layout, read
    /// through ntoskrnl's address space).
    fn kernel_struct(&self, name: &str, base: VirtAddr) -> Result<StructRef<'_>> {
        self.guest.ntoskrnl.types().struct_at(name, base)
    }

    fn read_kernel_unicode_string(&self, addr: VirtAddr) -> Result<String> {
        self.kernel_struct("_UNICODE_STRING", addr)?
            .read_unicode_string()
    }

    fn object_name_layout(&self) -> Result<ObjectNameLayout> {
        let header_type = self
            .symbols
            .find_type_across_modules(self.guest.ntoskrnl.dtb(), "_OBJECT_HEADER")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER".to_string()))?;
        let name_info_type = self
            .symbols
            .find_type_across_modules(self.guest.ntoskrnl.dtb(), "_OBJECT_HEADER_NAME_INFO")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER_NAME_INFO".to_string()))?;
        Ok(ObjectNameLayout {
            body_offset: header_type.field_offset("Body")?,
            info_mask_offset: header_type.field_offset("InfoMask")?,
            name_info_size: name_info_type.size as u64,
            name_offset: name_info_type.field_offset("Name")?,
        })
    }

    fn read_kernel_object_name(
        &self,
        object: VirtAddr,
        object_name: &ObjectNameLayout,
    ) -> Result<Option<String>> {
        let memory = self.guest.ntoskrnl.memory();
        let header = object - object_name.body_offset;
        let info_mask: u8 = memory.read(header + object_name.info_mask_offset)?;
        if (info_mask & 0x02) == 0 {
            return Ok(None);
        }
        let name_info = header - object_name.name_info_size;
        Ok(Some(self.read_kernel_unicode_string(
            name_info + object_name.name_offset,
        )?))
    }

    fn object_directory_layout(&self) -> Result<ObjectDirectoryLayout> {
        let dir_type = self
            .symbols
            .find_type_across_modules(self.guest.ntoskrnl.dtb(), "_OBJECT_DIRECTORY")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_DIRECTORY".to_string()))?;
        let entry_type = self
            .symbols
            .find_type_across_modules(self.guest.ntoskrnl.dtb(), "_OBJECT_DIRECTORY_ENTRY")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_DIRECTORY_ENTRY".to_string()))?;
        let buckets = dir_type
            .fields
            .get("HashBuckets")
            .ok_or_else(|| Error::FieldNotFound("HashBuckets".to_string()))?;
        Ok(ObjectDirectoryLayout {
            buckets_offset: buckets.offset as u64,
            bucket_count: (buckets.size / 8).max(1),
            chain_offset: entry_type.field_offset("ChainLink")?,
            object_offset: entry_type.field_offset("Object")?,
            name_offset: entry_type.fields.get("Name").map(|f| f.offset as u64),
        })
    }

    fn enumerate_object_directory(
        &self,
        directory: VirtAddr,
        dir: &ObjectDirectoryLayout,
        object_name: &ObjectNameLayout,
    ) -> Result<Vec<(String, VirtAddr)>> {
        let memory = self.guest.ntoskrnl.memory();
        let mut out = Vec::new();
        for bucket in 0..dir.bucket_count {
            let mut entry: VirtAddr = memory.read(directory + dir.buckets_offset + bucket * 8)?;
            for _ in 0..4096 {
                if entry.is_zero() {
                    break;
                }
                let object: VirtAddr = memory.read(entry + dir.object_offset)?;
                if !object.is_zero() {
                    let name = match dir.name_offset {
                        Some(offset) => Some(self.read_kernel_unicode_string(entry + offset)?),
                        None => self.read_kernel_object_name(object, object_name)?,
                    };
                    if let Some(name) = name
                        && !name.is_empty()
                    {
                        out.push((name, object));
                    }
                }
                entry = memory.read(entry + dir.chain_offset)?;
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    pub fn enumerate_driver_objects(&self) -> Result<Vec<DriverObjectInfo>> {
        let memory = self.guest.ntoskrnl.memory();
        let object_name = self.object_name_layout()?;
        let dir = self.object_directory_layout()?;
        let root_ptr = self
            .guest
            .ntoskrnl
            .symbol("ObpRootDirectoryObject")?
            .address();
        let root: VirtAddr = memory.read(root_ptr)?;
        let driver_dir = self
            .enumerate_object_directory(root, &dir, &object_name)?
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Driver"))
            .map(|(_, object)| object)
            .ok_or_else(|| Error::DebugInfo("\\Driver object directory not found".to_string()))?;

        let mut drivers = Vec::new();
        for (name, object) in self.enumerate_object_directory(driver_dir, &dir, &object_name)? {
            let driver = self.kernel_struct("_DRIVER_OBJECT", object)?;
            drivers.push(DriverObjectInfo {
                name: format!("\\Driver\\{name}"),
                object,
                driver_start: driver.read_field("DriverStart")?,
                driver_size: driver.read_field::<u32>("DriverSize")? as u64,
                device_object: driver.read_field("DeviceObject")?,
                driver_unload: driver.read_field("DriverUnload")?,
            });
        }
        Ok(drivers)
    }

    pub fn enumerate_threads_for_process_info(
        &self,
        process: &ProcessInfo,
    ) -> Result<Vec<ThreadInfo>> {
        let memory = self.guest.ntoskrnl.memory();
        let eprocess = self
            .guest
            .ntoskrnl
            .types_in(process.dtb)
            .struct_at("_EPROCESS", process.eprocess_va)?;
        let eprocess_layout = self.guest.ntoskrnl.types().layout("_EPROCESS")?;
        let thread_list_head_offset = eprocess_layout.field_offset("ThreadListHead")?;
        let ethread_layout = self.guest.ntoskrnl.types().layout("_ETHREAD")?;
        let thread_list_entry_offset = ethread_layout.field_offset("ThreadListEntry")?;
        let head = eprocess.addr() + thread_list_head_offset;

        let mut threads = Vec::new();
        let mut visited = HashSet::new();
        let mut current: VirtAddr = memory.read(head)?;

        for _ in 0..16384 {
            if current.is_zero() || current == head || !visited.insert(current.0) {
                break;
            }

            let ethread = current - thread_list_entry_offset;
            threads.push(self.thread_info_from_ethread_with_hint(ethread, Some(process))?);
            current = memory.read(current)?;
        }

        Ok(threads)
    }

    pub fn enumerate_threads(&self) -> Result<Vec<ThreadInfo>> {
        let processes = self.guest.enumerate_processes()?;
        let mut threads = Vec::new();

        for process in &processes {
            let Ok(process_threads) = self.enumerate_threads_for_process_info(process) else {
                continue;
            };
            threads.extend(process_threads);
        }

        Ok(threads)
    }

    pub fn thread_info_from_ethread(&self, ethread: VirtAddr) -> Result<ThreadInfo> {
        self.thread_info_from_ethread_with_hint(ethread, None)
    }

    fn thread_info_from_ethread_with_hint(
        &self,
        ethread: VirtAddr,
        process_hint: Option<&ProcessInfo>,
    ) -> Result<ThreadInfo> {
        let memory = self.guest.ntoskrnl.memory();
        let types = self.guest.ntoskrnl.types();
        let ethread_layout = types.layout("_ETHREAD")?;
        let kthread_layout = types.layout("_KTHREAD")?;
        let tcb_offset = ethread_layout.field_offset("Tcb").unwrap_or(0);
        let kthread = ethread + tcb_offset;

        let cid_base = ethread_layout
            .field_offset("Cid")
            .ok()
            .map(|offset| ethread + offset);
        let client_id_layout = types.layout("_CLIENT_ID").ok();
        let tid = cid_base.and_then(|base| {
            client_id_layout
                .as_ref()
                .and_then(|layout| layout.field_offset("UniqueThread").ok())
                .and_then(|offset| memory.read::<u64>(base + offset).ok())
        });
        let pid = cid_base.and_then(|base| {
            client_id_layout
                .as_ref()
                .and_then(|layout| layout.field_offset("UniqueProcess").ok())
                .and_then(|offset| memory.read::<u64>(base + offset).ok())
        });

        let read_ethread_ptr = |field: &str| -> Option<VirtAddr> {
            ethread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<VirtAddr>(ethread + offset).ok())
                .filter(|addr| !addr.is_zero())
        };
        let read_kthread_ptr = |field: &str| -> Option<VirtAddr> {
            kthread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<VirtAddr>(kthread + offset).ok())
                .filter(|addr| !addr.is_zero())
        };
        let read_kthread_u8 = |field: &str| -> Option<u8> {
            kthread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<u8>(kthread + offset).ok())
        };

        // KTHREAD.Process is a KPROCESS*, which is the Pcb at offset 0 of the
        // owning EPROCESS; present across modern builds and the most reliable
        // source. ThreadsProcess (older builds) and ProcessFastRef (newest, an
        // EX_FAST_REF that packs the pointer with refcount bits in the low 4)
        // are build-specific fallbacks.
        let eprocess = read_kthread_ptr("Process")
            .or_else(|| read_ethread_ptr("ThreadsProcess"))
            .or_else(|| {
                ethread_layout
                    .field_offset("ProcessFastRef")
                    .ok()
                    .and_then(|offset| memory.read::<u64>(ethread + offset).ok())
                    .map(|raw| VirtAddr(raw & !0xf))
                    .filter(|addr| !addr.is_zero())
            });

        // Bulk enumeration passes the owning process as a hint, so it never
        // walks the process list per thread. Single-thread lookups (break
        // context, `thread_info_from_ethread`) have no hint, so match the
        // thread's pid/EPROCESS against a one-shot process list for the name.
        let owner: Option<ProcessInfo> = match process_hint {
            Some(_) => None,
            None => self.guest.enumerate_processes().ok().and_then(|processes| {
                processes.into_iter().find(|process| {
                    pid.is_some_and(|pid| process.pid == pid)
                        || eprocess.is_some_and(|eprocess| process.eprocess_va == eprocess)
                })
            }),
        };
        let owner = process_hint.or(owner.as_ref());

        let process_name = owner
            .map(|process| process.name.clone())
            .or_else(|| eprocess.and_then(|eprocess| self.guest.process_image_name(eprocess)))
            // PID 0 is the System Idle Process, which isn't on PsActiveProcessHead
            // and so never matches above; label its per-CPU idle threads like WinDbg
            .or_else(|| (pid == Some(0)).then(|| "Idle".to_string()));

        Ok(ThreadInfo {
            ethread,
            kthread,
            tid,
            pid: pid.or_else(|| owner.map(|process| process.pid)),
            process_name,
            eprocess: eprocess.or_else(|| owner.map(|process| process.eprocess_va)),
            state: read_kthread_u8("State"),
            wait_reason: read_kthread_u8("WaitReason"),
            priority: read_kthread_u8("Priority"),
            base_priority: read_kthread_u8("BasePriority"),
            wait_irql: read_kthread_u8("WaitIrql"),
            kernel_stack_resident: read_kthread_u8("KernelStackResident").map(|value| value != 0),
            start_address: read_ethread_ptr("StartAddress"),
            win32_start_address: read_ethread_ptr("Win32StartAddress"),
            teb: read_ethread_ptr("Teb"),
            kernel_stack: read_kthread_ptr("KernelStack"),
            stack_base: read_kthread_ptr("StackBase"),
            stack_limit: read_kthread_ptr("StackLimit"),
            trap_frame: read_kthread_ptr("TrapFrame"),
            pending_irps: self.thread_pending_irps(&memory, &ethread_layout, ethread),
        })
    }

    fn thread_pending_irps(
        &self,
        memory: &impl MemoryOps<VirtAddr>,
        ethread_layout: &TypeInfo,
        ethread: VirtAddr,
    ) -> Option<Vec<VirtAddr>> {
        let irp_list_offset = ethread_layout.field_offset("IrpList").ok()?;
        let irp_layout = self.guest.ntoskrnl.types().layout("_IRP").ok()?;
        let thread_list_entry_offset = irp_layout.field_offset("ThreadListEntry").ok()?;
        let head = ethread + irp_list_offset;
        let mut current: VirtAddr = memory.read(head).ok()?;
        let mut irps = Vec::new();
        let mut visited = HashSet::new();

        for _ in 0..256 {
            if current.is_zero() || current == head || !visited.insert(current.0) {
                break;
            }
            irps.push(current - thread_list_entry_offset);
            current = match memory.read(current) {
                Ok(next) => next,
                Err(_) => break,
            };
        }

        Some(irps)
    }

    pub fn current_windows_thread_for_processor(&self, processor: u16) -> Result<ThreadInfo> {
        let memory = self.guest.ntoskrnl.memory();
        let prcb_current_thread_offset = self
            .guest
            .ntoskrnl
            .types()
            .layout("_KPRCB")?
            .field_offset("CurrentThread")?;
        let ethread_tcb_offset = self
            .guest
            .ntoskrnl
            .types()
            .layout("_ETHREAD")?
            .field_offset("Tcb")
            .unwrap_or(0);
        let processor_block = self.guest.ntoskrnl.symbol("KiProcessorBlock")?.address();
        let prcb: VirtAddr = memory.read(processor_block + (processor as u64) * 8)?;
        if prcb.is_zero() {
            return Err(Error::DebugInfo(format!(
                "KiProcessorBlock[{}] is null",
                processor
            )));
        }

        let kthread: VirtAddr = memory.read(prcb + prcb_current_thread_offset)?;
        if kthread.is_zero() {
            return Err(Error::DebugInfo(format!(
                "KPRCB.CurrentThread for processor {} is null",
                processor
            )));
        }

        self.thread_info_from_ethread(kthread - ethread_tcb_offset)
    }

    pub fn enumerate_vad_regions_for_process_info(
        &self,
        process: &ProcessInfo,
    ) -> Result<Vec<MemoryRegionInfo>> {
        let memory = crate::memory::AddressSpace::new(&self.kvm, process.dtb);
        let types = self.guest.ntoskrnl.types_in(process.dtb);
        let eprocess_layout = self.guest.ntoskrnl.types().layout("_EPROCESS")?;
        let vad_root_base = process.eprocess_va + eprocess_layout.field_offset("VadRoot")?;
        let root = self.read_vad_root(process.dtb, vad_root_base)?;
        if root.is_zero() {
            return Ok(Vec::new());
        }

        let vad_layout = types
            .layout("_MMVAD_SHORT")
            .or_else(|_| types.layout("_MMVAD"))?;
        let vad_node_offset = vad_layout.field_offset("VadNode").unwrap_or(0);
        let node_layout = types.layout("_RTL_BALANCED_NODE")?;
        let left_offset = node_layout.field_offset("Left").unwrap_or(0);
        let right_offset = node_layout.field_offset("Right").unwrap_or(8);
        let flags_layout = types.layout("_MMVAD_FLAGS").ok();
        let modules = self.guest.process_modules(process).unwrap_or_default();

        let mut regions = Vec::new();
        let mut stack = vec![root];
        let mut visited = HashSet::new();

        while let Some(node) = stack.pop() {
            if node.is_zero() || !visited.insert(node.0) || visited.len() > 65536 {
                continue;
            }

            let left = Self::canonical_vad_link(memory.read::<VirtAddr>(node + left_offset)?);
            let right = Self::canonical_vad_link(memory.read::<VirtAddr>(node + right_offset)?);
            if !right.is_zero() {
                stack.push(right);
            }
            if !left.is_zero() {
                stack.push(left);
            }

            let vad = node - vad_node_offset;
            if let Some(region) =
                self.read_vad_region(&memory, &vad_layout, flags_layout.as_ref(), vad, &modules)
            {
                regions.push(region);
            }
        }

        regions.sort_by_key(|region| region.start.0);
        Ok(regions)
    }

    fn read_vad_root(&self, dtb: Dtb, vad_root_base: VirtAddr) -> Result<VirtAddr> {
        let memory = crate::memory::AddressSpace::new(&self.kvm, dtb);
        let types = self.guest.ntoskrnl.types_in(dtb);

        if let Ok(tree_layout) = types.layout("_RTL_AVL_TREE")
            && let Ok(root_offset) = tree_layout.field_offset("Root")
        {
            let root: VirtAddr = memory.read(vad_root_base + root_offset)?;
            return Ok(Self::canonical_vad_link(root));
        }

        let root: VirtAddr = memory.read(vad_root_base)?;
        Ok(Self::canonical_vad_link(root))
    }

    fn canonical_vad_link(link: VirtAddr) -> VirtAddr {
        VirtAddr(link.0 & !0xf)
    }

    fn read_integer_field(
        memory: &impl MemoryOps<VirtAddr>,
        layout: &TypeInfo,
        base: VirtAddr,
        field: &str,
    ) -> Option<u64> {
        let info = layout.fields.get(field)?;
        let address = base + info.offset as u64;
        match info.size {
            1 => memory.read::<u8>(address).ok().map(u64::from),
            2 => memory.read::<u16>(address).ok().map(u64::from),
            4 => memory.read::<u32>(address).ok().map(u64::from),
            8 => memory.read::<u64>(address).ok(),
            _ => None,
        }
    }

    fn bitfield_value(layout: &TypeInfo, field: &str, raw: u64) -> Option<u64> {
        let info = layout.fields.get(field)?;
        let ParsedType::Bitfield { pos, len, .. } = info.type_data else {
            return None;
        };
        let mask = if len >= 64 {
            u64::MAX
        } else {
            (1u64 << len) - 1
        };
        Some((raw >> pos) & mask)
    }

    fn vad_flags_base_offset(vad_layout: &TypeInfo) -> Option<u64> {
        vad_layout
            .field_offset("u")
            .or_else(|_| vad_layout.field_offset("u1"))
            .or_else(|_| vad_layout.field_offset("VadFlags"))
            .ok()
    }

    fn read_vad_region(
        &self,
        memory: &impl MemoryOps<VirtAddr>,
        vad_layout: &TypeInfo,
        flags_layout: Option<&TypeInfo>,
        vad: VirtAddr,
        modules: &[crate::guest::ModuleInfo],
    ) -> Option<MemoryRegionInfo> {
        let start_low = Self::read_integer_field(memory, vad_layout, vad, "StartingVpn")?;
        let end_low = Self::read_integer_field(memory, vad_layout, vad, "EndingVpn")?;
        let start_high =
            Self::read_integer_field(memory, vad_layout, vad, "StartingVpnHigh").unwrap_or(0);
        let end_high =
            Self::read_integer_field(memory, vad_layout, vad, "EndingVpnHigh").unwrap_or(0);
        let start_vpn = start_low | (start_high << 32);
        let end_vpn = end_low | (end_high << 32);
        let start = VirtAddr(start_vpn.checked_shl(12)?);
        let end = VirtAddr(end_vpn.checked_add(1)?.checked_shl(12)?);

        let flags = Self::vad_flags_base_offset(vad_layout)
            .and_then(|offset| memory.read::<u32>(vad + offset).ok())
            .map(u64::from);
        let protection = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "Protection", raw));
        let vad_type = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "VadType", raw));
        let private_memory = flags.zip(flags_layout).and_then(|(raw, layout)| {
            Self::bitfield_value(layout, "PrivateMemory", raw).map(|v| v != 0)
        });
        let commit_charge = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "CommitCharge", raw));
        let details = modules
            .iter()
            .find(|module| {
                module.base_address.0 >= start.0 && module.base_address.0 < end.0
                    || start.0 >= module.base_address.0 && start.0 < module.end_address().0
            })
            .map(|module| module.name.clone());

        Some(MemoryRegionInfo {
            start,
            end,
            protection,
            vad_type,
            private_memory,
            commit_charge,
            details,
        })
    }

    pub fn current_symbol_index(&self) -> SymbolIndex {
        self.symbols.merged_symbol_index(Some(self.current_dtb()))
    }

    pub fn current_types_index(&self) -> SymbolIndex {
        self.symbols.merged_types_index(Some(self.current_dtb()))
    }

    pub fn startup_message_data(&mut self) -> Result<DebuggerStartupMessage> {
        let build_number = self.guest.ntoskrnl.symbol("NtBuildNumber")?.read()?;
        let base_address = self.guest.ntoskrnl.base_address;
        let loaded_module_list = self.guest.ntoskrnl.symbol("PsLoadedModuleList")?.read()?;

        Ok(DebuggerStartupMessage {
            build_number: Value(build_number),
            base_address,
            loaded_module_list,
        })
    }

    pub fn pte_traverse(&self, address: VirtAddr) -> Result<DebuggerPteTraversal> {
        let process = &self.guest.ntoskrnl;
        let memory = process.memory();

        let pte_base: VirtAddr = process.symbol("MmPteBase")?.read()?;
        let pde_base = pte_base + (pte_base.0 >> 9 & 0x7FFFFFFFFF);
        let ppe_base = pde_base + (pde_base.0 >> 9 & 0x3FFFFFFF);
        let pxe_base = ppe_base + (ppe_base.0 >> 9 & 0x1FFFFF);

        let pxe_address = VirtAddr(pxe_base.0 + (((address.0 >> 39) & 0x1FF) << 3));
        let ppe_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 30) << 3) + ppe_base.0);

        let pxe_value: PageTableEntry = memory.read(pxe_address)?;
        let ppe_value: PageTableEntry = memory.read(ppe_address)?;

        let pxe = DebuggerPte {
            name: "PXE".into(),
            address: pxe_address,
            value: pxe_value,
        };
        let ppe = DebuggerPte {
            name: "PPE".into(),
            address: ppe_address,
            value: ppe_value,
        };

        if ppe_value.is_large_page() {
            return Ok(DebuggerPteTraversal {
                address,
                pxe,
                ppe,
                pde: None,
                pte: None,
            });
        }

        let pde_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 21) << 3) + pde_base.0);
        let pde_value: PageTableEntry = memory.read(pde_address)?;
        let pde = DebuggerPte {
            name: "PDE".into(),
            address: pde_address,
            value: pde_value,
        };

        if pde_value.is_large_page() {
            return Ok(DebuggerPteTraversal {
                address,
                pxe,
                ppe,
                pde: Some(pde),
                pte: None,
            });
        }

        let pte_address = VirtAddr(((address.0 & 0xFFFFFFFFFFFF) >> 12) << 3) + pte_base.0;
        let pte_value: PageTableEntry = memory.read(pte_address)?;
        let pte = DebuggerPte {
            name: "PTE".into(),
            address: pte_address,
            value: pte_value,
        };

        Ok(DebuggerPteTraversal {
            address,
            pxe,
            ppe,
            pde: Some(pde),
            pte: Some(pte),
        })
    }
}

impl fmt::Display for DebuggerPte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = format!("pfn {:<5x} {:>11}", self.value.pfn(), self.value.flags());
        write!(
            f,
            "{} at {:X}\ncontains {:016X}\n{}",
            self.name,
            self.address,
            Value(self.value.0),
            flags
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ThreadInfo;
    use crate::types::VirtAddr;

    fn sample_thread() -> ThreadInfo {
        ThreadInfo {
            ethread: VirtAddr(0xffff_8000_0000_1000),
            kthread: VirtAddr(0xffff_8000_0000_1100),
            tid: Some(0x44),
            pid: Some(0x22),
            process_name: Some("sample.exe".to_string()),
            eprocess: Some(VirtAddr(0xffff_8000_0000_2000)),
            state: Some(5),
            wait_reason: Some(6),
            priority: Some(13),
            base_priority: Some(8),
            wait_irql: Some(2),
            kernel_stack_resident: Some(true),
            start_address: Some(VirtAddr(0x7ff7_0000_1234)),
            win32_start_address: Some(VirtAddr(0x7ff7_0000_5678)),
            teb: Some(VirtAddr(0x0000_0000_0050_0000)),
            kernel_stack: Some(VirtAddr(0xffff_f000_0000_8000)),
            stack_base: Some(VirtAddr(0xffff_f000_0000_a000)),
            stack_limit: Some(VirtAddr(0xffff_f000_0000_6000)),
            trap_frame: Some(VirtAddr(0xffff_f000_0000_7000)),
            pending_irps: Some(vec![VirtAddr(0xffff_8000_0000_3000)]),
        }
    }

    #[test]
    fn thread_pseudo_registers_cover_common_windbg_names() {
        let thread = sample_thread();
        assert_eq!(
            thread.pseudo_register_value("thread"),
            Some(thread.ethread.0)
        );
        assert_eq!(
            thread.pseudo_register_value("ethread"),
            Some(thread.ethread.0)
        );
        assert_eq!(
            thread.pseudo_register_value("kthread"),
            Some(thread.kthread.0)
        );
        assert_eq!(thread.pseudo_register_value("tid"), thread.tid);
        assert_eq!(thread.pseudo_register_value("pid"), thread.pid);
        assert_eq!(
            thread.pseudo_register_value("proc"),
            thread.eprocess.map(|addr| addr.0)
        );
        assert_eq!(
            thread.pseudo_register_value("process"),
            thread.eprocess.map(|addr| addr.0)
        );
        assert_eq!(
            thread.pseudo_register_value("teb"),
            thread.teb.map(|addr| addr.0)
        );
        assert_eq!(
            thread.pseudo_register_value("priority"),
            thread.priority.map(u64::from)
        );
        assert_eq!(
            thread.pseudo_register_value("basepriority"),
            thread.base_priority.map(u64::from)
        );
        assert_eq!(
            thread.pseudo_register_value("waitirql"),
            thread.wait_irql.map(u64::from)
        );
        assert_eq!(thread.pseudo_register_value("stackresident"), Some(1));
    }

    #[test]
    fn thread_pseudo_registers_are_case_insensitive_and_optional() {
        let mut thread = sample_thread();
        assert_eq!(
            thread.pseudo_register_value("TrapFrame"),
            thread.trap_frame.map(|addr| addr.0)
        );
        thread.teb = None;
        assert_eq!(thread.pseudo_register_value("TEB"), None);
        assert_eq!(thread.pseudo_register_value("unknown"), None);
    }

    #[test]
    fn cr3_normalization_strips_pcid_and_reserved_bits() {
        assert_eq!(
            super::DebuggerContext::normalize_cr3(0xffff_8123_4567_8abc),
            0x000f_8123_4567_8000
        );
    }
}
