use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{Guest, ModuleSymbolLoadReport, ProcessInfo, WinObject},
    host::KvmHandle,
    symbols::SymbolStore,
    types::{PageTableEntry, Value, VirtAddr},
};

pub struct DebuggerContext {
    pub kvm: KvmHandle,
    pub symbols: Arc<SymbolStore>,
    pub guest: Guest,
    pub current_process: Option<WinObject>,
    pub current_process_info: Option<ProcessInfo>,
    pub registers: Option<HashMap<String, u64>>,
}

pub struct DebuggerStartupMessage {
    pub build_number: Value<u16>,
    pub base_address: VirtAddr,
    pub loaded_module_list: VirtAddr,
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
        let kvm = KvmHandle::new()?;
        let symbols = SymbolStore::new();
        let guest = Guest::new(&kvm, &symbols)?;

        // load symbols for all kernel modules (ntoskrnl is already loaded, this adds others)
        let _ = guest.load_all_kernel_module_symbols(&kvm, &symbols);

        let symbols = Arc::new(symbols);

        Ok(Self {
            kvm,
            symbols,
            guest,
            current_process: None,
            current_process_info: None,
            registers: None,
        })
    }

    pub fn get_current_process(&self) -> &WinObject {
        match &self.current_process {
            Some(p) => p,
            None => &self.guest.ntoskrnl,
        }
    }

    pub fn attach(&mut self, pid: u64) -> Result<AttachReport> {
        let processes = self.guest.enumerate_processes(&self.kvm, &self.symbols)?;
        let process_info = processes
            .iter()
            .find(|p| p.pid == pid)
            .ok_or(Error::ProcessNotFound(pid))?
            .clone();

        let name = process_info.name.clone();

        let symbol_report =
            self.guest
                .load_all_process_module_symbols(&self.kvm, &self.symbols, &process_info);

        let winobj =
            self.guest
                .winobj_from_process_info(&self.kvm, &self.symbols, &process_info)?;

        self.current_process = Some(winobj);
        self.current_process_info = Some(process_info);
        Ok(AttachReport {
            name,
            symbol_report: symbol_report?,
        })
    }

    pub fn detach(&mut self) {
        self.current_process = None;
        self.current_process_info = None;
    }

    pub fn current_dtb(&self) -> crate::types::Dtb {
        match &self.current_process {
            Some(p) => p.dtb(),
            None => self.guest.ntoskrnl.dtb(),
        }
    }

    pub fn current_symbol_index(&self) -> crate::symbols::SymbolIndex {
        self.symbols.merged_symbol_index(Some(self.current_dtb()))
    }

    pub fn current_types_index(&self) -> crate::symbols::SymbolIndex {
        self.symbols.merged_types_index(Some(self.current_dtb()))
    }

    pub fn get_startup_message_data(&mut self) -> Result<DebuggerStartupMessage> {
        let build_number = self
            .guest
            .ntoskrnl
            .symbol(&self.symbols, "NtBuildNumber")?
            .read(&self.kvm)?;
        let base_address = self.guest.ntoskrnl.base_address;
        let loaded_module_list = self
            .guest
            .ntoskrnl
            .symbol(&self.symbols, "PsLoadedModuleList")?
            .read(&self.kvm)?;

        Ok(DebuggerStartupMessage {
            build_number: Value(build_number),
            base_address,
            loaded_module_list,
        })
    }

    pub fn pte_traverse(&self, address: VirtAddr) -> Result<DebuggerPteTraversal> {
        let process = &self.guest.ntoskrnl;
        let memory = process.memory(&self.kvm);

        let pte_base: VirtAddr = process
            .symbol(&self.symbols, "MmPteBase")?
            .read(&self.kvm)?;
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
