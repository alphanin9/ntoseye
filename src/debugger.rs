use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{Guest, ModuleSymbolLoadReport, ProcessInfo, WinObject},
    host::KvmHandle,
    symbols::{SymbolIndex, SymbolStore},
    types::{Dtb, PageTableEntry, Value, VirtAddr},
};

pub struct DebuggerContext {
    pub kvm: KvmHandle,
    pub symbols: Arc<SymbolStore>,
    pub guest: Guest,
    pub current_process: Option<WinObject>,
    pub current_process_info: Option<ProcessInfo>,
    pub registers: Option<HashMap<String, u64>>,
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

struct UnicodeStringLayout {
    length_offset: u64,
    buffer_offset: u64,
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

    pub fn current_dtb(&self) -> Dtb {
        match &self.current_process {
            Some(p) => p.dtb(),
            None => self.guest.ntoskrnl.dtb(),
        }
    }

    fn unicode_string_layout(&self) -> Result<UnicodeStringLayout> {
        let unicode = self
            .symbols
            .find_type_across_modules(self.guest.ntoskrnl.dtb(), "_UNICODE_STRING")
            .ok_or_else(|| Error::StructNotFound("_UNICODE_STRING".to_string()))?;
        Ok(UnicodeStringLayout {
            length_offset: unicode.try_get_field_offset("Length")?,
            buffer_offset: unicode.try_get_field_offset("Buffer")?,
        })
    }

    fn read_kernel_unicode_string(
        &self,
        addr: VirtAddr,
        layout: &UnicodeStringLayout,
    ) -> Result<Option<String>> {
        let memory = self.guest.ntoskrnl.memory(&self.kvm);
        let length: u16 = memory.read(addr + layout.length_offset)?;
        if length == 0 {
            return Ok(Some(String::new()));
        }
        let buffer: VirtAddr = memory.read(addr + layout.buffer_offset)?;
        if buffer.is_zero() {
            return Ok(None);
        }
        let mut bytes = vec![0u8; length as usize];
        memory.read_bytes(buffer, &mut bytes)?;
        let words = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
        Ok(Some(String::from_utf16_lossy(&words.collect::<Vec<_>>())))
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
            body_offset: header_type.try_get_field_offset("Body")?,
            info_mask_offset: header_type.try_get_field_offset("InfoMask")?,
            name_info_size: name_info_type.size as u64,
            name_offset: name_info_type.try_get_field_offset("Name")?,
        })
    }

    fn read_kernel_object_name(
        &self,
        object: VirtAddr,
        object_name: &ObjectNameLayout,
        unicode: &UnicodeStringLayout,
    ) -> Result<Option<String>> {
        let memory = self.guest.ntoskrnl.memory(&self.kvm);
        let header = object - object_name.body_offset;
        let info_mask: u8 = memory.read(header + object_name.info_mask_offset)?;
        if (info_mask & 0x02) == 0 {
            return Ok(None);
        }
        let name_info = header - object_name.name_info_size;
        self.read_kernel_unicode_string(name_info + object_name.name_offset, unicode)
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
            chain_offset: entry_type.try_get_field_offset("ChainLink")?,
            object_offset: entry_type.try_get_field_offset("Object")?,
            name_offset: entry_type.fields.get("Name").map(|f| f.offset as u64),
        })
    }

    fn enumerate_object_directory(
        &self,
        directory: VirtAddr,
        dir: &ObjectDirectoryLayout,
        object_name: &ObjectNameLayout,
        unicode: &UnicodeStringLayout,
    ) -> Result<Vec<(String, VirtAddr)>> {
        let memory = self.guest.ntoskrnl.memory(&self.kvm);
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
                        Some(offset) => self.read_kernel_unicode_string(entry + offset, unicode)?,
                        None => self.read_kernel_object_name(object, object_name, unicode)?,
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
        let memory = self.guest.ntoskrnl.memory(&self.kvm);
        let unicode = self.unicode_string_layout()?;
        let object_name = self.object_name_layout()?;
        let dir = self.object_directory_layout()?;
        let root_ptr = self
            .guest
            .ntoskrnl
            .symbol(&self.symbols, "ObpRootDirectoryObject")?
            .address();
        let root: VirtAddr = memory.read(root_ptr)?;
        let driver_dir = self
            .enumerate_object_directory(root, &dir, &object_name, &unicode)?
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Driver"))
            .map(|(_, object)| object)
            .ok_or_else(|| Error::DebugInfo("\\Driver object directory not found".to_string()))?;

        let driver_type = self
            .symbols
            .find_type_across_modules(self.guest.ntoskrnl.dtb(), "_DRIVER_OBJECT")
            .ok_or_else(|| Error::StructNotFound("_DRIVER_OBJECT".to_string()))?;
        let start_offset = driver_type.try_get_field_offset("DriverStart")?;
        let size_offset = driver_type.try_get_field_offset("DriverSize")?;
        let device_offset = driver_type.try_get_field_offset("DeviceObject")?;
        let unload_offset = driver_type.try_get_field_offset("DriverUnload")?;

        let mut drivers = Vec::new();
        for (name, object) in
            self.enumerate_object_directory(driver_dir, &dir, &object_name, &unicode)?
        {
            let driver_start: VirtAddr = memory.read(object + start_offset)?;
            let driver_size: u32 = memory.read(object + size_offset)?;
            let device_object: VirtAddr = memory.read(object + device_offset)?;
            let driver_unload: VirtAddr = memory.read(object + unload_offset)?;
            drivers.push(DriverObjectInfo {
                name: format!("\\Driver\\{name}"),
                object,
                driver_start,
                driver_size: driver_size as u64,
                device_object,
                driver_unload,
            });
        }
        Ok(drivers)
    }

    pub fn current_symbol_index(&self) -> SymbolIndex {
        self.symbols.merged_symbol_index(Some(self.current_dtb()))
    }

    pub fn current_types_index(&self) -> SymbolIndex {
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
