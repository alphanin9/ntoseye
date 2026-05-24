use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::mem;
use std::net::TcpStream;
use std::time::Duration;

use pelite::pe64::{Pe, PeView, image::IMAGE_SCN_MEM_EXECUTE};

use crate::backend::MemoryOps;
use crate::dbg_backend::{DebugBackend, StopEvent};
use crate::debugger::DebuggerContext;
use crate::error::{Error, Result};
use crate::guest::{ModuleInfo, ProcessInfo, read_pe_image};
use crate::memory::AddressSpace;
use crate::types::{Dtb, VirtAddr};

#[derive(Debug, Default, Clone)]
struct StubFeatures {
    no_ack_mode: bool,
    qxfer_features_read: bool,
}

#[derive(Debug, Default)]
enum PacketReadState {
    #[default]
    SeekingStart,
    ReadingData(Vec<u8>),
    ReadingChecksum {
        data: Vec<u8>,
        checksum: [u8; 2],
        len: usize,
    },
}

#[derive(Debug)]
enum AckResult {
    Ack,
    Nack,
    ReplyStarted,
}

#[derive(Debug)]
struct RawPacket {
    data: Vec<u8>,
    checksum: [u8; 2],
}

#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    #[allow(dead_code)]
    pub regnum: usize,
}

#[derive(Debug, Default, Clone)]
pub struct RegisterMap {
    by_name: HashMap<String, RegisterInfo>,
    ordered: Vec<RegisterInfo>,
}

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: u32,
    pub address: VirtAddr,
    pub enabled: bool,
    pub symbol: Option<String>,
    pub kind: BreakpointKind,
    pub scope: BreakpointScope,
    backend: BreakpointBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    Software,
    Hardware,
}

impl BreakpointKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Hardware => "hardware",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointScope {
    Kernel,
    Process { pid: u64, dtb: Dtb, name: String },
}

impl BreakpointScope {
    fn matches_cr3(&self, cr3: u64) -> bool {
        // Mask out the PCID (bits 0..11) and reserved/canonical bits
        // (52..63), leaving only the page-directory base physical frame.
        const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;
        match self {
            Self::Kernel => true,
            Self::Process { dtb, .. } => (cr3 & CR3_PAGE_MASK) == (*dtb & CR3_PAGE_MASK),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Kernel => "global".to_string(),
            Self::Process { pid, name, .. } => format!("{name} ({pid})"),
        }
    }
}

/// Who owns the target-side breakpoint state.
///
/// * `Software`: written via the debug transport
///   (`DbgKdWriteBreakPointApi` / gdb `Z0`). The transport tracks the
///   original byte and handles removal.
///
/// * `Hardware`: written via the debug transport's hardware execution
///   breakpoint primitive (gdb `Z1`). No guest code byte is modified, and RIP
///   is expected to report the breakpoint address directly on hit.
///
/// * `GuestMemoryPatch`: we write 0xCC ourselves through `/dev/kvm` against a
///   specific process's page table. No Kdp primitive supports per-process BPs
///   (KD's BP APIs all route through `MmDbgCopyMemory`, which uses the current
///   CR3), so this is the only way to scope a user-mode BP to one process.
///   Writing at the physical-frame level bypasses copy-on-write, so the int3
///   is visible to every process mapping that frame. `check_breakpoint_hit`'s
///   CR3 filter discards wrong-process hits, but the kernel still pays for
///   the trap.
#[derive(Debug, Clone)]
enum BreakpointBackend {
    Software,
    Hardware,
    GuestMemoryPatch { original_byte: u8 },
}

pub struct BreakpointManager {
    breakpoints: HashMap<u32, Breakpoint>,
    next_id: u32,
}

impl BreakpointManager {
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
            next_id: 0,
        }
    }

    pub fn add(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        address: VirtAddr,
        symbol: Option<String>,
    ) -> Result<u32> {
        self.add_with_kind(client, debugger, address, symbol, BreakpointKind::Software)
    }

    pub fn add_hardware(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        address: VirtAddr,
        symbol: Option<String>,
    ) -> Result<u32> {
        self.add_with_kind(client, debugger, address, symbol, BreakpointKind::Hardware)
    }

    fn add_with_kind(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        address: VirtAddr,
        symbol: Option<String>,
        kind: BreakpointKind,
    ) -> Result<u32> {
        let scope = Self::scope_for_current_context(debugger);
        if matches!(scope, BreakpointScope::Process { .. })
            && matches!(kind, BreakpointKind::Software)
            && !client.supports_process_breakpoints()
        {
            return Err(Error::NotSupported);
        }

        let id = self.next_id;
        self.next_id += 1;

        Self::validate_breakpoint_target(debugger, address)?;
        let backend = Self::install_breakpoint(client, debugger, address, &scope, kind)?;

        let bp = Breakpoint {
            id,
            address,
            enabled: true,
            symbol,
            kind,
            scope,
            backend,
        };

        self.breakpoints.insert(id, bp);
        Ok(id)
    }

    pub fn remove(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;

        if bp.enabled {
            let _ = Self::uninstall_breakpoint(client, debugger, &bp);
        }

        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }

        Ok(())
    }

    pub fn discard(&mut self, id: u32) -> Result<Breakpoint> {
        let bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;
        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }
        Ok(bp)
    }

    pub fn enable(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if bp.enabled {
            return Ok(());
        }

        Self::install_existing_breakpoint(client, debugger, bp)?;
        bp.enabled = true;
        Ok(())
    }

    pub fn disable(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }

        Self::uninstall_breakpoint(client, debugger, bp)?;
        bp.enabled = false;
        Ok(())
    }

    pub fn disable_guest_memory_patch_in_address_space(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        id: u32,
        dtb: Dtb,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }

        match bp.backend {
            BreakpointBackend::GuestMemoryPatch { original_byte } => {
                let memory = AddressSpace::new(&debugger.kvm, dtb);
                memory.write_bytes(bp.address, &[original_byte])?;
                client.note_breakpoint_uninstalled(bp.address.0);
                bp.enabled = false;
                Ok(())
            }
            BreakpointBackend::Software | BreakpointBackend::Hardware => Err(Error::Rsp(
                "cannot address-space-disable a transport-managed breakpoint".into(),
            )),
        }
    }

    pub fn list(&self) -> Vec<&Breakpoint> {
        let mut bps: Vec<_> = self.breakpoints.values().collect();
        bps.sort_by_key(|bp| bp.id);
        bps
    }

    pub fn has_enabled_breakpoints(&self) -> bool {
        self.breakpoints.values().any(|bp| bp.enabled)
    }

    // NOTE refreshing ensures local breakpoint state matches target state in case they were cleared,
    // this should fix single stepping breaking every breakpoint proceeding the step..
    pub fn refresh_enabled(
        &self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
    ) -> Result<()> {
        let mut enabled: Vec<_> = self.breakpoints.values().filter(|bp| bp.enabled).collect();
        enabled.sort_by_key(|bp| bp.id);

        for bp in enabled {
            let _ = Self::uninstall_breakpoint(client, debugger, bp);
            Self::install_existing_breakpoint(client, debugger, bp)?;
        }

        Ok(())
    }

    pub fn check_breakpoint_hit(&self, rip: u64, cr3: u64) -> BreakpointHitResult {
        for bp in self.breakpoints.values() {
            if bp.address.0 == rip && bp.enabled && bp.scope.matches_cr3(cr3) {
                return BreakpointHitResult::Hit(bp.clone());
            }
        }

        BreakpointHitResult::NotBreakpoint
    }

    /// Find a BP at `rip` regardless of its scope; "is this int3 owned by us?"
    pub fn breakpoint_id_at_address(&self, rip: u64) -> Option<u32> {
        self.breakpoints
            .values()
            .find(|bp| bp.enabled && bp.address.0 == rip)
            .map(|bp| bp.id)
    }

    pub fn int3_breakpoint_hit_at(&self, rip: u64, cr3: u64) -> bool {
        self.breakpoints.values().any(|bp| {
            bp.enabled
                && bp.address.0 == rip
                && bp.scope.matches_cr3(cr3)
                && matches!(
                    bp.backend,
                    BreakpointBackend::Software | BreakpointBackend::GuestMemoryPatch { .. }
                )
        })
    }

    fn scope_for_current_context(debugger: &DebuggerContext) -> BreakpointScope {
        match &debugger.current_process_info {
            Some(ProcessInfo { pid, name, dtb, .. }) => BreakpointScope::Process {
                pid: *pid,
                dtb: *dtb,
                name: name.clone(),
            },
            None => BreakpointScope::Kernel,
        }
    }

    fn install_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        address: VirtAddr,
        scope: &BreakpointScope,
        kind: BreakpointKind,
    ) -> Result<BreakpointBackend> {
        match (kind, scope) {
            (BreakpointKind::Software, BreakpointScope::Kernel) => {
                client.set_breakpoint(address.0)?;
                Ok(BreakpointBackend::Software)
            }
            (BreakpointKind::Software, BreakpointScope::Process { dtb, .. }) => {
                let memory = AddressSpace::new(&debugger.kvm, *dtb);
                let mut original = [0u8; 1];
                memory.read_bytes(address, &mut original)?;
                memory.write_bytes(address, &[0xcc])?;
                // The kernel doesn't know about this BP (we patched it
                // directly via /dev/kvm), so the backend needs to be told
                // separately for managed-BP bookkeeping at stop time.
                client.note_breakpoint_installed(address.0);
                Ok(BreakpointBackend::GuestMemoryPatch {
                    original_byte: original[0],
                })
            }
            (BreakpointKind::Hardware, _) => {
                client.set_hardware_breakpoint(address.0)?;
                Ok(BreakpointBackend::Hardware)
            }
        }
    }

    fn install_existing_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (BreakpointScope::Kernel, BreakpointBackend::Software) => {
                client.set_breakpoint(bp.address.0)
            }
            (_, BreakpointBackend::Hardware) => client.set_hardware_breakpoint(bp.address.0),
            (BreakpointScope::Process { dtb, .. }, BreakpointBackend::GuestMemoryPatch { .. }) => {
                let memory = AddressSpace::new(&debugger.kvm, *dtb);
                memory.write_bytes(bp.address, &[0xcc])?;
                client.note_breakpoint_installed(bp.address.0);
                Ok(())
            }
            _ => Err(Error::Rsp("breakpoint backend/scope mismatch".into())),
        }
    }

    fn uninstall_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (BreakpointScope::Kernel, BreakpointBackend::Software) => {
                client.remove_breakpoint(bp.address.0)
            }
            (_, BreakpointBackend::Hardware) => client.remove_hardware_breakpoint(bp.address.0),
            (
                BreakpointScope::Process { dtb, .. },
                BreakpointBackend::GuestMemoryPatch { original_byte },
            ) => {
                let memory = AddressSpace::new(&debugger.kvm, *dtb);
                memory.write_bytes(bp.address, &[*original_byte])?;
                client.note_breakpoint_uninstalled(bp.address.0);
                Ok(())
            }
            _ => Err(Error::Rsp("breakpoint backend/scope mismatch".into())),
        }
    }

    fn validate_breakpoint_target(debugger: &DebuggerContext, address: VirtAddr) -> Result<()> {
        let module = Self::find_kernel_module_containing_address(debugger, address);
        let memory = AddressSpace::new(&debugger.kvm, debugger.current_dtb());
        let translation = memory
            .virt_to_phys(address)?
            .ok_or(Error::BadVirtualAddress(address))?;

        if translation.nx {
            let context = module
                .as_ref()
                .map(|module| module.short_name.as_str())
                .unwrap_or("unknown");
            return Err(Error::Rsp(format!(
                "refusing breakpoint at {:#x}: target page is non-executable ({})",
                address.0, context
            )));
        }

        if let Some(module) = module {
            let image = read_pe_image(module.base_address, &memory)?;
            let view = PeView::from_bytes(&image)?;
            let rva = address.0.saturating_sub(module.base_address.0) as u32;
            let in_executable_section = view.section_headers().iter().any(|section| {
                let size = section.VirtualSize.max(section.SizeOfRawData);
                size != 0
                    && section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    && rva >= section.VirtualAddress
                    && rva < section.VirtualAddress.saturating_add(size)
            });

            if !in_executable_section {
                return Err(Error::Rsp(format!(
                    "refusing breakpoint at {:#x}: address falls in non-executable section of {}",
                    address.0, module.short_name
                )));
            }
        }

        Ok(())
    }

    fn find_kernel_module_containing_address(
        debugger: &DebuggerContext,
        address: VirtAddr,
    ) -> Option<ModuleInfo> {
        debugger
            .guest
            .get_kernel_modules(&debugger.kvm, &debugger.symbols)
            .ok()?
            .into_iter()
            .find(|module| module.contains_address(address))
    }
}

#[derive(Debug)]
pub enum BreakpointHitResult {
    /// Breakpoint hit
    Hit(Breakpoint),
    /// RIP doesn't match any breakpoint
    NotBreakpoint,
}

impl RegisterMap {
    /// Construct a `RegisterMap` from an explicit list of registers. Each
    /// register's `offset`/`size` is interpreted as an index into whatever
    /// byte buffer the backend hands back from `read_registers`. Used by
    /// backends (like KD) that build their register layout from a fixed
    /// struct rather than parsing a target description.
    pub fn from_registers(registers: Vec<RegisterInfo>) -> Self {
        let mut map = RegisterMap::default();
        for reg in registers {
            map.by_name.insert(reg.name.clone(), reg.clone());
            map.ordered.push(reg);
        }
        map
    }

    pub fn read_u64<S>(&self, name: S, data: &[u8]) -> Result<u64>
    where
        S: Into<String> + AsRef<str>,
    {
        let info = self
            .by_name
            .get(name.as_ref())
            .ok_or(Error::RegisterNotFound(name.into()))?;
        if info.offset + info.size > data.len() {
            return Err(Error::BufferNotEnough);
        }
        let slice = &data[info.offset..info.offset + info.size];

        let mut buf = [0u8; 8];
        let copy_len = slice.len().min(8);
        buf[..copy_len].copy_from_slice(&slice[..copy_len]);
        Ok(u64::from_le_bytes(buf))
    }

    pub fn write_u64<S>(&self, name: S, data: &mut [u8], value: u64) -> Result<()>
    where
        S: Into<String> + AsRef<str>,
    {
        let info = self
            .by_name
            .get(name.as_ref())
            .ok_or(Error::RegisterNotFound(name.into()))?;
        if info.offset + info.size > data.len() {
            return Err(Error::BufferNotEnough);
        }
        let bytes = value.to_le_bytes();
        let copy_len = info.size.min(bytes.len());
        data[info.offset..info.offset + copy_len].copy_from_slice(&bytes[..copy_len]);
        Ok(())
    }

    pub fn to_hashmap(&self, data: &[u8]) -> HashMap<String, u64> {
        self.ordered
            .iter()
            .filter_map(|reg| {
                if reg.offset + reg.size > data.len() {
                    return None;
                }
                let slice = &data[reg.offset..reg.offset + reg.size];
                let mut buf = [0u8; 8];
                let copy_len = slice.len().min(8);
                buf[..copy_len].copy_from_slice(&slice[..copy_len]);
                Some((reg.name.clone(), u64::from_le_bytes(buf)))
            })
            .collect()
    }

    // pub fn is_empty(&self) -> bool {
    //     self.ordered.is_empty()
    // }

    fn parse_target_xml(xml: &str) -> Self {
        let mut map = RegisterMap::default();
        let mut current_offset: usize = 0;
        let mut next_regnum: Option<usize> = None;

        let xml = Self::strip_xml_comments(xml);

        let mut cursor = 0;
        while let Some(start_offset) = xml[cursor..].find("<reg") {
            let start = cursor + start_offset;
            let rest = &xml[start + 4..];
            if !matches!(rest.as_bytes().first(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
                cursor = start + 4;
                continue;
            }

            let Some(end_offset) = xml[start..].find('>') else {
                break;
            };

            let end = start + end_offset + 1;
            let element = &xml[start..end];
            let name = Self::extract_attr(element, "name");
            let bitsize = Self::extract_attr(element, "bitsize");
            let explicit_regnum = Self::extract_attr(element, "regnum");

            if let (Some(name), Some(bitsize)) = (name, bitsize) {
                let size_bits: usize = bitsize.parse().unwrap_or(0);
                let size_bytes = size_bits / 8;

                let regnum: usize =
                    if let Some(explicit) = explicit_regnum.and_then(|s| s.parse().ok()) {
                        next_regnum = Some(explicit + 1);
                        explicit
                    } else {
                        let num = next_regnum.unwrap_or(0);
                        next_regnum = Some(num + 1);
                        num
                    };

                let reg = RegisterInfo {
                    name: name.to_string(),
                    offset: current_offset,
                    size: size_bytes,
                    regnum,
                };

                current_offset += size_bytes;
                map.by_name.insert(reg.name.clone(), reg.clone());
                map.ordered.push(reg);
            }

            cursor = end;
        }

        map
    }

    fn strip_xml_comments(xml: &str) -> String {
        let mut result = xml.to_string();
        while let Some(start) = result.find("<!--") {
            if let Some(end_offset) = result[start..].find("-->") {
                let end = start + end_offset + 3; // +3 for "-->"
                result = format!("{}{}", &result[..start], &result[end..]);
            } else {
                break;
            }
        }
        result
    }

    fn extract_attr<'a>(element: &'a str, attr: &str) -> Option<&'a str> {
        let pattern = format!("{}=\"", attr);
        let start = element.find(&pattern)?;
        let value_start = start + pattern.len();
        let rest = &element[value_start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }
}

impl StubFeatures {
    fn parse(response: &str) -> Self {
        let mut features = StubFeatures::default();

        for item in response.split(';') {
            match item {
                "QStartNoAckMode+" => features.no_ack_mode = true,
                "qXfer:features:read+" => features.qxfer_features_read = true,
                _ => {}
            }
        }

        features
    }
}

pub struct GdbClient {
    stream: TcpStream,
    features: StubFeatures,
    rx_state: PacketReadState,
    no_ack_mode: bool,
    register_map: RegisterMap,
    is_running: bool,
}

impl GdbClient {
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;

        let mut client = GdbClient {
            stream,
            features: StubFeatures::default(),
            rx_state: PacketReadState::default(),
            no_ack_mode: false,
            register_map: RegisterMap::default(),
            is_running: false, // NOTE if the user toys with VM via GUI, this value goes bad
        };

        client.force_stop_and_resync()?;

        let supported = client.send_packet(
            "qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;vContSupported+",
        )?;
        client.features = StubFeatures::parse(&supported);

        if client.features.no_ack_mode {
            let _ = client.enable_no_ack_mode();
        }

        let _ = client.send_packet("?")?;

        client.register_map = client.fetch_register_map()?;

        Ok(client)
    }

    fn force_stop_and_resync(&mut self) -> Result<()> {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))?;
        self.rx_state = PacketReadState::default();

        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        while self.read_response_packet().is_ok() {}

        self.stream.set_read_timeout(None)?;
        self.rx_state = PacketReadState::default();

        self.is_running = false;

        Ok(())
    }

    pub fn send_packet(&mut self, data: &str) -> Result<String> {
        let packet = Self::encode_packet(data);
        self.send_raw_command(&packet)?;
        self.read_response_packet()
    }

    fn enable_no_ack_mode(&mut self) -> Result<()> {
        let response = self.send_packet("QStartNoAckMode")?;
        if response == "OK" {
            self.no_ack_mode = true;
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }

    pub fn query_halt_reason(&mut self) -> Result<String> {
        self.send_packet("?")
    }

    fn encode_packet(data: &str) -> Vec<u8> {
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        format!("${}#{:02x}", data, checksum).into_bytes()
    }

    fn send_raw_command(&mut self, packet: &[u8]) -> Result<()> {
        loop {
            self.stream.write_all(packet)?;
            self.stream.flush()?;

            if self.no_ack_mode {
                return Ok(());
            }

            match self.wait_for_ack()? {
                AckResult::Ack => return Ok(()),
                AckResult::Nack => continue,
                AckResult::ReplyStarted => return Ok(()),
            }
        }
    }

    fn wait_for_ack(&mut self) -> Result<AckResult> {
        let mut buf = [0u8; 1];

        loop {
            self.stream.read_exact(&mut buf)?;
            match buf[0] {
                b'+' => return Ok(AckResult::Ack),
                b'-' => return Ok(AckResult::Nack),
                b'$' => {
                    self.rx_state = PacketReadState::ReadingData(Vec::new());
                    return Ok(AckResult::ReplyStarted);
                }
                _ => continue,
            }
        }
    }

    fn read_response_packet(&mut self) -> Result<String> {
        loop {
            let packet = self.read_raw_packet()?;
            let expected = Self::parse_checksum(packet.checksum)?;
            let actual = packet
                .data
                .iter()
                .fold(0u8, |acc, byte| acc.wrapping_add(*byte));

            if actual != expected {
                if self.no_ack_mode {
                    return Err(Error::Rsp(format!(
                        "bad checksum from stub: expected {:02x}, got {:02x}",
                        expected, actual
                    )));
                }

                self.stream.write_all(b"-")?;
                self.stream.flush()?;
                continue;
            }

            if !self.no_ack_mode {
                self.stream.write_all(b"+")?;
                self.stream.flush()?;
            }

            let decoded = Self::decode_packet_data(&packet.data)?;
            let response = String::from_utf8(decoded)
                .map_err(|e| Error::Rsp(format!("non-utf8 packet payload: {}", e)))?;
            return Ok(response);
        }
    }

    fn read_raw_packet(&mut self) -> Result<RawPacket> {
        loop {
            let mut buf = [0u8; 1];
            self.stream.read_exact(&mut buf)?;
            if let Some(packet) = self.consume_packet_byte(buf[0])? {
                return Ok(packet);
            }
        }
    }

    fn consume_packet_byte(&mut self, byte: u8) -> Result<Option<RawPacket>> {
        match &mut self.rx_state {
            PacketReadState::SeekingStart => {
                if byte == b'$' {
                    self.rx_state = PacketReadState::ReadingData(Vec::new());
                }
                Ok(None)
            }
            PacketReadState::ReadingData(data) => {
                if byte == b'#' {
                    let raw_data = mem::take(data);
                    self.rx_state = PacketReadState::ReadingChecksum {
                        data: raw_data,
                        checksum: [0u8; 2],
                        len: 0,
                    };
                } else {
                    data.push(byte);
                }
                Ok(None)
            }
            PacketReadState::ReadingChecksum {
                data,
                checksum,
                len,
            } => {
                checksum[*len] = byte;
                *len += 1;

                if *len == 2 {
                    let raw_data = mem::take(data);
                    let raw_checksum = *checksum;
                    self.rx_state = PacketReadState::SeekingStart;
                    return Ok(Some(RawPacket {
                        data: raw_data,
                        checksum: raw_checksum,
                    }));
                }

                Ok(None)
            }
        }
    }

    fn parse_checksum(checksum: [u8; 2]) -> Result<u8> {
        let checksum_str = std::str::from_utf8(&checksum)
            .map_err(|e| Error::Rsp(format!("invalid checksum encoding: {}", e)))?;
        u8::from_str_radix(checksum_str, 16)
            .map_err(|e| Error::Rsp(format!("invalid checksum value '{}': {}", checksum_str, e)))
    }

    fn decode_packet_data(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoded = Vec::with_capacity(data.len());
        let mut index = 0;

        while index < data.len() {
            match data[index] {
                b'}' => {
                    index += 1;
                    if index >= data.len() {
                        return Err(Error::Rsp("truncated escaped packet data".into()));
                    }
                    decoded.push(data[index] ^ 0x20);
                    index += 1;
                }
                b'*' => {
                    let Some(last) = decoded.last().copied() else {
                        return Err(Error::Rsp("invalid run-length packet data".into()));
                    };
                    index += 1;
                    if index >= data.len() {
                        return Err(Error::Rsp("truncated run-length packet data".into()));
                    }
                    let repeat_count = data[index]
                        .checked_sub(29)
                        .ok_or_else(|| Error::Rsp("invalid run-length repeat count".into()))?;
                    decoded.extend(std::iter::repeat_n(last, repeat_count as usize));
                    index += 1;
                }
                byte => {
                    decoded.push(byte);
                    index += 1;
                }
            }
        }

        Ok(decoded)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        let response = self.send_packet(&format!("Z0,{:x},1", addr))?;
        if response == "OK" {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to set breakpoint at {:#x}: {}",
                addr, response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        let response = self.send_packet(&format!("z0,{:x},1", addr))?;
        if response == "OK" {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to remove breakpoint at {:#x}: {}",
                addr, response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    fn set_hardware_breakpoint(&mut self, addr: u64) -> Result<()> {
        let response = self.send_packet(&format!("Z1,{:x},1", addr))?;
        if response == "OK" {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to set hardware breakpoint at {:#x}: {}",
                addr, response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    fn remove_hardware_breakpoint(&mut self, addr: u64) -> Result<()> {
        let response = self.send_packet(&format!("z1,{:x},1", addr))?;
        if response == "OK" {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to remove hardware breakpoint at {:#x}: {}",
                addr, response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        let response = self.send_packet("g")?;

        if response.starts_with('E') {
            return Err(Error::Rsp(format!(
                "failed to read registers: {}",
                response
            )));
        }

        let bytes = hex::decode(&response)?;
        Ok(bytes)
    }

    #[allow(dead_code)]
    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        let hex_data: String = data.iter().map(|b| format!("{:02x}", b)).collect();

        let response = self.send_packet(&format!("G{}", hex_data))?;

        if response == "OK" {
            Ok(())
        } else {
            Err(Error::Rsp(format!(
                "failed to write registers: {}",
                response
            )))
        }
    }

    fn send_command_no_reply(&mut self, data: &str) -> Result<()> {
        let packet = Self::encode_packet(data);
        self.send_raw_command(&packet)
    }

    fn monitor_command(&mut self, command: &str) -> Result<String> {
        let encoded_command = hex::encode(command.as_bytes());
        let packet = Self::encode_packet(&format!("qRcmd,{}", encoded_command));
        self.send_raw_command(&packet)?;

        let mut output = String::new();
        loop {
            let response = self.read_response_packet()?;
            if response == "OK" {
                return Ok(output);
            }
            if response.is_empty() {
                return Err(Error::NotSupported);
            }
            if let Some(hex_output) = response.strip_prefix('O') {
                let bytes = hex::decode(hex_output)?;
                output.push_str(&String::from_utf8_lossy(&bytes));
                continue;
            }
            if response.starts_with('E') {
                return Err(Error::Rsp(format!(
                    "monitor command failed for '{}': {}",
                    command, response
                )));
            }
            return Err(Error::Rsp(format!(
                "unexpected qRcmd response for '{}': {}",
                command, response
            )));
        }
    }

    fn continue_execution(&mut self) -> Result<()> {
        // set continue thread to -1 (all threads)
        let _ = self.send_packet("Hc-1")?;
        self.send_command_no_reply("c")?;
        self.is_running = true;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn continue_at(&mut self, addr: u64) -> Result<()> {
        self.send_command_no_reply(&format!("c{:x}", addr))?;
        self.is_running = true;
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        self.send_command_no_reply("s")?;
        self.is_running = true;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn step_at(&mut self, addr: u64) -> Result<()> {
        self.send_command_no_reply(&format!("s{:x}", addr))?;
        self.is_running = true;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn step_and_wait(&mut self) -> Result<String> {
        self.step()?;
        self.wait_for_stop()
    }

    fn wait_for_stop(&mut self) -> Result<String> {
        if !self.is_running {
            return self.query_halt_reason();
        }

        let response = self.read_stop_reply()?;
        self.is_running = false;
        Ok(response)
    }

    fn try_wait_for_stop(&mut self) -> Result<Option<String>> {
        if !self.is_running {
            return Ok(Some(self.query_halt_reason()?));
        }

        match self.read_stop_reply() {
            Ok(response) => {
                self.is_running = false;
                Ok(Some(response))
            }
            Err(Error::Io(ref e))
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn read_stop_reply(&mut self) -> Result<String> {
        loop {
            let response = self.read_response_packet()?;
            match response.as_bytes().first().copied() {
                Some(b'S' | b'T' | b'W' | b'X' | b'N') => return Ok(response),
                Some(b'O') => continue,
                Some(b'F') => {
                    return Err(Error::Rsp(
                        "remote file I/O packets are unsupported while waiting for stop".into(),
                    ));
                }
                Some(b'E') => {
                    return Err(Error::Rsp(format!(
                        "run-control command failed: {}",
                        response
                    )));
                }
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected packet while waiting for stop: {}",
                        response
                    )));
                }
            }
        }
    }

    fn stop_reply_summary(response: &str) -> Option<String> {
        let first = response.as_bytes().first().copied()?;
        match first {
            b'W' => Some(format!(
                "gdbstub target exited with status 0x{}",
                response.get(1..).unwrap_or("")
            )),
            b'X' => Some(format!(
                "gdbstub target terminated with signal 0x{}",
                response.get(1..).unwrap_or("")
            )),
            b'N' => Some("gdbstub reports no resumed threads".to_string()),
            b'S' => Some(format!(
                "gdbstub stop signal 0x{}",
                response.get(1..).unwrap_or("")
            )),
            b'T' => {
                let signal = response.get(1..3).unwrap_or("");
                Some(format!("gdbstub stop signal 0x{signal}"))
            }
            _ => None,
        }
    }

    fn stop_reply_is_terminal(response: &str) -> bool {
        matches!(
            response.as_bytes().first().copied(),
            Some(b'W' | b'X' | b'N')
        )
    }

    fn interrupt(&mut self) -> Result<()> {
        if !self.is_running {
            return Ok(());
        }

        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        let _ = self.read_stop_reply()?;

        self.is_running = false;

        Ok(())
    }

    fn get_thread_list(&mut self) -> Result<Vec<String>> {
        let mut threads = Vec::new();
        let mut response = self.send_packet("qfThreadInfo")?;

        loop {
            if response == "l" {
                break;
            }

            if let Some(list) = response.strip_prefix('m') {
                for id in list.split(',') {
                    if !id.is_empty() {
                        threads.push(id.to_string());
                    }
                }
            } else if response.starts_with('E') {
                return Err(Error::Rsp(format!(
                    "failed to enumerate threads: {}",
                    response
                )));
            } else {
                return Err(Error::Rsp(format!(
                    "unexpected qThreadInfo response: {}",
                    response
                )));
            }

            response = self.send_packet("qsThreadInfo")?;
        }

        Ok(threads)
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        let resp_g = self.send_packet(&format!("Hg{}", thread_id))?;
        if resp_g != "OK" {
            return Err(Error::Rsp(format!(
                "failed to set general thread: {}",
                resp_g
            )));
        }

        let resp_c = self.send_packet(&format!("Hc{}", thread_id))?;
        if resp_c != "OK" {
            return Err(Error::Rsp(format!(
                "failed to set control thread: {}",
                resp_c
            )));
        }

        Ok(())
    }

    fn get_stopped_thread_id(&mut self) -> Result<String> {
        let response = self.send_packet("?")?;
        if let Some(thread_id) = Self::parse_stop_reply_thread_id(&response) {
            return Ok(thread_id);
        }

        let response = self.send_packet("qC")?;
        if let Some(thread_id) = response.strip_prefix("QC") {
            return Ok(thread_id.to_string());
        }

        Err(Error::Rsp(
            "could not determine thread from stop reply".into(),
        ))
    }

    fn parse_stop_reply_thread_id(response: &str) -> Option<String> {
        if !response.starts_with('T') {
            return None;
        }

        let start = response.find("thread:")?;
        let remainder = &response[start + 7..];
        let end = remainder.find(';').unwrap_or(remainder.len());
        Some(remainder[..end].to_string())
    }

    fn fetch_register_map(&mut self) -> Result<RegisterMap> {
        if !self.features.qxfer_features_read {
            return Err(Error::NotSupported);
        }

        let mut xml = String::new();
        let mut offset = 0;

        loop {
            let query = format!("qXfer:features:read:target.xml:{:x},fff", offset);
            let response = self.send_packet(&query)?;

            if response.is_empty() {
                return Err(Error::NotSupported);
            }

            let (marker, data) = response.split_at(1);
            xml.push_str(data);
            offset += data.len();

            match marker {
                "l" => break,    // last chunk
                "m" => continue, // more data
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected qXfer response: {}",
                        response
                    )));
                }
            }
        }

        let full_xml = self.resolve_xml_includes(&xml)?;

        Ok(RegisterMap::parse_target_xml(&full_xml))
    }

    fn resolve_xml_includes(&mut self, xml: &str) -> Result<String> {
        let mut result = xml.to_string();

        while let Some(start) = result.find("<xi:include") {
            let end = match result[start..].find("/>") {
                Some(e) => start + e + 2,
                None => break,
            };

            let element = &result[start..end];
            let href = RegisterMap::extract_attr(element, "href");

            if let Some(filename) = href {
                // fetch the included file
                let included_xml = self.fetch_feature_file(filename)?;
                result = format!("{}{}{}", &result[..start], included_xml, &result[end..]);
            } else {
                // no href, just remove the include element
                result = format!("{}{}", &result[..start], &result[end..]);
            }
        }

        Ok(result)
    }

    fn fetch_feature_file(&mut self, filename: &str) -> Result<String> {
        let mut xml = String::new();
        let mut offset = 0;

        loop {
            let query = format!("qXfer:features:read:{}:{:x},fff", filename, offset);
            let response = self.send_packet(&query)?;

            if response.is_empty() {
                return Err(Error::NotSupported);
            }

            let (marker, data) = response.split_at(1);
            xml.push_str(data);
            offset += data.len();

            match marker {
                "l" => break,
                "m" => continue,
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected qXfer response for {}: {}",
                        filename, response
                    )));
                }
            }
        }

        Ok(xml)
    }
}

impl DebugBackend for GdbClient {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        GdbClient::read_registers(self)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        GdbClient::write_registers(self, data)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        GdbClient::set_breakpoint(self, addr)
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        GdbClient::remove_breakpoint(self, addr)
    }

    fn set_hardware_breakpoint(&mut self, addr: u64) -> Result<()> {
        GdbClient::set_hardware_breakpoint(self, addr)
    }

    fn remove_hardware_breakpoint(&mut self, addr: u64) -> Result<()> {
        GdbClient::remove_hardware_breakpoint(self, addr)
    }

    fn continue_execution(&mut self) -> Result<()> {
        GdbClient::continue_execution(self)
    }

    fn step(&mut self) -> Result<()> {
        GdbClient::step(self)
    }

    fn interrupt(&mut self) -> Result<()> {
        GdbClient::interrupt(self)
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        let response = GdbClient::wait_for_stop(self)?;
        Ok(StopEvent {
            thread_id: Self::parse_stop_reply_thread_id(&response),
            summary: Self::stop_reply_summary(&response),
            target_exited: Self::stop_reply_is_terminal(&response),
        })
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        self.stream.set_read_timeout(Some(timeout))?;
        let result = GdbClient::try_wait_for_stop(self);
        // restore blocking mode regardless of outcome
        let _ = self.stream.set_read_timeout(None);
        Ok(result?.map(|response| StopEvent {
            thread_id: Self::parse_stop_reply_thread_id(&response),
            summary: Self::stop_reply_summary(&response),
            target_exited: Self::stop_reply_is_terminal(&response),
        }))
    }

    fn get_thread_list(&mut self) -> Result<Vec<String>> {
        GdbClient::get_thread_list(self)
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        GdbClient::set_current_thread(self, thread_id)
    }

    fn get_stopped_thread_id(&mut self) -> Result<String> {
        GdbClient::get_stopped_thread_id(self)
    }

    fn monitor_command(&mut self, command: &str) -> Result<String> {
        GdbClient::monitor_command(self, command)
    }

    fn is_running(&self) -> bool {
        self.is_running
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Breakpoint, BreakpointBackend, BreakpointHitResult, BreakpointKind, BreakpointManager,
        BreakpointScope, GdbClient, RegisterMap, StubFeatures,
    };
    use crate::types::VirtAddr;

    #[test]
    fn decodes_escaped_and_run_length_packet_data() {
        let decoded = GdbClient::decode_packet_data(&[b'A', b'*', b' ', b'}', b'\x03']).unwrap();
        assert_eq!(decoded, b"AAAA#");
    }

    #[test]
    fn rejects_truncated_escape_sequences() {
        let err = GdbClient::decode_packet_data(b"}").unwrap_err();
        assert!(err.to_string().contains("truncated escaped packet data"));
    }

    #[test]
    fn parses_target_xml_without_line_based_reg_tags() {
        let xml = r#"
            <target>
              <feature name="org.gnu.gdb.i386.core">
                <reg
                    name="rax"
                    bitsize="64"
                    regnum="0"/>
                <reg name="rip" bitsize="64"/>
              </feature>
            </target>
        "#;

        let map = RegisterMap::parse_target_xml(xml);
        let regs = map.to_hashmap(&[1u8; 16]);

        assert_eq!(
            map.read_u64("rax", &[1u8; 16]).unwrap(),
            0x0101_0101_0101_0101
        );
        assert_eq!(regs.get("rip"), Some(&0x0101_0101_0101_0101));
    }

    #[test]
    fn parses_stub_features_from_qsupported() {
        let features = StubFeatures::parse(
            "PacketSize=1000;QStartNoAckMode+;multiprocess+;qXfer:features:read+",
        );
        assert!(features.no_ack_mode);
        assert!(features.qxfer_features_read);
    }

    #[test]
    fn parses_thread_id_from_stop_reply() {
        let thread_id = GdbClient::parse_stop_reply_thread_id("T05thread:p1.2;core:1;");
        assert_eq!(thread_id.as_deref(), Some("p1.2"));
    }

    #[test]
    fn ignores_non_stop_reply_when_parsing_thread_id() {
        assert!(GdbClient::parse_stop_reply_thread_id("S05").is_none());
    }

    #[test]
    fn detects_breakpoint_hit_at_exact_rip() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x1000),
                enabled: true,
                symbol: None,
                kind: BreakpointKind::Software,
                scope: BreakpointScope::Kernel,
                backend: BreakpointBackend::Software,
            },
        );

        match manager.check_breakpoint_hit(0x1000, 0) {
            BreakpointHitResult::Hit(bp) => assert_eq!(bp.id, 0),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn process_breakpoint_hit_requires_matching_cr3() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x7ff7_1234_1000),
                enabled: true,
                symbol: None,
                kind: BreakpointKind::Software,
                scope: BreakpointScope::Process {
                    pid: 42,
                    dtb: 0x1234_5000,
                    name: "user.exe".to_string(),
                },
                backend: BreakpointBackend::GuestMemoryPatch {
                    original_byte: 0x90,
                },
            },
        );

        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5000),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5fff),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x9999_9000),
            BreakpointHitResult::NotBreakpoint
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_4000),
            BreakpointHitResult::NotBreakpoint
        ));
    }

    #[test]
    fn hardware_breakpoint_hits_exact_rip_but_is_not_int3_rewind_candidate() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x2000),
                enabled: true,
                symbol: None,
                kind: BreakpointKind::Hardware,
                scope: BreakpointScope::Kernel,
                backend: BreakpointBackend::Hardware,
            },
        );

        assert!(matches!(
            manager.check_breakpoint_hit(0x2000, 0),
            BreakpointHitResult::Hit(_)
        ));
        assert!(!manager.int3_breakpoint_hit_at(0x2000, 0));
    }
}
