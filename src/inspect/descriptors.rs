//! Shared IDT/GDT/TSS descriptor-table parsing.
//!
//! These helpers extract architectural descriptor tables from guest memory and
//! the QEMU monitor register dump. They return plain structs; the REPL renders
//! them as tables and the agent serializes them as JSON.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::memory::AddressSpace;
use crate::target::Target;
use crate::types::VirtAddr;

const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[derive(Debug, Clone, Copy)]
pub struct Idtr {
    pub base: VirtAddr,
    pub limit: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct Gdtr {
    pub base: VirtAddr,
    pub limit: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct IdtEntry {
    pub vector: usize,
    pub handler: VirtAddr,
    pub selector: u16,
    pub ist: u8,
    pub gate_type: u8,
    pub dpl: u8,
    pub present: bool,
}

#[derive(Debug, Clone)]
pub struct GdtEntry {
    pub index: usize,
    pub selector: u16,
    pub base: u64,
    pub effective_limit: u64,
    pub ty: u8,
    pub system: bool,
    pub dpl: u8,
    pub present: bool,
    pub long_mode: bool,
    pub default_big: bool,
    pub granularity: bool,
    pub avl: bool,
    pub raw: u128,
}

#[derive(Debug, Clone)]
pub struct TssStackBases {
    pub rsp: [VirtAddr; 3],
    pub ist: [VirtAddr; 7],
    pub io_map_base: u16,
}

fn parse_hex_u64(token: &str) -> Option<u64> {
    let stripped = token
        .trim_matches(|c: char| c == ',' || c == ';')
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u64::from_str_radix(stripped, 16).ok()
}

pub fn parse_idtr_from_qemu_registers(output: &str) -> Option<Idtr> {
    for line in output.lines() {
        let Some((_, rest)) = line.split_once("IDT=") else {
            continue;
        };
        let mut values = rest.split_whitespace().filter_map(parse_hex_u64);
        return Some(Idtr {
            base: VirtAddr(values.next()?),
            limit: values.next()? as u16,
        });
    }
    None
}

pub fn parse_gdtr_from_qemu_registers(output: &str) -> Option<Gdtr> {
    for line in output.lines() {
        let Some((_, rest)) = line.split_once("GDT=") else {
            continue;
        };
        let mut values = rest.split_whitespace().filter_map(parse_hex_u64);
        return Some(Gdtr {
            base: VirtAddr(values.next()?),
            limit: values.next()? as u16,
        });
    }
    None
}

pub fn parse_tr_selector_from_qemu_registers(output: &str) -> Option<u16> {
    for line in output.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("TR") else {
            continue;
        };
        let Some((_, value_text)) = rest.split_once('=') else {
            continue;
        };
        return Some(
            value_text
                .split_whitespace()
                .next()
                .and_then(parse_hex_u64)? as u16,
        );
    }
    None
}

pub fn parse_selector_arg(arg: &str) -> Option<u16> {
    let stripped = arg.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(stripped, 16)
        .or_else(|_| arg.parse::<u16>())
        .ok()
}

pub fn parse_idt_entry(vector: usize, bytes: &[u8]) -> IdtEntry {
    let offset_low = u16::from_le_bytes([bytes[0], bytes[1]]) as u64;
    let selector = u16::from_le_bytes([bytes[2], bytes[3]]);
    let ist = bytes[4] & 0x07;
    let attr = bytes[5];
    let offset_mid = u16::from_le_bytes([bytes[6], bytes[7]]) as u64;
    let offset_high = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as u64;

    IdtEntry {
        vector,
        handler: VirtAddr(offset_low | (offset_mid << 16) | (offset_high << 32)),
        selector,
        ist,
        gate_type: attr & 0x1f,
        dpl: (attr >> 5) & 0x03,
        present: attr & 0x80 != 0,
    }
}

pub fn read_idt_entries(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    idtr: Idtr,
    max_entries: Option<usize>,
) -> Result<Vec<IdtEntry>> {
    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    let idt_size = idtr.limit as usize + 1;
    let entry_count = max_entries.map_or(idt_size / 16, |count| count.min(idt_size / 16));
    if entry_count == 0 {
        return Err(Error::InvalidRange);
    }
    let mut data = vec![0u8; entry_count * 16];
    AddressSpace::new(&debugger.kvm, cr3).read_bytes(idtr.base, &mut data)?;
    Ok(data
        .chunks_exact(16)
        .enumerate()
        .map(|(vector, bytes)| parse_idt_entry(vector, bytes))
        .collect())
}

pub fn parse_gdt_entry(index: usize, data: &[u8]) -> GdtEntry {
    let lo = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let ty = ((lo >> 40) & 0x0f) as u8;
    let system = ((lo >> 44) & 1) == 0;
    let dpl = ((lo >> 45) & 0x03) as u8;
    let present = ((lo >> 47) & 1) != 0;
    let long_mode = ((lo >> 53) & 1) != 0;
    let default_big = ((lo >> 54) & 1) != 0;
    let granularity = ((lo >> 55) & 1) != 0;
    let avl = ((lo >> 52) & 1) != 0;
    let limit = ((lo & 0xffff) | (((lo >> 48) & 0x0f) << 16)) as u32;
    let effective_limit = if granularity {
        ((limit as u64) << 12) | 0xfff
    } else {
        limit as u64
    };
    let base_low = ((lo >> 16) & 0x00ff_ffff) | (((lo >> 56) & 0xff) << 24);
    let base = if system && data.len() >= 16 {
        let hi = u64::from_le_bytes(data[8..16].try_into().unwrap()) & 0xffff_ffff;
        base_low | (hi << 32)
    } else {
        base_low
    };
    let raw = if data.len() >= 16 {
        u128::from_le_bytes(data[0..16].try_into().unwrap())
    } else {
        lo as u128
    };
    GdtEntry {
        index,
        selector: (index * 8) as u16,
        base,
        effective_limit,
        ty,
        system,
        dpl,
        present,
        long_mode,
        default_big,
        granularity,
        avl,
        raw,
    }
}

pub fn read_gdt_entries(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    max_entries: Option<usize>,
) -> Result<Vec<GdtEntry>> {
    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    let gdt_size = gdtr.limit as usize + 1;
    let entry_count = max_entries.map_or(gdt_size / 8, |count| count.min(gdt_size / 8));
    if entry_count == 0 {
        return Err(Error::InvalidRange);
    }
    let read_len = gdt_size.min(entry_count * 8 + 8);
    let mut data = vec![0u8; read_len];
    AddressSpace::new(&debugger.kvm, cr3).read_bytes(gdtr.base, &mut data)?;
    let mut entries = Vec::new();
    for index in 0..entry_count {
        let offset = index * 8;
        let Some(first) = data.get(offset..offset + 8) else {
            break;
        };
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(first);
        let lo = u64::from_le_bytes(first.try_into().unwrap());
        let system = ((lo >> 44) & 1) == 0;
        if system
            && matches!(((lo >> 40) & 0x0f) as u8, 0x2 | 0x9 | 0xb)
            && let Some(second) = data.get(offset + 8..offset + 16)
        {
            bytes[8..16].copy_from_slice(second);
        }
        entries.push(parse_gdt_entry(index, &bytes));
    }
    Ok(entries)
}

pub fn read_gdt_entry(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    selector: u16,
) -> Result<GdtEntry> {
    let index = (selector >> 3) as usize;
    read_gdt_entries(debugger, register_map, regs, gdtr, Some(index + 1))?
        .into_iter()
        .find(|entry| entry.index == index)
        .ok_or(Error::InvalidRange)
}

pub fn parse_tss_stack_bases(data: &[u8]) -> Result<TssStackBases> {
    if data.len() < 0x68 {
        return Err(Error::BufferNotEnough);
    }
    let read_u64 = |offset: usize| -> VirtAddr {
        VirtAddr(u64::from_le_bytes(
            data[offset..offset + 8].try_into().unwrap(),
        ))
    };
    Ok(TssStackBases {
        rsp: [read_u64(0x04), read_u64(0x0c), read_u64(0x14)],
        ist: [
            read_u64(0x24),
            read_u64(0x2c),
            read_u64(0x34),
            read_u64(0x3c),
            read_u64(0x44),
            read_u64(0x4c),
            read_u64(0x54),
        ],
        io_map_base: u16::from_le_bytes(data[0x66..0x68].try_into().unwrap()),
    })
}

pub fn read_tss_stack_bases(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    selector: u16,
) -> Result<(GdtEntry, TssStackBases)> {
    let entry = read_gdt_entry(debugger, register_map, regs, gdtr, selector)?;
    if !entry.system || !matches!(entry.ty, 0x9 | 0xb) {
        return Err(Error::InvalidExpression(format!(
            "selector {:#x} is not an x64 TSS descriptor ({})",
            selector,
            gdt_type_label(&entry)
        )));
    }
    let size = ((entry.effective_limit + 1).min(0x1000) as usize).max(0x68);
    let mut data = vec![0u8; size];
    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    AddressSpace::new(&debugger.kvm, cr3).read_bytes(VirtAddr(entry.base), &mut data)?;
    let stacks = parse_tss_stack_bases(&data)?;
    Ok((entry, stacks))
}

pub fn gdt_type_label(entry: &GdtEntry) -> String {
    if !entry.system {
        let exec = entry.ty & 0x08 != 0;
        let conforming_or_expand_down = entry.ty & 0x04 != 0;
        let writable_or_readable = entry.ty & 0x02 != 0;
        let accessed = entry.ty & 0x01 != 0;
        let mut flags = String::new();
        flags.push(if exec { 'C' } else { 'D' });
        if conforming_or_expand_down {
            flags.push(if exec { 'c' } else { 'e' });
        }
        if writable_or_readable {
            flags.push(if exec { 'r' } else { 'w' });
        }
        if accessed {
            flags.push('a');
        }
        return flags;
    }
    match entry.ty {
        0x2 => "LDT".to_string(),
        0x9 => "TSS64-avail".to_string(),
        0xb => "TSS64-busy".to_string(),
        0xc => "call-gate64".to_string(),
        0xe => "int-gate64".to_string(),
        0xf => "trap-gate64".to_string(),
        _ => format!("sys-{:#x}", entry.ty),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_idt_entry_fields_and_handler() {
        // handler 0xFFFFF800_12345678 split across low/mid/high fields
        let mut bytes = [0u8; 16];
        bytes[0..2].copy_from_slice(&0x5678u16.to_le_bytes()); // offset low
        bytes[2..4].copy_from_slice(&0x0010u16.to_le_bytes()); // selector
        bytes[4] = 0x03; // IST index (low 3 bits)
        bytes[5] = 0x8E; // present, dpl=0, type=0xE (interrupt gate)
        bytes[6..8].copy_from_slice(&0x1234u16.to_le_bytes()); // offset mid
        bytes[8..12].copy_from_slice(&0xFFFF_F800u32.to_le_bytes()); // offset high

        let entry = parse_idt_entry(7, &bytes);
        assert_eq!(entry.vector, 7);
        assert_eq!(entry.handler, VirtAddr(0xFFFF_F800_1234_5678));
        assert_eq!(entry.selector, 0x0010);
        assert_eq!(entry.ist, 3);
        assert_eq!(entry.gate_type, 0x0E);
        assert_eq!(entry.dpl, 0);
        assert!(entry.present);
    }

    #[test]
    fn parses_code_segment_descriptor() {
        let lo: u64 = 0xFFFF
            | (0xAu64 << 40)   // type: exec | readable
            | (1u64 << 44)     // S = 1 (code/data, non-system)
            | (1u64 << 47)     // present
            | (0xFu64 << 48)   // limit high nibble
            | (1u64 << 53)     // long mode
            | (1u64 << 55); // granularity
        let bytes = lo.to_le_bytes();

        let entry = parse_gdt_entry(1, &bytes);
        assert!(!entry.system);
        assert_eq!(entry.ty, 0xA);
        assert_eq!(entry.base, 0);
        assert_eq!(entry.effective_limit, 0xFFFF_FFFF); // granularity scales limit
        assert!(entry.present);
        assert!(entry.long_mode);
        assert!(!entry.default_big);
        assert!(entry.granularity);
        assert_eq!(entry.selector, 8);
        assert_eq!(gdt_type_label(&entry), "Cr");
    }

    #[test]
    fn parses_system_tss_descriptor_with_full_base() {
        let base: u64 = 0xFFFF_F800_1234_5000;
        let limit: u32 = 0x67;
        let ty: u8 = 0x9; // TSS64-available

        let lo: u64 = (limit as u64 & 0xFFFF)
            | ((base & 0x00FF_FFFF) << 16)
            | ((ty as u64) << 40)
            // S = 0 (system)
            | (1u64 << 47) // present
            | (((limit as u64 >> 16) & 0xF) << 48)
            | (((base >> 24) & 0xFF) << 56);
        let hi: u64 = (base >> 32) & 0xFFFF_FFFF;

        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&lo.to_le_bytes());
        bytes[8..16].copy_from_slice(&hi.to_le_bytes());

        let entry = parse_gdt_entry(8, &bytes);
        assert!(entry.system);
        assert_eq!(entry.ty, 0x9);
        assert_eq!(entry.base, base);
        assert_eq!(entry.effective_limit, 0x67);
        assert_eq!(gdt_type_label(&entry), "TSS64-avail");
    }

    #[test]
    fn parses_tss_stack_bases() {
        let mut data = vec![0u8; 0x68];
        data[0x04..0x0c].copy_from_slice(&0x1111u64.to_le_bytes()); // RSP0
        data[0x0c..0x14].copy_from_slice(&0x2222u64.to_le_bytes()); // RSP1
        data[0x14..0x1c].copy_from_slice(&0x3333u64.to_le_bytes()); // RSP2
        data[0x24..0x2c].copy_from_slice(&0xAAAAu64.to_le_bytes()); // IST1
        data[0x54..0x5c].copy_from_slice(&0xBBBBu64.to_le_bytes()); // IST7
        data[0x66..0x68].copy_from_slice(&0x0068u16.to_le_bytes()); // IO map base

        let tss = parse_tss_stack_bases(&data).unwrap();
        assert_eq!(tss.rsp[0], VirtAddr(0x1111));
        assert_eq!(tss.rsp[1], VirtAddr(0x2222));
        assert_eq!(tss.rsp[2], VirtAddr(0x3333));
        assert_eq!(tss.ist[0], VirtAddr(0xAAAA));
        assert_eq!(tss.ist[6], VirtAddr(0xBBBB));
        assert_eq!(tss.io_map_base, 0x68);
    }

    #[test]
    fn rejects_short_tss_buffer() {
        assert!(parse_tss_stack_bases(&[0u8; 0x10]).is_err());
    }

    #[test]
    fn parses_idtr_and_gdtr_from_qemu_dump() {
        let dump = "\
RAX=0000000000000000 RBX=0000000000000000
GDT=     fffff80512340000 0000007f
IDT=     fffff80512346000 0000000000000fff
TR =0040 fffff80512345000 00000067 8b00 DPL=0 TSS64-busy";

        let idtr = parse_idtr_from_qemu_registers(dump).unwrap();
        assert_eq!(idtr.base, VirtAddr(0xFFFF_F805_1234_6000));
        assert_eq!(idtr.limit, 0x0FFF);

        let gdtr = parse_gdtr_from_qemu_registers(dump).unwrap();
        assert_eq!(gdtr.base, VirtAddr(0xFFFF_F805_1234_0000));
        assert_eq!(gdtr.limit, 0x007F);

        let tr = parse_tr_selector_from_qemu_registers(dump).unwrap();
        assert_eq!(tr, 0x0040);
    }

    #[test]
    fn returns_none_when_qemu_dump_lacks_tables() {
        let dump = "RAX=0 RBX=0";
        assert!(parse_idtr_from_qemu_registers(dump).is_none());
        assert!(parse_gdtr_from_qemu_registers(dump).is_none());
        assert!(parse_tr_selector_from_qemu_registers(dump).is_none());
    }

    #[test]
    fn parses_selector_arguments() {
        assert_eq!(parse_selector_arg("0x40"), Some(0x40));
        assert_eq!(parse_selector_arg("0X28"), Some(0x28));
        assert_eq!(parse_selector_arg("ff"), Some(0xff));
        assert_eq!(parse_selector_arg("zzz"), None);
    }

    #[test]
    fn labels_system_descriptor_types() {
        let mut entry = parse_gdt_entry(0, &[0u8; 16]);
        entry.system = true;
        entry.ty = 0xb;
        assert_eq!(gdt_type_label(&entry), "TSS64-busy");
        entry.ty = 0x2;
        assert_eq!(gdt_type_label(&entry), "LDT");
        entry.ty = 0x7;
        assert_eq!(gdt_type_label(&entry), "sys-0x7");
    }
}
