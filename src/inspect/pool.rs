//! Shared kernel pool (heap) block inspection.
//!
//! Walks `_POOL_HEADER` chains and the big-page pool table from guest memory.
//! Returns plain structs; the REPL renders them as text and the agent
//! serializes them as JSON.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::symbols::{ParsedType, TypeInfo};
use crate::target::Target;
use crate::types::VirtAddr;

const POOL_ALIGN: u64 = 0x10;
pub const POOL_PAGE_SIZE: u64 = 0x1000;
const POOL_FREE_TAG: u32 = 0x6565_7246;
const POOL_MAX_GAP_UNITS: u64 = 4;

#[derive(Clone, Copy)]
pub struct PoolHeader {
    pub header: VirtAddr,
    pub body: VirtAddr,
    pub size: u64,
    pub previous_size: u64,
    pub pool_type: u8,
    pub tag: u32,
    pub synthetic_free: bool,
}

pub struct BigPoolEntry {
    pub va: VirtAddr,
    pub entry: VirtAddr,
    pub index: u64,
    pub nonpaged: bool,
    pub size: u64,
    pub tag: u32,
    pub pattern: u8,
    pub pool_flags: u16,
    pub slush_size: u16,
}

pub struct PoolLayout {
    pool_header: TypeInfo,
    header_size: u64,
    pool_tag_offset: u64,
    pool_header_uses_struct: bool,
    big_pool_type: Option<TypeInfo>,
    big_pool_uses_struct: bool,
    big_pool_has_pool_type: bool,
    big_pool_has_slush: bool,
    big_pool_entry_size: Option<u64>,
}

pub fn pool_layout(debugger: &Target) -> Result<PoolLayout> {
    let pool_header = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_HEADER")
        .ok_or_else(|| Error::StructNotFound("_POOL_HEADER".to_string()))?;
    let pool_tag_offset = pool_header.field_offset("PoolTag")?;
    let pool_header_uses_struct = [
        "PreviousSize",
        "PoolIndex",
        "BlockSize",
        "PoolType",
        "PoolTag",
    ]
    .iter()
    .all(|name| pool_header.fields.contains_key(*name));
    let big_pool_type = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_TRACKER_BIG_PAGES");
    let (big_pool_uses_struct, big_pool_has_pool_type, big_pool_has_slush) = match &big_pool_type {
        Some(ti) => (
            ["Va", "Key", "NumberOfBytes", "Pattern"]
                .iter()
                .all(|name| ti.fields.contains_key(*name)),
            ti.fields.contains_key("PoolType"),
            ti.fields.contains_key("SlushSize"),
        ),
        None => (false, false, false),
    };
    let big_pool_entry_size = big_pool_type.as_ref().map(|ti| ti.size as u64);
    Ok(PoolLayout {
        header_size: pool_header.size as u64,
        pool_header,
        pool_tag_offset,
        pool_header_uses_struct,
        big_pool_type,
        big_pool_uses_struct,
        big_pool_has_pool_type,
        big_pool_has_slush,
        big_pool_entry_size,
    })
}

fn read_pool_field(
    ti: &TypeInfo,
    mem: &impl MemoryOps<VirtAddr>,
    addr: VirtAddr,
    field: &str,
) -> Option<u64> {
    let f = ti.fields.get(field)?;
    let field_addr = addr + f.offset as u64;
    if let ParsedType::Bitfield { pos, len, .. } = &f.type_data {
        let raw: u64 = mem.read(field_addr).ok()?;
        let mask = if *len == 64 {
            u64::MAX
        } else {
            (1u64 << *len) - 1
        };
        return Some((raw >> *pos) & mask);
    }
    match field {
        "PreviousSize" | "PoolIndex" | "BlockSize" | "PoolType" | "Pattern" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some(value as u8 as u64)
        }
        "SlushSize" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some((value & 0xfff) as u64)
        }
        "PoolTag" | "Key" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some(value as u64)
        }
        "Va" | "NumberOfBytes" => mem.read(field_addr).ok(),
        _ => None,
    }
}

pub fn tag_string(tag: u32) -> String {
    let mut s = String::with_capacity(4);
    for i in 0..4 {
        let c = ((tag >> (i * 8)) & 0xff) as u8;
        s.push(if (0x20..=0x7e).contains(&c) {
            c as char
        } else {
            '.'
        });
    }
    s
}

fn tag_looks_printable(tag: u32) -> bool {
    (0..4).all(|i| (0x20..=0x7e).contains(&((tag >> (i * 8)) & 0xff)))
}

fn plausible_pool_tag(tag: u32) -> bool {
    tag == POOL_FREE_TAG || tag_looks_printable(tag)
}

pub fn pool_block_state(h: &PoolHeader) -> &'static str {
    if h.synthetic_free || h.tag == POOL_FREE_TAG {
        "Free"
    } else if h.pool_type == 0 {
        "Free?"
    } else if tag_looks_printable(h.tag) {
        "Allocated"
    } else {
        "Allocated?"
    }
}

fn parse_pool_header(
    debugger: &Target,
    layout: &PoolLayout,
    header: VirtAddr,
) -> Option<PoolHeader> {
    let mem = debugger.current_process().memory();
    let (previous_size, block_units, pool_type, tag) = if layout.pool_header_uses_struct {
        (
            read_pool_field(&layout.pool_header, &mem, header, "PreviousSize")? as u8,
            read_pool_field(&layout.pool_header, &mem, header, "BlockSize")? as u8,
            read_pool_field(&layout.pool_header, &mem, header, "PoolType")? as u8,
            read_pool_field(&layout.pool_header, &mem, header, "PoolTag")? as u32,
        )
    } else {
        let word0: u32 = mem.read(header).ok()?;
        let tag: u32 = mem.read(header + layout.pool_tag_offset).ok()?;
        (
            (word0 & 0xff) as u8,
            ((word0 >> 16) & 0xff) as u8,
            ((word0 >> 24) & 0xff) as u8,
            tag,
        )
    };
    if block_units == 0 {
        return None;
    }
    Some(PoolHeader {
        header,
        body: header + layout.header_size,
        size: block_units as u64 * POOL_ALIGN,
        previous_size: previous_size as u64 * POOL_ALIGN,
        pool_type,
        tag,
        synthetic_free: false,
    })
}

fn pool_header_plausible(layout: &PoolLayout, h: &PoolHeader) -> bool {
    h.size >= layout.header_size
        && h.size <= POOL_PAGE_SIZE
        && (h.header.0 & !(POOL_PAGE_SIZE - 1))
            == ((h.header.0 + h.size - 1) & !(POOL_PAGE_SIZE - 1))
        && (plausible_pool_tag(h.tag) || (h.pool_type == 0 && h.previous_size == 0))
}

fn try_pool_header_lax(
    debugger: &Target,
    layout: &PoolLayout,
    addr: VirtAddr,
) -> Option<PoolHeader> {
    let h = parse_pool_header(debugger, layout, addr)?;
    pool_header_plausible(layout, &h).then_some(h)
}

fn gap_free_pool_block(
    debugger: &Target,
    layout: &PoolLayout,
    header: VirtAddr,
    size: u64,
) -> PoolHeader {
    let mem = debugger.current_process().memory();
    let tag: u32 = mem.read(header + layout.pool_tag_offset).unwrap_or(0);
    PoolHeader {
        header,
        body: header + layout.header_size,
        size,
        previous_size: 0,
        pool_type: 0,
        tag,
        synthetic_free: true,
    }
}

fn walk_pool_page_lax(
    debugger: &Target,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let mut blocks = Vec::new();
    let mut addr = base;
    while addr.0 < base.0 + POOL_PAGE_SIZE {
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
        {
            addr += h.size;
            blocks.push(h);
        } else {
            let mut advanced = false;
            for step in 1..=POOL_MAX_GAP_UNITS {
                let probe = addr + step * POOL_ALIGN;
                if probe.0 >= base.0 + POOL_PAGE_SIZE {
                    break;
                }
                if let Some(h2) = try_pool_header_lax(debugger, layout, probe)
                    .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
                {
                    addr = h2.header;
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                break;
            }
        }
    }
    blocks
}

fn scan_pool_page_lax(
    debugger: &Target,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let mut candidates = Vec::new();
    let mut off = 0;
    while off < POOL_PAGE_SIZE {
        let addr = base + off;
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
        {
            candidates.push(h);
        }
        off += POOL_ALIGN;
    }
    let mut blocks = Vec::new();
    let mut cursor = base;
    for (i, h) in candidates.iter().copied().enumerate() {
        if h.header < cursor {
            continue;
        }
        if h.header == cursor
            && h.size == POOL_ALIGN
            && pool_block_state(&h) == "Free?"
            && let Some(next) = candidates.get(i + 1)
            && next.header.0 > h.header.0 + POOL_ALIGN
        {
            let free_size = next.header.0 - h.header.0 - POOL_ALIGN;
            blocks.push(gap_free_pool_block(debugger, layout, h.header, free_size));
            cursor = h.header + free_size;
        } else {
            if h.header > cursor {
                let free_size = h.header.0.saturating_sub(cursor.0 + POOL_ALIGN);
                if free_size >= POOL_ALIGN * 2 {
                    blocks.push(gap_free_pool_block(debugger, layout, cursor, free_size));
                }
            }
            blocks.push(h);
            cursor = h.header + h.size;
        }
    }
    blocks
}

fn find_pool_block_index(blocks: &[PoolHeader], needle: &PoolHeader) -> Option<usize> {
    blocks
        .iter()
        .position(|h| h.header == needle.header && h.size == needle.size)
}

pub fn locate_pool_block_in_page(
    debugger: &Target,
    layout: &PoolLayout,
    target: VirtAddr,
) -> (Vec<PoolHeader>, Option<usize>, VirtAddr) {
    let base = VirtAddr(target.0 & !(POOL_PAGE_SIZE - 1));
    let aligned = VirtAddr(target.0 & !(POOL_ALIGN - 1));
    let mut anchor = None;
    let mut addr = aligned;
    loop {
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| target >= h.header && target.0 < h.header.0 + h.size)
        {
            anchor = Some(h);
            break;
        }
        if addr <= base {
            break;
        }
        addr -= POOL_ALIGN;
    }
    let Some(anchor) = anchor else {
        return (Vec::new(), None, base);
    };
    let blocks = walk_pool_page_lax(debugger, layout, base);
    if let Some(idx) = find_pool_block_index(&blocks, &anchor) {
        return (blocks, Some(idx), base);
    }
    let blocks = scan_pool_page_lax(debugger, layout, base);
    if let Some(idx) = find_pool_block_index(&blocks, &anchor) {
        return (blocks, Some(idx), base);
    }
    (vec![anchor], Some(0), base)
}

pub fn classify_pool_region(
    debugger: &Target,
    addr: VirtAddr,
) -> Option<(&'static str, VirtAddr, VirtAddr)> {
    for (name, start, stop) in [
        ("NonPagedPool", "MmNonPagedPoolStart", "MmNonPagedPoolEnd"),
        ("PagedPool", "MmPagedPoolStart", "MmPagedPoolEnd"),
        ("SpecialPool", "MmSpecialPoolStart", "MmSpecialPoolEnd"),
    ] {
        let s_addr = debugger
            .symbols
            .find_symbol_across_modules(debugger.current_dtb(), start)?;
        let e_addr = debugger
            .symbols
            .find_symbol_across_modules(debugger.current_dtb(), stop)?;
        let mem = debugger.current_process().memory();
        let s = VirtAddr(mem.read::<u64>(s_addr).ok()?);
        let e = VirtAddr(mem.read::<u64>(e_addr).ok()?);
        if addr >= s && addr < e {
            return Some((name, s, e));
        }
    }
    None
}

fn parse_big_pool_entry(
    debugger: &Target,
    layout: &PoolLayout,
    entry: VirtAddr,
) -> Option<BigPoolEntry> {
    let mem = debugger.current_process().memory();
    let ti = layout.big_pool_type.as_ref()?;
    let (va_raw, size, tag, pattern, pool_flags, slush_size) = if layout.big_pool_uses_struct {
        (
            read_pool_field(ti, &mem, entry, "Va")?,
            read_pool_field(ti, &mem, entry, "NumberOfBytes")?,
            read_pool_field(ti, &mem, entry, "Key")? as u32,
            read_pool_field(ti, &mem, entry, "Pattern")? as u8,
            if layout.big_pool_has_pool_type {
                read_pool_field(ti, &mem, entry, "PoolType").unwrap_or(0) as u16 & 0xfff
            } else {
                0
            },
            if layout.big_pool_has_slush {
                read_pool_field(ti, &mem, entry, "SlushSize").unwrap_or(0) as u16 & 0xfff
            } else {
                0
            },
        )
    } else {
        let va_raw: u64 = mem.read(entry + ti.field_offset("Va").ok()?).ok()?;
        let size: u64 = mem
            .read(entry + ti.field_offset("NumberOfBytes").ok()?)
            .ok()?;
        let tag: u32 = mem.read(entry + ti.field_offset("Key").ok()?).ok()?;
        let flags_word: u32 = mem.read(entry + ti.field_offset("Pattern").ok()?).ok()?;
        (
            va_raw,
            size,
            tag,
            (flags_word & 0xff) as u8,
            ((flags_word >> 8) & 0xfff) as u16,
            ((flags_word >> 20) & 0xfff) as u16,
        )
    };
    let va = VirtAddr(va_raw & !1);
    if va.is_zero() || size == 0 || !plausible_pool_tag(tag) {
        return None;
    }
    Some(BigPoolEntry {
        va,
        entry,
        index: 0,
        nonpaged: va_raw & 1 != 0,
        size,
        tag,
        pattern,
        pool_flags,
        slush_size,
    })
}

pub fn find_big_pool(
    debugger: &Target,
    layout: &PoolLayout,
    target: VirtAddr,
) -> Option<BigPoolEntry> {
    let table_sym = debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "PoolBigPageTable")?;
    let mem = debugger.current_process().memory();
    let table_addr = VirtAddr(mem.read::<u64>(table_sym).ok()?);
    let count_sym = debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "PoolBigPageTableSize")?;
    let count: u64 = mem.read(count_sym).ok()?;
    if count == 0 || count > 0x100000 {
        return None;
    }
    let entry_size = layout.big_pool_entry_size?;
    for i in 0..count {
        let entry_addr = table_addr + i * entry_size;
        if let Some(mut entry) = parse_big_pool_entry(debugger, layout, entry_addr)
            .filter(|e| target >= e.va && target.0 < e.va.0 + e.size)
        {
            entry.index = i;
            return Some(entry);
        }
    }
    None
}

pub fn segment_heap_hint(debugger: &Target) -> Option<&'static str> {
    debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "RtlpHpHeapGlobals")?;
    Some("kernel has RtlpHpHeapGlobals; address may be segment heap instead of _POOL_HEADER")
}

pub fn annotate_near_symbol(debugger: &Target, addr: VirtAddr) -> Option<String> {
    let (module, name, offset) = debugger
        .symbols
        .find_closest_symbol_for_address(debugger.current_dtb(), addr)?;
    (offset <= 0x1000).then(|| format!("{}!{}+0x{:x}", module, name, offset))
}
