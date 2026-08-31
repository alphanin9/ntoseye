use std::cell::RefCell;
use std::collections::HashMap;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::types::*;

// PageFrameNumber
pub const PFN_MASK: u64 = (!0xFu64 << 8) & 0xFFFFFFFFFu64;
pub const PAGE_SIZE: usize = 0x1000; // 4KiB
/// AMD64 2 MiB PDE mapping / AArch64 level-2 block.
pub const LARGE_PAGE_SIZE: u64 = 1 << 21;
/// AMD64 1 GiB PDPTE mapping / AArch64 level-1 block.
pub const HUGE_PAGE_SIZE: u64 = 1 << 30;
pub const PAGE_SHIFT: u32 = 12;
pub const PTE_SHIFT: u8 = 12;
pub const PDE_SHIFT: u8 = 21;
pub const PDPTE_SHIFT: u8 = 30;
pub const PML4E_SHIFT: u8 = 39;
pub const PT_INDEX_MASK: u64 = 0x1FF;

/// Sentinel DTB: `AddressSpace` skips page-table translation and treats
/// virtual addresses as physical. Used by triage dumps, which only contain
/// captured virtual memory regions.
pub const DTB_IDENTITY: Dtb = u64::MAX;

// 'a = lifetime of the borrow of the backend
//  B = any type that implements phys mem
pub struct AddressSpace<'a, B: MemoryOps<PhysAddr>> {
    backend: &'a B,
    dtb: Dtb,
    /// AArch64 TTBR1 (kernel-space root). Kernel VAs (bit 55 set) walk this;
    /// `dtb` is the TTBR0/process root for the user half. Ignored on AMD64,
    /// where one CR3 covers both halves.
    kernel_dtb: Option<Dtb>,
    arm64: bool,
    /// Page-table entries already read during this borrow, keyed by the
    /// physical address of the entry itself.
    ///
    /// A walk re-reads the same upper-level entries for every page it
    /// translates — reading one 2 MiB region 4 KiB at a time fetched the same
    /// PDE 512 times — and over a KD transport each of those is a network round
    /// trip. The entries cannot change underneath us: an `AddressSpace` borrows
    /// its backend, and resuming the target needs `&mut Target`, so the
    /// borrow checker already guarantees no cached entry outlives a stop.
    pt_cache: RefCell<HashMap<u64, Option<PageTableEntry>>>,
}

pub struct Translation {
    pub address: PhysAddr,
    pub large: bool,
    /// Size of the mapping this translation resolved to (4 KiB, 2 MiB or
    /// 1 GiB). Readers advance by the remainder of *this* mapping rather than
    /// of a 4 KiB page, so a large page is walked once instead of once per
    /// 4 KiB inside it.
    pub page_size: u64,
    pub writable: bool,
    pub user: bool,
    /// Effective execute-never for the selected address-space half: AMD64 NX,
    /// AArch64 PXN for TTBR1 addresses, or AArch64 UXN for TTBR0 addresses.
    pub nx: bool,
    /// Effective AArch64 UXN, including ancestor UXNTable restrictions.
    /// Always `false` on AMD64.
    pub uxn: bool,
}

impl Translation {
    pub const fn new_huge(pml4e: PageTableEntry, pdpte: PageTableEntry, va: VirtAddr) -> Self {
        Self {
            page_size: HUGE_PAGE_SIZE,
            address: pdpte.page_frame() + va.huge_page_offset(),
            large: true,
            writable: pml4e.is_writable() && pdpte.is_writable(),
            user: pml4e.is_user() && pdpte.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx(),
            uxn: false,
        }
    }

    pub const fn new_large(
        pml4e: PageTableEntry,
        pdpte: PageTableEntry,
        pde: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        Self {
            page_size: LARGE_PAGE_SIZE,
            address: pde.page_frame() + va.large_page_offset(),
            large: true,
            writable: pml4e.is_writable() && pdpte.is_writable() && pde.is_writable(),
            user: pml4e.is_user() && pdpte.is_user() && pde.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx() || pde.is_nx(),
            uxn: false,
        }
    }

    pub const fn new(
        pml4e: PageTableEntry,
        pdpte: PageTableEntry,
        pde: PageTableEntry,
        pte: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        Self {
            page_size: PAGE_SIZE as u64,
            address: pte.page_frame() + va.page_offset(),
            large: false,
            writable: pml4e.is_writable()
                && pdpte.is_writable()
                && pde.is_writable()
                && pte.is_writable(),
            user: pml4e.is_user() && pdpte.is_user() && pde.is_user() && pte.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx() || pde.is_nx() || pte.is_nx(),
            uxn: false,
        }
    }

    /// AArch64 1 GiB block descriptor at level 1.
    pub const fn arm64_huge(l0: PageTableEntry, l1: PageTableEntry, va: VirtAddr) -> Self {
        let pxn = l0.arm64_table_is_pxn() || l1.arm64_is_pxn();
        let uxn = l0.arm64_table_is_uxn() || l1.arm64_is_uxn();
        Self {
            page_size: HUGE_PAGE_SIZE,
            address: l1.arm64_page_frame() + va.huge_page_offset(),
            large: true,
            writable: l0.arm64_table_allows_write() && l1.arm64_is_writable(),
            user: l0.arm64_table_allows_user() && l1.arm64_is_user(),
            nx: if va.0 & (1 << 55) != 0 { pxn } else { uxn },
            uxn,
        }
    }

    /// AArch64 2 MiB block descriptor at level 2.
    pub const fn arm64_large(
        l0: PageTableEntry,
        l1: PageTableEntry,
        l2: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        let pxn = l0.arm64_table_is_pxn() || l1.arm64_table_is_pxn() || l2.arm64_is_pxn();
        let uxn = l0.arm64_table_is_uxn() || l1.arm64_table_is_uxn() || l2.arm64_is_uxn();
        Self {
            page_size: LARGE_PAGE_SIZE,
            address: l2.arm64_page_frame() + va.large_page_offset(),
            large: true,
            writable: l0.arm64_table_allows_write()
                && l1.arm64_table_allows_write()
                && l2.arm64_is_writable(),
            user: l0.arm64_table_allows_user()
                && l1.arm64_table_allows_user()
                && l2.arm64_is_user(),
            nx: if va.0 & (1 << 55) != 0 { pxn } else { uxn },
            uxn,
        }
    }

    /// AArch64 4 KiB page descriptor at level 3.
    pub const fn arm64_page(
        l0: PageTableEntry,
        l1: PageTableEntry,
        l2: PageTableEntry,
        l3: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        let pxn = l0.arm64_table_is_pxn()
            || l1.arm64_table_is_pxn()
            || l2.arm64_table_is_pxn()
            || l3.arm64_is_pxn();
        let uxn = l0.arm64_table_is_uxn()
            || l1.arm64_table_is_uxn()
            || l2.arm64_table_is_uxn()
            || l3.arm64_is_uxn();
        Self {
            page_size: PAGE_SIZE as u64,
            address: l3.arm64_page_frame() + va.page_offset(),
            large: false,
            writable: l0.arm64_table_allows_write()
                && l1.arm64_table_allows_write()
                && l2.arm64_table_allows_write()
                && l3.arm64_is_writable(),
            user: l0.arm64_table_allows_user()
                && l1.arm64_table_allows_user()
                && l2.arm64_table_allows_user()
                && l3.arm64_is_user(),
            nx: if va.0 & (1 << 55) != 0 { pxn } else { uxn },
            uxn,
        }
    }
}

impl<'a, B: MemoryOps<PhysAddr>> AddressSpace<'a, B> {
    pub fn new(backend: &'a B, dtb: Dtb) -> Self {
        Self {
            backend,
            dtb,
            kernel_dtb: None,
            arm64: false,
            pt_cache: RefCell::new(HashMap::new()),
        }
    }

    /// AArch64 address space with separate TTBR0 (user) and TTBR1 (kernel)
    /// roots; the walk selects the root from the VA's bit 55.
    pub fn new_arm64(backend: &'a B, ttbr0: Dtb, ttbr1: Dtb) -> Self {
        Self {
            backend,
            dtb: ttbr0,
            kernel_dtb: Some(ttbr1),
            arm64: true,
            pt_cache: RefCell::new(HashMap::new()),
        }
    }

    fn read_pt_entry(&self, table_base: PhysAddr, index: usize) -> Result<Option<PageTableEntry>> {
        let entry_addr = table_base + 8 * index as u64;
        if let Some(cached) = self.pt_cache.borrow().get(&entry_addr) {
            return Ok(*cached);
        }
        // A missing frame is cached as `None` too: it is a property of the
        // table, so re-reading it would repeat the same failing round trip.
        let entry = match self.backend.read(entry_addr) {
            Ok(entry) => Some(entry),
            Err(Error::BadPhysicalAddress(_)) => None,
            Err(e) => return Err(e),
        };
        self.pt_cache.borrow_mut().insert(entry_addr, entry);
        Ok(entry)
    }

    fn virt_to_phys_arm64(&self, va: VirtAddr) -> Result<Option<Translation>> {
        if self.dtb == DTB_IDENTITY {
            return Ok(Some(Translation {
                address: va.0,
                large: false,
                page_size: PAGE_SIZE as u64,
                writable: false,
                user: false,
                nx: false,
                uxn: false,
            }));
        }

        // AArch64: bit 55 selects TTBR1 (kernel) vs TTBR0 (user).
        let root = if va.0 & (1 << 55) != 0 {
            self.kernel_dtb.unwrap_or(self.dtb)
        } else {
            self.dtb
        };

        // Level 0 (index bits 47:39 — same 9-bit index math as x64 PML4).
        let Some(l0) = self.read_pt_entry(root, va.pml4_index())? else {
            return Ok(None);
        };
        if !l0.arm64_is_valid() || l0.arm64_is_block() {
            // 512 GiB L0 blocks are not used by Windows; treat as unmapped.
            return Ok(None);
        }

        let Some(l1) = self.read_pt_entry(l0.arm64_page_frame(), va.pdpt_index())? else {
            return Ok(None);
        };
        if !l1.arm64_is_valid() {
            return Ok(None);
        }
        if l1.arm64_is_block() {
            return Ok(Some(Translation::arm64_huge(l0, l1, va)));
        }

        let Some(l2) = self.read_pt_entry(l1.arm64_page_frame(), va.pd_index())? else {
            return Ok(None);
        };
        if !l2.arm64_is_valid() {
            return Ok(None);
        }
        if l2.arm64_is_block() {
            return Ok(Some(Translation::arm64_large(l0, l1, l2, va)));
        }

        let Some(l3) = self.read_pt_entry(l2.arm64_page_frame(), va.pt_index())? else {
            return Ok(None);
        };
        // At L3 only 0b11 is a page descriptor; 0b01 is reserved.
        if l3.0 & 0b11 != 0b11 {
            return Ok(None);
        }
        Ok(Some(Translation::arm64_page(l0, l1, l2, l3, va)))
    }

    pub fn virt_to_phys(&self, va: VirtAddr) -> Result<Option<Translation>> {
        if self.arm64 {
            return self.virt_to_phys_arm64(va);
        }
        if self.dtb == DTB_IDENTITY {
            return Ok(Some(Translation {
                address: va.0,
                large: false,
                page_size: PAGE_SIZE as u64,
                writable: false,
                user: false,
                nx: false,
                uxn: false,
            }));
        }

        let Some(pml4e) = self.read_pt_entry(self.dtb, va.pml4_index())? else {
            return Ok(None);
        };

        if !pml4e.is_present() {
            return Ok(None);
        }

        let Some(pdpte) = self.read_pt_entry(pml4e.page_frame(), va.pdpt_index())? else {
            return Ok(None);
        };

        if !pdpte.is_present() {
            return Ok(None);
        }

        if pdpte.is_large_page() {
            return Ok(Some(Translation::new_huge(pml4e, pdpte, va)));
        }

        let Some(pde) = self.read_pt_entry(pdpte.page_frame(), va.pd_index())? else {
            return Ok(None);
        };

        if !pde.is_present() {
            return Ok(None);
        }

        if pde.is_large_page() {
            return Ok(Some(Translation::new_large(pml4e, pdpte, pde, va)));
        }

        let Some(pte) = self.read_pt_entry(pde.page_frame(), va.pt_index())? else {
            return Ok(None);
        };

        if !pte.is_present() {
            return Ok(None);
        }

        Ok(Some(Translation::new(pml4e, pdpte, pde, pte, va)))
    }
}

impl<'a, B: MemoryOps<PhysAddr>> MemoryOps<VirtAddr> for AddressSpace<'a, B> {
    fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;

        while offset < buf.len() {
            let curr_vaddr = addr + offset as u64;

            let translation = match self.virt_to_phys(curr_vaddr)? {
                Some(translation) => translation,
                None if offset > 0 => return Err(Error::PartialRead(offset)),
                None => return Err(Error::BadVirtualAddress(curr_vaddr)),
            };

            // Advance by the remainder of the mapping we actually resolved,
            // not of a 4 KiB page: a 2 MiB mapping otherwise costs 512 walks.
            let bytes_available =
                (translation.page_size - (curr_vaddr.0 & (translation.page_size - 1))) as usize;
            let chunk_size = (buf.len() - offset).min(bytes_available);

            self.backend
                .read_bytes(translation.address, &mut buf[offset..offset + chunk_size])?;
            offset += chunk_size;
        }

        Ok(())
    }

    fn write_bytes(&self, addr: VirtAddr, buf: &[u8]) -> Result<()> {
        let mut offset = 0;

        while offset < buf.len() {
            let curr_vaddr = addr + offset as u64;

            let translation = match self.virt_to_phys(curr_vaddr)? {
                Some(translation) => translation,
                None => {
                    if offset > 0 {
                        return Err(Error::PartialWrite(offset));
                    } else {
                        return Err(Error::BadVirtualAddress(curr_vaddr));
                    }
                }
            };

            // Advance by the remainder of the mapping we actually resolved,
            // not of a 4 KiB page: a 2 MiB mapping otherwise costs 512 walks.
            let bytes_available =
                (translation.page_size - (curr_vaddr.0 & (translation.page_size - 1))) as usize;
            let chunk_size = (buf.len() - offset).min(bytes_available);

            self.backend
                .write_bytes(translation.address, &buf[offset..offset + chunk_size])?;
            offset += chunk_size;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryOps;

    struct FakePhysMem {
        data: Vec<u8>,
    }

    impl MemoryOps<PhysAddr> for FakePhysMem {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let start = addr as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(Error::BadPhysicalAddress(addr));
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            Err(Error::BadPhysicalAddress(0))
        }
    }

    /// Physical backend that records every read, so tests can assert how many
    /// round trips a walk actually costs.
    struct CountingPhysMem {
        data: Vec<u8>,
        reads: std::cell::RefCell<Vec<(PhysAddr, usize)>>,
    }

    impl CountingPhysMem {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                reads: std::cell::RefCell::new(Vec::new()),
            }
        }

        /// Reads of a single page-table entry (8 bytes), i.e. walk cost.
        fn entry_reads(&self) -> usize {
            self.reads.borrow().iter().filter(|(_, len)| *len == 8).count()
        }
    }

    impl MemoryOps<PhysAddr> for CountingPhysMem {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            self.reads.borrow_mut().push((addr, buf.len()));
            let start = addr as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(Error::BadPhysicalAddress(addr));
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            Err(Error::BadPhysicalAddress(0))
        }
    }

    /// PML4 at 0x1000 -> PDPT at 0x2000 -> PD at 0x3000, whose entry maps a
    /// 2 MiB large page at physical `large_frame`. Mirrors how Windows maps
    /// ntoskrnl: the walk terminates at the PDE with PS set.
    fn large_page_tables(large_frame: u64) -> (Vec<u8>, Dtb) {
        let mut data = vec![0u8; (large_frame + 2 * LARGE_PAGE_SIZE) as usize];
        let present_writable = 0b11u64;
        data[0x1000..0x1008].copy_from_slice(&(0x2000u64 | present_writable).to_le_bytes());
        data[0x2000..0x2008].copy_from_slice(&(0x3000u64 | present_writable).to_le_bytes());
        // PS (bit 7) set: this PDE *is* the mapping.
        data[0x3000..0x3008]
            .copy_from_slice(&(large_frame | present_writable | 0x80).to_le_bytes());
        (data, 0x1000)
    }

    #[test]
    fn large_page_mapping_is_walked_once_for_the_whole_mapping() {
        let large_frame = 0x20_0000u64;
        let (mut data, dtb) = large_page_tables(large_frame);
        data[large_frame as usize..large_frame as usize + 8]
            .copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        let mem = CountingPhysMem::new(data);
        let space = AddressSpace::new(&mem, dtb);

        // Span the full 2 MiB mapping in one read.
        let mut buf = vec![0u8; LARGE_PAGE_SIZE as usize];
        space.read_bytes(VirtAddr(0), &mut buf).unwrap();

        assert_eq!(u64::from_le_bytes(buf[..8].try_into().unwrap()), 0xDEAD_BEEF_CAFE_BABE);
        // Three levels, once -- not once per 4 KiB inside the mapping.
        assert_eq!(mem.entry_reads(), 3, "large page must be walked once");
        let data_reads = mem.reads.borrow().iter().filter(|(_, l)| *l != 8).count();
        assert_eq!(data_reads, 1, "a 2 MiB mapping is one contiguous physical run");
    }

    #[test]
    fn large_page_translation_reports_mapping_granularity() {
        let large_frame = 0x20_0000u64;
        let (data, dtb) = large_page_tables(large_frame);
        let mem = CountingPhysMem::new(data);
        let space = AddressSpace::new(&mem, dtb);

        let translation = space.virt_to_phys(VirtAddr(0x1234)).unwrap().unwrap();

        assert!(translation.large);
        assert_eq!(translation.page_size, LARGE_PAGE_SIZE);
        assert_eq!(translation.address, large_frame + 0x1234);
    }

    #[test]
    fn repeated_translations_reuse_cached_page_table_entries() {
        let large_frame = 0x20_0000u64;
        let (data, dtb) = large_page_tables(large_frame);
        let mem = CountingPhysMem::new(data);
        let space = AddressSpace::new(&mem, dtb);

        for offset in [0u64, 0x1000, 0x2000, 0x1f_f000] {
            space.virt_to_phys(VirtAddr(offset)).unwrap().unwrap();
        }

        // Every one of those resolves through the same three entries.
        assert_eq!(mem.entry_reads(), 3, "walk entries must be read once per borrow");
    }

    #[test]
    fn walk_cache_is_scoped_to_one_address_space_borrow() {
        let large_frame = 0x20_0000u64;
        let (data, dtb) = large_page_tables(large_frame);
        let mem = CountingPhysMem::new(data);

        AddressSpace::new(&mem, dtb).virt_to_phys(VirtAddr(0)).unwrap();
        assert_eq!(mem.entry_reads(), 3);
        // A fresh borrow re-reads: nothing is cached across a stop, because an
        // AddressSpace cannot outlive the &Target it borrows.
        AddressSpace::new(&mem, dtb).virt_to_phys(VirtAddr(0)).unwrap();
        assert_eq!(mem.entry_reads(), 6);
    }

    #[test]
    fn identity_dtb_skips_page_table_walk() {
        let mut data = vec![0u8; 0x2000];
        // Plant recognizable bytes at VA/PA 0x1000
        data[0x1000..0x1008].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_le_bytes());
        let mem = FakePhysMem { data };
        let space = AddressSpace::new(&mem, DTB_IDENTITY);

        let mut buf = [0u8; 8];
        space.read_bytes(VirtAddr(0x1000), &mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0xDEADBEEFCAFEBABE);
    }

    #[test]
    fn identity_dtb_cross_boundary_read() {
        let mut data = vec![0u8; 0x3000];
        // Span across a 4K boundary: fill 0xFFF..0x1001
        for (i, byte) in data[0xFF0..0x1010].iter_mut().enumerate() {
            *byte = ((0xFF0 + i) & 0xFF) as u8;
        }
        let mem = FakePhysMem { data };
        let space = AddressSpace::new(&mem, DTB_IDENTITY);

        let mut buf = [0u8; 0x20];
        space.read_bytes(VirtAddr(0xFF0), &mut buf).unwrap();
        assert_eq!(buf[0], 0xF0);
        assert_eq!(buf[0x10], 0x00); // 0x1000 & 0xFF
        assert_eq!(buf[0x1F], 0x0F); // 0x100F & 0xFF
    }

    #[test]
    fn arm64_kernel_walk_uses_upper_half_of_combined_root_page() {
        let mut data = vec![0u8; 0x6000];
        let kernel_va = VirtAddr(0xffff_8000_0000_0000);
        let root_page = 0x1000u64;
        data[root_page as usize + kernel_va.pml4_index() * 8
            ..root_page as usize + kernel_va.pml4_index() * 8 + 8]
            .copy_from_slice(&(0x2000u64 | 0b11).to_le_bytes());
        data[0x2000..0x2008].copy_from_slice(&(0x3000u64 | 0b11).to_le_bytes());
        data[0x3000..0x3008].copy_from_slice(&(0x4000u64 | 0b11).to_le_bytes());
        data[0x4000..0x4008].copy_from_slice(&(0x5000u64 | 0b11).to_le_bytes());
        data[0x5000..0x5008].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        let mem = FakePhysMem { data };
        let space = AddressSpace::new_arm64(&mem, root_page, root_page);

        let value: u64 = space.read(kernel_va).unwrap();

        assert_eq!(value, 0xDEAD_BEEF_CAFE_BABE);
    }
    #[test]
    fn arm64_translation_applies_table_attribute_restrictions() {
        let l0 = PageTableEntry(0b11 | (1 << 61) | (1 << 62) | (1 << 60));
        let table = PageTableEntry(0b11);
        let page = PageTableEntry(0b11 | (1 << 7) | 0x1234_5000);

        let translation = Translation::arm64_page(l0, table, table, page, VirtAddr(0x2000));

        assert_eq!(translation.address, 0x1234_5000);
        assert!(!translation.user);
        assert!(!translation.writable);
        assert!(translation.uxn);
        assert!(translation.nx);
    }

    #[test]
    fn arm64_translation_uses_pxn_for_kernel_addresses() {
        let l0 = PageTableEntry(0b11 | (1 << 59));
        let table = PageTableEntry(0b11);
        let page = PageTableEntry(0b11 | 0x1234_5000);

        let translation =
            Translation::arm64_page(l0, table, table, page, VirtAddr(0xffff_f800_0000_2000));

        assert!(translation.nx);
        assert!(!translation.uxn);
    }
}
