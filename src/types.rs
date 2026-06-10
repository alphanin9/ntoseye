use crate::memory::{
    PAGE_SHIFT, PDE_SHIFT, PDPTE_SHIFT, PFN_MASK, PML4E_SHIFT, PT_INDEX_MASK, PTE_SHIFT,
};
use owo_colors::OwoColorize;
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(
    Default,
    Clone,
    Copy,
    FromBytes,
    IntoBytes,
    Immutable,
    Debug,
    PartialEq,
    Eq,
    derive_more::From,
    derive_more::Into,
    derive_more::Add,
    derive_more::Sub,
    derive_more::AddAssign,
    derive_more::SubAssign,
    derive_more::BitAnd,
    derive_more::BitOr,
    derive_more::FromStr,
    derive_more::Constructor,
    PartialOrd,
)]
#[repr(transparent)]
pub struct VirtAddr(pub u64);

impl From<u32> for VirtAddr {
    fn from(value: u32) -> Self {
        VirtAddr::from_u64(value as u64)
    }
}

impl AddAssign<u64> for VirtAddr {
    fn add_assign(&mut self, rhs: u64) {
        *self += VirtAddr(rhs);
    }
}

impl SubAssign<u64> for VirtAddr {
    fn sub_assign(&mut self, rhs: u64) {
        *self -= VirtAddr(rhs);
    }
}

impl Add<u64> for VirtAddr {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        self + VirtAddr(rhs)
    }
}

impl Sub<u64> for VirtAddr {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        self - VirtAddr(rhs)
    }
}

impl Add<u32> for VirtAddr {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        self + VirtAddr::from(rhs)
    }
}

impl Sub<u32> for VirtAddr {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self::Output {
        self - VirtAddr::from(rhs)
    }
}

pub type PhysAddr = u64;

pub type Dtb = PhysAddr;

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct PageTableEntry(pub u64);

impl VirtAddr {
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub const fn construct(
        pml4_index: usize,
        pdpt_index: usize,
        pd_index: usize,
        pt_index: usize,
    ) -> Self {
        let mut addr = ((pml4_index << PML4E_SHIFT)
            | (pdpt_index << PDPTE_SHIFT)
            | (pd_index << PDE_SHIFT)
            | (pt_index << PTE_SHIFT)) as u64;

        if pml4_index >= 256 {
            addr |= 0xffff_0000_0000_0000;
        }

        Self(addr)
    }

    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub const fn huge_page_offset(self) -> u64 {
        self.0 & !(!0u64 << 30)
    }

    pub const fn large_page_offset(self) -> u64 {
        self.0 & !(!0u64 << 21)
    }

    pub const fn pml4_index(self) -> usize {
        ((self.0 >> PML4E_SHIFT) & PT_INDEX_MASK) as usize
    }

    pub const fn pdpt_index(self) -> usize {
        ((self.0 >> PDPTE_SHIFT) & PT_INDEX_MASK) as usize
    }

    pub const fn pd_index(self) -> usize {
        ((self.0 >> PDE_SHIFT) & PT_INDEX_MASK) as usize
    }

    pub const fn pt_index(self) -> usize {
        ((self.0 >> PTE_SHIFT) & PT_INDEX_MASK) as usize
    }

    pub const fn page_offset(self) -> u64 {
        self.0 & !(!0 << PAGE_SHIFT)
    }
}

impl PageTableEntry {
    pub const fn is_present(self) -> bool {
        self.0 & 1 != 0
    }

    pub const fn is_large_page(self) -> bool {
        self.0 & 0x80 != 0
    }

    pub const fn page_frame(self) -> u64 {
        self.0 & PFN_MASK
    }

    pub const fn is_user(self) -> bool {
        self.0 & 0x4 != 0
    }

    pub const fn is_nx(self) -> bool {
        self.0 & (1 << 63) != 0
    }

    pub const fn is_writable(self) -> bool {
        self.0 & 0x2 != 0
    }

    pub const fn pfn(self) -> u64 {
        self.page_frame() >> 12
    }

    pub fn flags(self) -> String {
        format!(
            "{}{}{}{}{}{}{}{}{}{}{}",
            if self.0 & (1 << 9) != 0 { 'C' } else { '-' }, // CopyOnWrite
            if self.0 & (1 << 8) != 0 { 'G' } else { '-' }, // Global
            if self.0 & (1 << 7) != 0 { 'L' } else { '-' }, // LargePage
            if self.0 & (1 << 6) != 0 { 'D' } else { '-' }, // Dirty
            if self.0 & (1 << 5) != 0 { 'A' } else { '-' }, // Accessed
            if self.0 & (1 << 4) != 0 { 'N' } else { '-' }, // CacheDisable
            '-', // WriteThrough (always '-' in reference)
            if self.0 & (1 << 2) != 0 { 'U' } else { 'K' }, // Owner (User/Kernel)
            if self.0 & (1 << 11) != 0 { 'W' } else { 'R' }, // Write
            if self.0 & (1 << 63) != 0 { '-' } else { 'E' }, // NoExecute (inverted)
            if self.0 & 1 != 0 { 'V' } else { '-' }, // Valid
        )
    }
}

pub struct Value<T>(pub T);

/// Macro to implement formatting traits with a specific color
macro_rules! impl_colored_fmt {
    (impl<$g:ident> $t:ty, $color:ident, $($trait:path),+) => {
        $(
            impl<$g> $trait for $t
            where $g: $trait
            {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    <_ as $trait>::fmt(&self.0.$color(), f)
                }
            }
        )*
    };

    ($t:ty, $color:ident, $($trait:path),+) => {
        $(
            impl $trait for $t {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    <_ as $trait>::fmt(&self.0.$color(), f)
                }
            }
        )*
    };
}

/// Plain forwarding to the inner value's formatting; no styling. Domain types
/// stay presentation-free; all address coloring lives in the `ui` module
/// (`ui::addr`), so a `VirtAddr` formatted with `{:#x}` is just plain hex
macro_rules! impl_plain_fmt {
    ($t:ty, $($trait:path),+) => {
        $(
            impl $trait for $t {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    <_ as $trait>::fmt(&self.0, f)
                }
            }
        )*
    };
}

impl_plain_fmt!(
    VirtAddr,
    fmt::Display,
    fmt::LowerHex,
    fmt::UpperHex,
    fmt::Binary
);

impl_colored_fmt!(
    impl<T> Value<T>,
    cyan,
    fmt::Display, fmt::LowerHex, fmt::UpperHex, fmt::Binary
);
