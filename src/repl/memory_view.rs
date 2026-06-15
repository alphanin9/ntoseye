use owo_colors::OwoColorize;

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;

pub struct AddressRange {
    pub start: VirtAddr,
    pub end: VirtAddr,
}

impl AddressRange {
    pub fn parse(
        parts: &[&str],
        debugger: &Target,
        default_count: u64,
        item_size: u64,
    ) -> Result<Self> {
        let start_arg = parts.get(1).ok_or(Error::InvalidRange)?;
        let start = Expr::eval(start_arg, debugger)?;

        let end = if let Some(end_arg) = parts.get(2) {
            let end = Expr::eval(end_arg, debugger)?;
            if end.0 < start.0 {
                start + end.0 * item_size
            } else {
                end
            }
        } else {
            start + default_count * item_size
        };

        if end.0 < start.0 {
            return Err(Error::InvalidRange);
        }

        Ok(AddressRange { start, end })
    }

    pub fn len(&self) -> usize {
        (self.end.0 - self.start.0) as usize
    }
}

pub fn parse_byte_pattern(pattern: &str) -> Option<Vec<u8>> {
    if pattern.is_empty() {
        return None;
    }

    if pattern.starts_with("\\x") || pattern.starts_with("\\X") {
        let mut bytes = Vec::new();
        let mut rest = pattern;

        while let Some(stripped) = rest
            .strip_prefix("\\x")
            .or_else(|| rest.strip_prefix("\\X"))
        {
            if stripped.len() < 2 {
                return None;
            }

            let byte = u8::from_str_radix(&stripped[..2], 16).ok()?;
            bytes.push(byte);
            rest = &stripped[2..];
        }

        if rest.is_empty() && !bytes.is_empty() {
            return Some(bytes);
        }

        return None;
    }

    if !pattern.len().is_multiple_of(2) || !pattern.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    hex::decode(pattern).ok()
}

pub fn resolve_length_or_end(start: VirtAddr, end_or_length: VirtAddr) -> Option<usize> {
    let length = if end_or_length.0 < start.0 {
        end_or_length.0
    } else {
        end_or_length.0 - start.0
    };

    usize::try_from(length).ok()
}

pub fn repeat_pattern(pattern: &[u8], length: usize) -> Vec<u8> {
    let mut filled = Vec::with_capacity(length);

    while filled.len() < length {
        let remaining = length - filled.len();
        filled.extend_from_slice(&pattern[..remaining.min(pattern.len())]);
    }

    filled
}

pub enum ItemFormat {
    Bytes,
    Dwords,
    Qwords,
}

pub struct MemoryDisplayMode {
    bytes_per_row: usize,
    item_size: usize,
    item_format: ItemFormat,
    show_ascii: bool,
}

impl MemoryDisplayMode {
    pub fn bytes() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 1,
            item_format: ItemFormat::Bytes,
            show_ascii: true,
        }
    }

    pub fn dwords() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 4,
            item_format: ItemFormat::Dwords,
            show_ascii: false,
        }
    }

    pub fn qwords() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 8,
            item_format: ItemFormat::Qwords,
            show_ascii: false,
        }
    }
}

pub fn display_memory(start_address: VirtAddr, data: &[u8], mode: &MemoryDisplayMode) {
    for (i, chunk) in data.chunks(mode.bytes_per_row).enumerate() {
        print!(
            "{}  ",
            ui::addr((start_address + ((i * mode.bytes_per_row) as u64)).0)
        );

        let items_per_row = mode.bytes_per_row / mode.item_size;
        let mut printed = 0;

        for item in chunk.chunks(mode.item_size) {
            match mode.item_format {
                ItemFormat::Bytes => {
                    print!("{:02x} ", item[0]);
                }
                ItemFormat::Dwords => {
                    if item.len() == 4 {
                        let val = u32::from_le_bytes([item[0], item[1], item[2], item[3]]);
                        print!("{:08x} ", val);
                    } else {
                        for byte in item {
                            print!("{:02x}", byte);
                        }
                        print!("   ");
                    }
                }
                ItemFormat::Qwords => {
                    if item.len() == 8 {
                        let val = u64::from_le_bytes([
                            item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7],
                        ]);
                        print!("{:016x} ", val);
                    } else {
                        for byte in item {
                            print!("{:02x}", byte);
                        }
                        print!("   ");
                    }
                }
            }
            printed += 1;
        }

        // pad remaining items if needed
        for _ in printed..items_per_row {
            match mode.item_format {
                ItemFormat::Bytes => print!("   "),
                ItemFormat::Dwords => print!("         "),
                ItemFormat::Qwords => print!("                 "),
            }
        }

        if mode.show_ascii {
            print!(" ");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    print!("{}", *byte as char);
                } else {
                    print!("{}", ".".bright_black());
                }
            }
        }

        println!();
    }

    println!();
}
