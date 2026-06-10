use std::collections::HashMap;

use crate::error::{Error, Result};

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

    pub fn parse_target_xml(xml: &str) -> Self {
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

    pub fn extract_attr<'a>(element: &'a str, attr: &str) -> Option<&'a str> {
        let pattern = format!("{}=\"", attr);
        let start = element.find(&pattern)?;
        let value_start = start + pattern.len();
        let rest = &element[value_start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::RegisterMap;

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
}
