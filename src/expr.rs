use crate::backend::MemoryOps;
use crate::debugger::DebuggerContext;
use crate::error::{Error, Result};
use crate::symbols::SymbolStore;
use crate::types::{Dtb, VirtAddr};

#[derive(Debug, Clone, PartialEq)]
pub enum ExprType {
    /// primitive types
    Byte,
    Word,
    Dword,
    Qword,
    /// struct/union type by name
    Struct(String),
    /// pointer to a type
    Pointer(Box<ExprType>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(VirtAddr),
    Symbol(String),
    /// `$rax`, `$rip`, etc
    Register(String),
    /// `*expr`
    Deref(Box<Expr>),
    /// `expr->field`
    FieldAccess(Box<Expr>, String),
    /// `expr[index]`
    Index(Box<Expr>, u64),
    Add(Box<Expr>, u64),
    Sub(Box<Expr>, u64),
    /// `(TYPE)expr` or `(TYPE*)expr`
    Cast(Box<Expr>, ExprType),
}

impl Expr {
    pub fn eval(input: &str, context: &DebuggerContext) -> Result<VirtAddr> {
        Self::parse(input)?.resolve(context)
    }

    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(Error::InvalidExpression("empty expression".into()));
        }
        let (expr, suffix) = Self::parse_base_with_suffix(input)?;
        if suffix.is_empty() {
            Ok(expr)
        } else {
            Self::parse_suffix(expr, suffix)
        }
    }

    fn split_parens(input: &str) -> Result<(&str, &str)> {
        let mut depth = 0;
        for (i, c) in input.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        let inner = &input[1..i];
                        let rest = input[i + 1..].trim();
                        return Ok((inner, rest));
                    }
                }
                _ => {}
            }
        }
        Err(Error::InvalidExpression("unmatched parentheses".into()))
    }

    /// check if a string looks like a valid type name for casting
    fn is_type_name(s: &str) -> bool {
        let s = s.trim().trim_end_matches('*').trim();
        !s.is_empty()
            && s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    fn parse_base_with_suffix(input: &str) -> Result<(Expr, String)> {
        let input = input.trim();

        if input.starts_with('(') {
            let (inner, rest) = Self::split_parens(input)?;

            // try as cast: (TYPE)expr — must have a valid type name and something after
            if !rest.is_empty() && Self::is_type_name(inner) {
                let expr_type = Self::parse_type(inner)?;
                let (base_expr, suffix) = Self::parse_base_with_suffix(rest)?;
                let cast_expr = Expr::Cast(Box::new(base_expr), expr_type);
                if suffix.is_empty() {
                    return Ok((cast_expr, String::new()));
                }
                return Ok((Self::parse_suffix(cast_expr, suffix)?, String::new()));
            }

            // otherwise it's grouping: (expr)
            let expr = Self::parse(inner)?;
            return Ok((expr, rest.to_string()));
        }
        
        if input.starts_with('*') {
            let (inner, suffix) = Self::parse_base_with_suffix(input[1..].trim())?;
            return Ok((Expr::Deref(Box::new(inner)), suffix));
        }

        if input.starts_with('$') {
            let name_end = input[1..].find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .map(|i| i + 1)
                .unwrap_or(input.len());
            let reg_name = &input[1..name_end];
            if reg_name.is_empty() {
                return Err(Error::InvalidExpression("empty register name".into()));
            }
            let suffix = input[name_end..].trim().to_string();
            return Ok((Expr::Register(reg_name.to_string()), suffix));
        }

        if Self::is_numeric(input) {
            let (value, remaining) = Self::parse_value(input)?;
            return Ok((Expr::Literal(VirtAddr(value)), remaining));
        }

        let suffix_start = Self::find_suffix_start(input);
        if suffix_start > 0 {
            let symbol_name = input[..suffix_start].trim();
            let suffix = input[suffix_start..].trim().to_string();
            Ok((Expr::Symbol(symbol_name.to_string()), suffix))
        } else {
            Ok((Expr::Symbol(input.to_string()), String::new()))
        }
    }

    fn find_suffix_start(input: &str) -> usize {
        input.find(['+', '-', '[']).unwrap_or(0)
    }

    fn parse_type(type_str: &str) -> Result<ExprType> {
        let type_str = type_str.trim();
        
        if type_str.ends_with('*') {
            let inner_type = Self::parse_type(&type_str[..type_str.len() - 1])?;
            return Ok(ExprType::Pointer(Box::new(inner_type)));
        }

        match type_str.to_lowercase().as_str() {
            "byte" | "u8" | "uchar" | "char" | "boolean" | "uint8_t" | "int8_t" => Ok(ExprType::Byte),
            "word" | "u16" | "ushort" | "short" | "wchar" | "uint16_t" | "int16_t" => Ok(ExprType::Word),
            "dword" | "u32" | "ulong" | "long" | "uint" | "int" | "uint32_t" | "int32_t" => Ok(ExprType::Dword),
            "qword" | "u64" | "dword64" | "ulong64" | "longlong" | "ulonglong"
                | "pvoid" | "size_t" | "uint64_t" | "int64_t" | "usize" => Ok(ExprType::Qword),
            _ => Ok(ExprType::Struct(type_str.to_string())),
        }
    }

    fn parse_suffix(expr: Expr, rest: String) -> Result<Expr> {
        let rest = rest.trim();

        if rest.is_empty() {
            return Ok(expr);
        }

        // field access
        if rest.starts_with("->") {
            let rest = rest.trim_start_matches("->").trim_start();
            let field_end = rest.find(|c: char| c == '+' || c == '-' || c == '[' || c.is_whitespace())
                .unwrap_or(rest.len());
            let field_name = rest[..field_end].trim().to_string();
            let remaining = rest[field_end..].trim().to_string();
            let result = Expr::FieldAccess(Box::new(expr), field_name);
            return Self::parse_suffix(result, remaining);
        }

        // array
        if rest.starts_with('[') {
            let close = rest.find(']')
                .ok_or_else(|| Error::InvalidExpression("unmatched '['".into()))?;
            let index_str = rest[1..close].trim();
            let (index, _) = Self::parse_value(index_str)?;
            let remaining = rest[close + 1..].trim().to_string();
            let result = Expr::Index(Box::new(expr), index);
            return Self::parse_suffix(result, remaining);
        }

        if rest.starts_with('+') {
            let rest = rest.trim_start_matches('+').trim();
            let (value, remaining) = Self::parse_value(rest)?;
            let result = Expr::Add(Box::new(expr), value);
            return Self::parse_suffix(result, remaining);
        }

        if rest.starts_with('-') {
            let rest = rest.trim_start_matches('-').trim();
            let (value, remaining) = Self::parse_value(rest)?;
            let result = Expr::Sub(Box::new(expr), value);
            return Self::parse_suffix(result, remaining);
        }

        Err(Error::InvalidExpression(format!("unexpected token: {}", rest)))
    }

    fn parse_value(s: &str) -> Result<(u64, String)> {
        let s = s.trim();
        
        let end = s.find(|c: char| c.is_whitespace() || c == ')' || c == '+' || c == '-').unwrap_or(s.len());
        let value_str = &s[..end];
        let remaining = s[end..].trim().to_string();

        let value = if value_str.starts_with("0x") || value_str.starts_with("0X") {
            u64::from_str_radix(&value_str[2..], 16)
                .map_err(|_| Error::InvalidExpression(format!("invalid hex value: {}", value_str)))?
        } else if value_str.starts_with("0b") || value_str.starts_with("0B") {
            u64::from_str_radix(&value_str[2..], 2)
                .map_err(|_| Error::InvalidExpression(format!("invalid binary value: {}", value_str)))?
        } else {
            value_str.parse::<u64>()
                .map_err(|_| Error::InvalidExpression(format!("invalid numeric value: {}", value_str)))?
        };

        Ok((value, remaining))
    }

    fn is_numeric(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        if s.starts_with("0x") || s.starts_with("0X") {
            s.len() > 2 && s[2..].chars().all(|c| c.is_ascii_hexdigit())
        } else if s.starts_with("0b") || s.starts_with("0B") {
            s.len() > 2 && s[2..].chars().all(|c| c == '0' || c == '1')
        } else {
            s.chars().all(|c| c.is_ascii_digit())
        }
    }

    pub fn resolve(&self, context: &DebuggerContext) -> Result<VirtAddr> {
        match self {
            Expr::Literal(addr) => Ok(*addr),
            
            Expr::Symbol(name) => {
                let addr = context.symbols.find_symbol_across_modules(context.current_dtb(), name)
                    .ok_or_else(|| Error::SymbolNotFound(name.clone()))?;
                Ok(addr)
            }

            Expr::Register(name) => {
                let regs = context.registers.as_ref()
                    .ok_or_else(|| Error::InvalidExpression("registers unavailable while VM is running".into()))?;
                let value = regs.get(name)
                    .ok_or_else(|| Error::RegisterNotFound(name.clone()))?;
                Ok(VirtAddr(*value))
            }

            Expr::Deref(inner) => {
                let addr = inner.resolve(context)?;
                let mem = context.get_current_process().memory(&context.kvm);
                let val: u64 = mem.read(addr)?;
                Ok(VirtAddr(val))
            }

            Expr::FieldAccess(base, field_name) => {
                let base_addr = base.resolve(context)?;

                let base_type_name = base.resolve_type(&context.symbols, context.current_dtb())
                    .ok_or_else(|| Error::InvalidExpression(
                        "field access requires explicit cast: e.g., (TYPE)expr->field".into()
                    ))?;

                let type_info = context.symbols.find_type_across_modules(context.current_dtb(), &base_type_name)
                    .ok_or_else(|| Error::StructNotFound(base_type_name))?;

                let offset = type_info.try_get_field_offset(field_name)
                    .map_err(|_| Error::FieldNotFound(field_name.clone()))?;
                Ok(base_addr + offset)
            }

            Expr::Index(base, index) => {
                let base_addr = base.resolve(context)?;
                let elem_size = Self::resolve_element_size(base, context);
                Ok(base_addr + index * elem_size)
            }

            Expr::Add(inner, value) => {
                let base = inner.resolve(context)?;
                Ok(base + *value)
            }

            Expr::Sub(inner, value) => {
                let base = inner.resolve(context)?;
                Ok(base - *value)
            }

            Expr::Cast(expr, _) => {
                expr.resolve(context)
            }
        }
    }

    pub fn resolve_type(&self, symbols: &SymbolStore, dtb: Dtb) -> Option<String> {
        match self {
            Expr::Cast(_, expr_type) => Some(Self::expr_type_to_name(expr_type)),
            Expr::FieldAccess(base, field_name) => {
                let base_type_name = base.resolve_type(symbols, dtb)?;
                let type_info = symbols.find_type_across_modules(dtb, &base_type_name)?;
                let field_info = type_info.fields.get(field_name)?;
                Self::get_struct_type_name(&field_info.type_data)
            }
            _ => None,
        }
    }

    /// Return field names matching a prefix for the type this expression resolves to.
    pub fn complete_fields(&self, symbols: &SymbolStore, dtb: Dtb, prefix: &str) -> Vec<String> {
        let type_name = match self.resolve_type(symbols, dtb) {
            Some(name) => name,
            None => return vec![],
        };
        let type_info = match symbols.find_type_across_modules(dtb, &type_name) {
            Some(info) => info,
            None => return vec![],
        };
        let mut fields: Vec<String> = type_info.fields.keys()
            .filter(|f| f.starts_with(prefix))
            .cloned()
            .collect();
        fields.sort();
        fields
    }

    /// determine the element size in bytes for array indexing
    /// uses type info from casts (e.g. `(dword*)addr[3]` → 4 bytes per element)
    /// falls back to 1 if no type info is available
    fn resolve_element_size(expr: &Expr, context: &DebuggerContext) -> u64 {
        match expr {
            Expr::Cast(_, expr_type) => Self::expr_type_size(expr_type, context),
            _ => 1,
        }
    }

    fn expr_type_size(expr_type: &ExprType, context: &DebuggerContext) -> u64 {
        match expr_type {
            ExprType::Byte => 1,
            ExprType::Word => 2,
            ExprType::Dword => 4,
            ExprType::Qword => 8,
            ExprType::Pointer(_) => 8,
            ExprType::Struct(name) => {
                let lookup = if name.starts_with('_') { name.clone() } else { format!("_{name}") };
                context.symbols.find_type_across_modules(context.current_dtb(), &lookup)
                    .map(|t| t.size as u64)
                    .unwrap_or(1)
            }
        }
    }

    fn expr_type_to_name(expr_type: &ExprType) -> String {
        match expr_type {
            ExprType::Byte => "byte".to_string(),
            ExprType::Word => "word".to_string(),
            ExprType::Dword => "dword".to_string(),
            ExprType::Qword => "qword".to_string(),
            ExprType::Struct(name) => {
                if name.starts_with('_') {
                    name.clone()
                } else {
                    format!("_{name}")
                }
            }
            ExprType::Pointer(inner) => Self::expr_type_to_name(inner),
        }
    }

    fn get_struct_type_name(type_data: &crate::symbols::ParsedType) -> Option<String> {
        use crate::symbols::ParsedType;
        match type_data {
            ParsedType::Struct(name) | ParsedType::Union(name) => Some(name.clone()),
            ParsedType::Pointer(inner) => Self::get_struct_type_name(inner),
            ParsedType::Array(inner, _) => Self::get_struct_type_name(inner),
            _ => None,
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_symbol() {
        let expr = Expr::parse("PsInitialSystemProcess").unwrap();
        assert_eq!(expr, Expr::Symbol("PsInitialSystemProcess".to_string()));
    }

    #[test]
    fn test_parse_literal() {
        let expr = Expr::parse("0xfffff80123456789").unwrap();
        assert_eq!(expr, Expr::Literal(VirtAddr(0xfffff80123456789)));
    }

    #[test]
    fn test_parse_deref() {
        let expr = Expr::parse("*PsInitialSystemProcess").unwrap();
        assert_eq!(expr, Expr::Deref(Box::new(Expr::Symbol("PsInitialSystemProcess".to_string()))));
    }

    #[test]
    fn test_parse_addition() {
        let expr = Expr::parse("PsInitialSystemProcess + 0x20").unwrap();
        assert_eq!(expr, Expr::Add(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            0x20
        ));
    }

    #[test]
    fn test_parse_parentheses() {
        let expr = Expr::parse("(PsInitialSystemProcess + 0x20)").unwrap();
        assert_eq!(expr, Expr::Add(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            0x20
        ));
    }

    #[test]
    fn test_parse_complex() {
        let expr = Expr::parse("*PsInitialSystemProcess + 8").unwrap();
        assert_eq!(expr, Expr::Add(
            Box::new(Expr::Deref(Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())))),
            8
        ));
    }

    #[test]
    fn test_parse_field_access() {
        let expr = Expr::parse("PsInitialSystemProcess->Token").unwrap();
        assert_eq!(expr, Expr::FieldAccess(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            "Token".to_string()
        ));
    }

    #[test]
    fn test_parse_cast_primitive() {
        let expr = Expr::parse("(dword)0x12345678").unwrap();
        assert_eq!(expr, Expr::Cast(
            Box::new(Expr::Literal(VirtAddr(0x12345678))),
            ExprType::Dword
        ));
    }

    #[test]
    fn test_parse_cast_struct() {
        let expr = Expr::parse("(EPROCESS)PsInitialSystemProcess").unwrap();
        assert_eq!(expr, Expr::Cast(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            ExprType::Struct("EPROCESS".to_string())
        ));
    }

    #[test]
    fn test_parse_cast_pointer() {
        let expr = Expr::parse("(EPROCESS*)addr").unwrap();
        assert_eq!(expr, Expr::Cast(
            Box::new(Expr::Symbol("addr".to_string())),
            ExprType::Pointer(Box::new(ExprType::Struct("EPROCESS".to_string())))
        ));
    }

    #[test]
    fn test_parse_cast_with_field_access() {
        let expr = Expr::parse("(EPROCESS)PsInitialSystemProcess->Token").unwrap();
        assert_eq!(expr, Expr::FieldAccess(
            Box::new(Expr::Cast(
                Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
                ExprType::Struct("EPROCESS".to_string())
            )),
            "Token".to_string()
        ));
    }

    #[test]
    fn test_parse_nested_field_access() {
        let expr = Expr::parse("(EPROCESS)PsInitialSystemProcess->Token->Value").unwrap();
        // should parse as FieldAccess(FieldAccess(Cast(Symbol, EPROCESS), Token), Value)
        if let Expr::FieldAccess(inner, field2) = &expr {
            assert_eq!(field2, "Value");
            if let Expr::FieldAccess(inner2, field1) = inner.as_ref() {
                assert_eq!(field1, "Token");
                if let Expr::Cast(_, expr_type) = inner2.as_ref() {
                    assert!(matches!(expr_type, ExprType::Struct(name) if name == "EPROCESS"));
                } else {
                    panic!("Expected Cast");
                }
            } else {
                panic!("Expected FieldAccess");
            }
        } else {
            panic!("Expected FieldAccess");
        }
    }

    #[test]
    fn test_parse_deref_with_cast() {
        let expr = Expr::parse("*(dword)addr").unwrap();
        assert_eq!(expr, Expr::Deref(
            Box::new(Expr::Cast(
                Box::new(Expr::Symbol("addr".to_string())),
                ExprType::Dword
            ))
        ));
    }

    #[test]
    fn test_parse_cast_with_arithmetic() {
        let expr = Expr::parse("(qword)(addr + 0x10)").unwrap();
        assert_eq!(expr, Expr::Cast(
            Box::new(Expr::Add(
                Box::new(Expr::Symbol("addr".to_string())),
                0x10
            )),
            ExprType::Qword
        ));
    }

    #[test]
    fn test_parse_cast_pointer_with_literal_and_field() {
        let expr = Expr::parse("(EPROCESS*)(0xffffe70c61240080)->Token").unwrap();
        // should parse as FieldAccess(Cast(Literal(addr), Pointer(EPROCESS)), "Token")
        if let Expr::FieldAccess(inner, field) = &expr {
            assert_eq!(field, "Token");
            if let Expr::Cast(inner2, expr_type) = inner.as_ref() {
                if let ExprType::Pointer(inner_type) = expr_type {
                    if let ExprType::Struct(name) = inner_type.as_ref() {
                        assert_eq!(name, "EPROCESS");
                    } else {
                        panic!("Expected Struct");
                    }
                } else {
                    panic!("Expected Pointer");
                }
                if let Expr::Literal(addr) = inner2.as_ref() {
                    assert_eq!(addr.0, 0xffffe70c61240080);
                } else {
                    panic!("Expected Literal, got {:?}", inner2);
                }
            } else {
                panic!("Expected Cast, got {:?}", inner);
            }
        } else {
            panic!("Expected FieldAccess, got {:?}", expr);
        }
    }

    #[test]
    fn test_parse_cast_struct_with_literal_and_field() {
        let expr = Expr::parse("(EPROCESS)(0xffffe70c61240080)->Token").unwrap();
        // should parse as FieldAccess(Cast(Literal(addr), EPROCESS), "Token")
        if let Expr::FieldAccess(inner, field) = &expr {
            assert_eq!(field, "Token");
            if let Expr::Cast(inner2, expr_type) = inner.as_ref() {
                if let ExprType::Struct(name) = expr_type {
                    assert_eq!(name, "EPROCESS");
                } else {
                    panic!("Expected Struct");
                }
                if let Expr::Literal(addr) = inner2.as_ref() {
                    assert_eq!(addr.0, 0xffffe70c61240080);
                } else {
                    panic!("Expected Literal, got {:?}", inner2);
                }
            } else {
                panic!("Expected Cast, got {:?}", inner);
            }
        } else {
            panic!("Expected FieldAccess, got {:?}", expr);
        }
    }

    #[test]
    fn test_parse_grouped_deref() {
        // *(sym + 0x10) should parse as Deref(Add(Symbol, 0x10))
        let expr = Expr::parse("*(PsInitialSystemProcess + 0x10)").unwrap();
        assert_eq!(expr, Expr::Deref(Box::new(Expr::Add(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            0x10
        ))));
    }

    #[test]
    fn test_parse_grouped_deref_with_field() {
        // *(EPROCESS)(*sym)->Token should parse correctly
        let expr = Expr::parse("(_EPROCESS)(*PsInitialSystemProcess)->Token").unwrap();
        if let Expr::FieldAccess(inner, field) = &expr {
            assert_eq!(field, "Token");
            if let Expr::Cast(inner2, _) = inner.as_ref() {
                assert!(matches!(inner2.as_ref(), Expr::Deref(_)));
            } else {
                panic!("Expected Cast, got {:?}", inner);
            }
        } else {
            panic!("Expected FieldAccess, got {:?}", expr);
        }
    }

    #[test]
    fn test_parse_index() {
        let expr = Expr::parse("addr[3]").unwrap();
        assert_eq!(expr, Expr::Index(
            Box::new(Expr::Symbol("addr".to_string())),
            3
        ));
    }

    #[test]
    fn test_parse_index_hex() {
        let expr = Expr::parse("addr[0x10]").unwrap();
        assert_eq!(expr, Expr::Index(
            Box::new(Expr::Symbol("addr".to_string())),
            0x10
        ));
    }

    #[test]
    fn test_parse_field_then_index() {
        // (TYPE)addr->field[2] should parse as Index(FieldAccess(Cast(...), field), 2)
        let expr = Expr::parse("(EPROCESS)addr->field[2]").unwrap();
        if let Expr::Index(inner, index) = &expr {
            assert_eq!(*index, 2);
            assert!(matches!(inner.as_ref(), Expr::FieldAccess(_, _)));
        } else {
            panic!("Expected Index, got {:?}", expr);
        }
    }

    #[test]
    fn test_parse_register() {
        let expr = Expr::parse("$rax").unwrap();
        assert_eq!(expr, Expr::Register("rax".to_string()));
    }

    #[test]
    fn test_parse_register_with_arithmetic() {
        let expr = Expr::parse("$rsp+0x10").unwrap();
        assert_eq!(expr, Expr::Add(
            Box::new(Expr::Register("rsp".to_string())),
            0x10
        ));
    }

    #[test]
    fn test_parse_deref_register() {
        let expr = Expr::parse("*$rsp").unwrap();
        assert_eq!(expr, Expr::Deref(Box::new(Expr::Register("rsp".to_string()))));
    }

}
