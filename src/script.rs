//! Lua scripting for user-defined REPL commands.
//!
//! Scripts in `$XDG_CONFIG_HOME/ntoseye/commands/*.lua` are auto-loaded at
//! REPL startup and register named commands via `register_command(name, help, fn)`.
//! Registered commands appear in tab completion and dispatch like builtins.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mlua::{
    FromLua, Function, Lua, LuaOptions, MetaMethod, MultiValue, RegistryKey, StdLib, Table,
    UserData, UserDataMethods, Value, Variadic,
};
use sha2::{Digest, Sha256};

use crate::backend::MemoryOps;
use crate::dbg_backend::DebugBackend;
use crate::debugger::{DebuggerContext, DriverObjectInfo};
use crate::diagnostics;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::gdb::RegisterMap;
use crate::guest::{ModuleInfo, ProcessInfo};
use crate::repl::CompletionStrategy;
use crate::symbols::{ParsedType, SymbolStore, TypeInfo, cache_root};
use crate::types::{Dtb, VirtAddr};

/// Wraps a 64-bit address. Exposed to Lua as userdata so pointer math stays
/// unsigned and tostring renders in hex; raw Lua integers are signed i64 in 5.4
/// and would print kernel addresses as negatives.
#[derive(Copy, Clone)]
pub struct Address(pub u64);

impl UserData for Address {
    fn add_methods<M: UserDataMethods<Self>>(m: &mut M) {
        m.add_meta_method(MetaMethod::ToString, |_, a, ()| Ok(format!("{:#x}", a.0)));
        m.add_meta_method(MetaMethod::Eq, |_, a, b: Address| Ok(a.0 == b.0));
        m.add_meta_method(MetaMethod::Lt, |_, a, b: Address| Ok(a.0 < b.0));
        m.add_meta_method(MetaMethod::Le, |_, a, b: Address| Ok(a.0 <= b.0));
        m.add_meta_method(MetaMethod::Add, |_, a, b: AddrOrInt| {
            Ok(Address(a.0.wrapping_add(b.value)))
        });
        m.add_meta_method(MetaMethod::Sub, |lua, a, b: AddrOrInt| {
            let v = a.0.wrapping_sub(b.value);
            if b.is_address {
                Ok(Value::Integer(v as i64))
            } else {
                Ok(Value::UserData(lua.create_userdata(Address(v))?))
            }
        });
        m.add_meta_method(MetaMethod::BAnd, |_, a, b: AddrOrInt| {
            Ok(Address(a.0 & b.value))
        });
        m.add_meta_method(MetaMethod::BOr, |_, a, b: AddrOrInt| {
            Ok(Address(a.0 | b.value))
        });
        m.add_meta_method(MetaMethod::BXor, |_, a, b: AddrOrInt| {
            Ok(Address(a.0 ^ b.value))
        });
        m.add_meta_method(MetaMethod::Shl, |_, a, b: i64| {
            Ok(Address(a.0.wrapping_shl(b as u32)))
        });
        m.add_meta_method(MetaMethod::Shr, |_, a, b: i64| {
            Ok(Address(a.0.wrapping_shr(b as u32)))
        });

        m.add_method("to_int", |_, a, ()| Ok(a.0 as i64));
        m.add_method("to_hex", |_, a, ()| Ok(format!("{:#x}", a.0)));
    }
}

/// `Address | integer` coercion for metamethod arguments.
struct AddrOrInt {
    value: u64,
    is_address: bool,
}

impl FromLua for AddrOrInt {
    fn from_lua(value: Value, _: &Lua) -> mlua::Result<Self> {
        match value {
            Value::Integer(i) => Ok(AddrOrInt {
                value: i as u64,
                is_address: false,
            }),
            Value::Number(n) => number_to_u64(n).map(|value| AddrOrInt {
                value,
                is_address: false,
            }),
            Value::UserData(ud) => ud.borrow::<Address>().map(|a| AddrOrInt {
                value: a.0,
                is_address: true,
            }),
            _ => Err(mlua::Error::FromLuaConversionError {
                from: value.type_name(),
                to: "Address|integer".to_string(),
                message: None,
            }),
        }
    }
}

impl FromLua for Address {
    fn from_lua(value: Value, _: &Lua) -> mlua::Result<Self> {
        match value {
            Value::Integer(i) => Ok(Address(i as u64)),
            Value::Number(n) => number_to_u64(n).map(Address),
            Value::UserData(ud) => ud.borrow::<Address>().map(|a| *a),
            _ => Err(mlua::Error::FromLuaConversionError {
                from: value.type_name(),
                to: "Address".to_string(),
                message: None,
            }),
        }
    }
}

/// Decode one struct field from a buffer slice. Strategy:
///   - pointers -> Address userdata
///   - 1/2/4-byte primitives and enums -> Lua integer
///   - 8-byte primitives -> Address userdata to preserve unsigned values
///   - bitfields -> integer extracted from the underlying word
///   - everything else (nested structs, unions, arrays, unknown) -> Lua string
///     of raw bytes; callers can decode nested types explicitly via the host
///     read helpers using offset_of (avoids surprise allocation in hot loops)
fn decode_address(lua: &Lua, slice: &[u8]) -> mlua::Result<Value> {
    let v = u64::from_le_bytes(slice[..8].try_into().unwrap());
    Ok(Value::UserData(lua.create_userdata(Address(v))?))
}

fn decode_field(
    lua: &Lua,
    ty: &ParsedType,
    size: usize,
    buf: &[u8],
    off: usize,
) -> mlua::Result<Value> {
    let end = off.saturating_add(size);
    if end > buf.len() {
        return Ok(Value::Nil);
    }
    let slice = &buf[off..end];

    match ty {
        ParsedType::Pointer(_) => decode_address(lua, slice),
        ParsedType::Primitive(_) | ParsedType::Enum(_) => match slice.len() {
            1 => Ok(Value::Integer(slice[0] as i64)),
            2 => Ok(Value::Integer(
                u16::from_le_bytes(slice.try_into().unwrap()) as i64,
            )),
            4 => Ok(Value::Integer(
                u32::from_le_bytes(slice.try_into().unwrap()) as i64,
            )),
            8 => {
                let v = u64::from_le_bytes(slice.try_into().unwrap());
                Ok(Value::UserData(lua.create_userdata(Address(v))?))
            }
            _ => Ok(Value::String(lua.create_string(slice)?)),
        },
        ParsedType::Bitfield {
            underlying,
            pos,
            len,
        } => {
            // Read up to 8 bytes of the underlying word, mask out the bits
            let take = size.min(8);
            let mut padded = [0u8; 8];
            padded[..take].copy_from_slice(&slice[..take]);
            let word = u64::from_le_bytes(padded);
            let mask = if *len >= 64 {
                u64::MAX
            } else {
                (1u64 << *len) - 1
            };
            let v = (word >> *pos) & mask;
            // Underlying type only affects sign semantics, which we don't model;
            // return as unsigned. Reference to silence unused warning
            let _ = underlying;
            Ok(Value::Integer(v as i64))
        }
        _ => Ok(Value::String(lua.create_string(slice)?)),
    }
}

fn number_to_u64(n: f64) -> mlua::Result<u64> {
    if n.is_finite() && n >= 0.0 && n <= ((1u64 << 53) - 1) as f64 && n.fract() == 0.0 {
        Ok(n as u64)
    } else {
        Err(mlua::Error::FromLuaConversionError {
            from: "number",
            to: "Address|integer".to_string(),
            message: Some("expected a non-negative integer without precision loss".to_string()),
        })
    }
}

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&w| w != 0),
    )
    .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect()
}

fn read_memory_exact(
    debugger: &DebuggerContext,
    addr: Address,
    buf: &mut [u8],
) -> mlua::Result<()> {
    debugger
        .current_process()
        .memory()
        .read_bytes(VirtAddr(addr.0), buf)
        .map_err(mlua::Error::external)
}

fn write_memory_exact(debugger: &DebuggerContext, addr: Address, bytes: &[u8]) -> mlua::Result<()> {
    debugger
        .current_process()
        .memory()
        .write_bytes(VirtAddr(addr.0), bytes)
        .map_err(mlua::Error::external)
}

fn read_array<const N: usize>(debugger: &DebuggerContext, addr: Address) -> mlua::Result<[u8; N]> {
    let mut buf = [0u8; N];
    read_memory_exact(debugger, addr, &mut buf)?;
    Ok(buf)
}

fn read_vec(debugger: &DebuggerContext, addr: Address, len: usize) -> mlua::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    read_memory_exact(debugger, addr, &mut buf)?;
    Ok(buf)
}

fn field_address(
    debugger: &DebuggerContext,
    ty: &str,
    field: &str,
    base: Address,
) -> mlua::Result<Address> {
    let ti = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), ty)
        .ok_or_else(|| mlua::Error::external(format!("unknown type: {}", ty)))?;
    let offset = ti.field_offset(field).map_err(mlua::Error::external)?;
    Ok(Address(base.0.wrapping_add(offset)))
}

fn fields_table(lua: &Lua, ti: &TypeInfo) -> mlua::Result<Table> {
    let mut entries: Vec<_> = ti.fields.iter().collect();
    entries.sort_by_key(|(_, f)| f.offset);

    let out = lua.create_table()?;
    for (i, (name, f)) in entries.into_iter().enumerate() {
        let row = lua.create_table()?;
        row.set("name", name.as_str())?;
        row.set("offset", f.offset as i64)?;
        row.set("size", f.size as i64)?;
        row.set("type", format!("{}", f.type_data))?;
        if let ParsedType::Bitfield { pos, len, .. } = &f.type_data {
            row.set("bit_pos", *pos as i64)?;
            row.set("bit_len", *len as i64)?;
        }
        out.set((i + 1) as i64, row)?;
    }
    Ok(out)
}

fn match_processes(d: &DebuggerContext, target: &str) -> Result<Vec<ProcessInfo>> {
    let procs = d.guest.enumerate_processes()?;
    Ok(if let Ok(pid) = target.parse::<u64>() {
        procs.into_iter().filter(|p| p.pid == pid).collect()
    } else {
        let target_l = target.to_lowercase();
        procs
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&target_l))
            .collect()
    })
}

fn process_row(lua: &Lua, p: &ProcessInfo) -> mlua::Result<Table> {
    let row = lua.create_table()?;
    row.set("pid", p.pid as i64)?;
    row.set("name", p.name.as_str())?;
    row.set("eprocess", Address(p.eprocess_va.0))?;
    Ok(row)
}

fn module_table(lua: &Lua, m: &ModuleInfo) -> mlua::Result<Table> {
    let out = lua.create_table()?;
    out.set("name", m.name.as_str())?;
    out.set("short_name", m.short_name.as_str())?;
    out.set("base", Address(m.base_address.0))?;
    out.set("size", m.size as i64)?;
    out.set("end", Address(m.end_address().0))?;
    Ok(out)
}

fn driver_object_table(lua: &Lua, driver: &DriverObjectInfo) -> mlua::Result<Table> {
    let out = lua.create_table()?;
    out.set("name", driver.name.as_str())?;
    out.set("object", Address(driver.object.0))?;
    out.set("driver_start", Address(driver.driver_start.0))?;
    out.set("driver_size", driver.driver_size as i64)?;
    out.set("device_object", Address(driver.device_object.0))?;
    out.set("driver_unload", Address(driver.driver_unload.0))?;
    Ok(out)
}

fn struct_table(lua: &Lua, ti: &TypeInfo, addr: Address, buf: &[u8]) -> mlua::Result<Table> {
    let out = lua.create_table()?;
    out.set("__addr", addr)?;
    out.set("__size", ti.size as i64)?;
    out.set("__type", ti.name.as_str())?;

    for (name, f) in ti.fields.iter() {
        let value = decode_field(lua, &f.type_data, f.size as usize, buf, f.offset as usize)?;
        out.set(name.as_str(), value)?;
    }
    Ok(out)
}

fn install_metadata_ntos(
    lua: &Lua,
    ntos: &Table,
    symbols: Arc<SymbolStore>,
    dtb: Dtb,
) -> mlua::Result<()> {
    ntos.set("type_size", {
        let symbols = Arc::clone(&symbols);
        lua.create_function(move |_, ty: String| {
            symbols
                .find_type_across_modules(dtb, &ty)
                .map(|ti| ti.size as i64)
                .ok_or_else(|| mlua::Error::external(format!("unknown type: {}", ty)))
        })?
    })?;

    ntos.set("offset_of", {
        let symbols = Arc::clone(&symbols);
        lua.create_function(move |_, (ty, field): (String, String)| {
            let ti = symbols
                .find_type_across_modules(dtb, &ty)
                .ok_or_else(|| mlua::Error::external(format!("unknown type: {}", ty)))?;
            ti.field_offset(&field)
                .map(|o| o as i64)
                .map_err(mlua::Error::external)
        })?
    })?;

    ntos.set("try_type_size", {
        let symbols = Arc::clone(&symbols);
        lua.create_function(move |_, ty: String| {
            Ok(symbols
                .find_type_across_modules(dtb, &ty)
                .map(|ti| ti.size as i64))
        })?
    })?;

    ntos.set("try_offset_of", {
        let symbols = Arc::clone(&symbols);
        lua.create_function(move |_, (ty, field): (String, String)| {
            let Some(ti) = symbols.find_type_across_modules(dtb, &ty) else {
                return Ok(None);
            };
            Ok(ti.field_offset(&field).ok().map(|o| o as i64))
        })?
    })?;

    ntos.set("fields_of", {
        let symbols = Arc::clone(&symbols);
        lua.create_function(move |lua, ty: String| {
            let ti = symbols
                .find_type_across_modules(dtb, &ty)
                .ok_or_else(|| mlua::Error::external(format!("unknown type: {}", ty)))?;
            fields_table(lua, &ti)
        })?
    })?;

    ntos.set(
        "try_fields_of",
        lua.create_function(move |lua, ty: String| {
            let Some(ti) = symbols.find_type_across_modules(dtb, &ty) else {
                return Ok(None);
            };
            fields_table(lua, &ti).map(Some)
        })?,
    )?;

    Ok(())
}

struct Registered {
    help: String,
    callback: RegistryKey,
    strategies: Vec<CompletionStrategy>,
}

pub struct ScriptHost {
    lua: Lua,
    commands: HashMap<String, Registered>,
}

pub struct LoadReport {
    pub loaded: Vec<String>,
    pub failed: Vec<(PathBuf, String)>,
}

impl ScriptHost {
    pub fn new() -> Self {
        let libs = StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8;
        Self {
            lua: Lua::new_with(libs, LuaOptions::default())
                .expect("failed to create Lua scripting runtime"),
            commands: HashMap::new(),
        }
    }

    pub fn command_names(&self) -> Vec<(String, String, Vec<CompletionStrategy>)> {
        let mut commands: Vec<_> = self
            .commands
            .iter()
            .map(|(n, r)| (n.clone(), r.help.clone(), r.strategies.clone()))
            .collect();
        commands.sort_by(|a, b| a.0.cmp(&b.0));
        commands
    }

    pub fn has(&self, name: &str) -> bool {
        self.commands.contains_key(name)
    }

    /// Drop all registered commands and reset the Lua runtime to a clean state;
    /// Used by `reload` to pick up edits without restarting the REPL
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Auto-load every `.lua` file in `$XDG_CONFIG_HOME/ntoseye/commands/`
    pub fn load_all(
        &mut self,
        builtin_names: &HashSet<String>,
        debugger: Option<&DebuggerContext>,
    ) -> LoadReport {
        let mut report = LoadReport {
            loaded: Vec::new(),
            failed: Vec::new(),
        };

        let Some(dir) = scripts_dir() else {
            return report;
        };
        if !dir.exists() {
            let _ = std::fs::create_dir_all(&dir);
            return report;
        }

        let mut entries: Vec<PathBuf> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("lua"))
                .collect(),
            Err(_) => return report,
        };
        entries.sort();

        for path in entries {
            match self.load_one(&path, builtin_names, debugger) {
                Ok(names) => report.loaded.extend(names),
                Err(e) => report.failed.push((path, e)),
            }
        }
        report
    }

    fn load_one(
        &mut self,
        path: &Path,
        builtin_names: &HashSet<String>,
        debugger: Option<&DebuggerContext>,
    ) -> std::result::Result<Vec<String>, String> {
        let source = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let display = path.display().to_string();

        let pending: RefCell<Vec<(String, Registered)>> = RefCell::new(Vec::new());
        let warnings: RefCell<Vec<String>> = RefCell::new(Vec::new());

        let existing: HashSet<String> = self.commands.keys().cloned().collect();

        if let Some(dbg) = debugger {
            let setup = || -> mlua::Result<()> {
                let ntos = self.lua.create_table()?;
                ntos.set(
                    "addr",
                    self.lua
                        .create_function(|_, n: i64| Ok(Address(n as u64)))?,
                )?;
                install_metadata_ntos(
                    &self.lua,
                    &ntos,
                    Arc::clone(&dbg.symbols),
                    dbg.current_dtb(),
                )?;
                self.lua.globals().set("ntos", ntos)?;
                Ok(())
            };
            setup().map_err(|e| format!("{}", e))?;
        }

        let result = self.lua.scope(|scope| {
            let register = scope.create_function(|lua, args: MultiValue| {
                let mut iter = args.into_iter();
                let name: String = match iter.next() {
                    Some(Value::String(s)) => s.to_str()?.to_string(),
                    _ => return Err(mlua::Error::external(
                        "register_command(name, help, [strategies,] fn): name must be a string",
                    )),
                };
                let help: String = match iter.next() {
                    Some(Value::String(s)) => s.to_str()?.to_string(),
                    _ => return Err(mlua::Error::external(
                        "register_command: help must be a string",
                    )),
                };
                let third = iter.next().unwrap_or(Value::Nil);
                let (strategies, cb): (Vec<CompletionStrategy>, Function) = match third {
                    Value::Function(f) => (Vec::new(), f),
                    Value::Table(t) => {
                        let mut strats = Vec::new();
                        for v in t.sequence_values::<String>() {
                            let s = v?;
                            let strat = CompletionStrategy::from_kebab(&s).ok_or_else(|| {
                                mlua::Error::external(format!(
                                    "unknown completion strategy: '{}' (expected one of: none, symbol, type, process, vcpu, breakpoint, driver)",
                                    s
                                ))
                            })?;
                            strats.push(strat);
                        }
                        let fourth = iter.next().unwrap_or(Value::Nil);
                        let cb: Function = match fourth {
                            Value::Function(f) => f,
                            _ => return Err(mlua::Error::external(
                                "register_command: 4th arg must be a function when strategies table is given",
                            )),
                        };
                        (strats, cb)
                    }
                    _ => return Err(mlua::Error::external(
                        "register_command: 3rd arg must be a function or strategies table",
                    )),
                };

                if !is_valid_command_name(&name) {
                    return Err(mlua::Error::external(
                        "register_command: name must be non-empty and contain no whitespace/control characters",
                    ));
                }
                if builtin_names.contains(&name) {
                    warnings
                        .borrow_mut()
                        .push(format!("'{}' collides with builtin", name));
                    return Ok(());
                }
                if existing.contains(&name)
                    || pending.borrow().iter().any(|(n, _)| n == &name)
                {
                    warnings
                        .borrow_mut()
                        .push(format!("'{}' already registered", name));
                    return Ok(());
                }
                let key = lua.create_registry_value(cb)?;
                pending.borrow_mut().push((
                    name,
                    Registered {
                        help,
                        callback: key,
                        strategies,
                    },
                ));
                Ok(())
            })?;
            self.lua.globals().set("register_command", register)?;
            let exec_result = self.lua.load(&source).set_name(&display).exec();
            self.lua.globals().set("register_command", Value::Nil)?;
            exec_result?;
            Ok(())
        });

        if debugger.is_some() {
            let _ = self.lua.globals().set("ntos", Value::Nil);
        }

        if let Err(e) = result {
            return Err(format!("{}", e));
        }

        for w in warnings.into_inner() {
            diagnostics::eprint_warning(format!("{}: {}", path.display(), w));
        }

        let mut names = Vec::new();
        for (name, reg) in pending.into_inner() {
            names.push(name.clone());
            self.commands.insert(name, reg);
        }
        Ok(names)
    }

    /// Dispatch a script-registered command. `args` are the raw whitespace-split
    /// tokens after the command name; they're passed to the Lua function as
    /// individual string arguments
    pub fn dispatch(
        &self,
        name: &str,
        args: &[&str],
        debugger: &mut DebuggerContext,
        client: &mut dyn DebugBackend,
        register_map: &RegisterMap,
    ) -> mlua::Result<()> {
        let entry = self
            .commands
            .get(name)
            .ok_or_else(|| mlua::Error::external(format!("no such script command: {}", name)))?;

        let dbg = RefCell::new(debugger);
        let cli = RefCell::new(client);
        let regs_cache: RefCell<Option<Vec<u8>>> = RefCell::new(None);

        self.lua.scope(|scope| {
            let ntos = self.lua.create_table()?;

            ntos.set(
                "addr",
                scope.create_function(|_, n: i64| Ok(Address(n as u64)))?,
            )?;

            {
                let d = dbg.borrow();
                install_metadata_ntos(&self.lua, &ntos, Arc::clone(&d.symbols), d.current_dtb())?;
            }

            ntos.set(
                "containing_record",
                scope.create_function(|_, (entry, ty, field): (Address, String, String)| {
                    let d = dbg.borrow();
                    let field = field_address(&d, &ty, &field, Address(0))?;
                    Ok(Address(entry.0.wrapping_sub(field.0)))
                })?,
            )?;

            ntos.set(
                "command_usage",
                scope.create_function({
                    let help = entry.help.clone();
                    move |_, ()| {
                        println!("{}", help);
                        Ok(())
                    }
                })?,
            )?;

            ntos.set(
                "eval",
                scope.create_function(|_, expr: String| {
                    let d = dbg.borrow();
                    Expr::eval(&expr, &d)
                        .map(|va| Address(va.0))
                        .map_err(mlua::Error::external)
                })?,
            )?;

            ntos.set(
                "try_eval",
                scope.create_function(|_, expr: String| {
                    let d = dbg.borrow();
                    Ok(Expr::eval(&expr, &d).ok().map(|va| Address(va.0)))
                })?,
            )?;

            ntos.set(
                "loaded_module_list",
                scope.create_function(|_, ()| {
                    let d = dbg.borrow();
                    d.guest
                        .ntoskrnl
                        .symbol("PsLoadedModuleList")
                        .and_then(|s| s.read())
                        .map(|va: VirtAddr| Address(va.0))
                        .map_err(mlua::Error::external)
                })?,
            )?;

            ntos.set(
                "kernel_modules",
                scope.create_function(|lua, ()| {
                    let d = dbg.borrow();
                    let modules = d.guest.kernel_modules().map_err(mlua::Error::external)?;
                    let out = lua.create_table()?;
                    for (idx, m) in modules.iter().enumerate() {
                        out.set((idx + 1) as i64, module_table(lua, m)?)?;
                    }
                    Ok(out)
                })?,
            )?;

            ntos.set(
                "try_find_kernel_module",
                scope.create_function(|lua, name: String| {
                    let d = dbg.borrow();
                    let needle = name.to_lowercase();
                    let modules = d.guest.kernel_modules().map_err(mlua::Error::external)?;
                    for m in &modules {
                        if m.short_name.eq_ignore_ascii_case(&needle)
                            || m.name.to_lowercase().contains(&needle)
                        {
                            return module_table(lua, m).map(Some);
                        }
                    }
                    Ok(None)
                })?,
            )?;

            ntos.set(
                "driver_objects",
                scope.create_function(|lua, ()| {
                    let d = dbg.borrow();
                    let drivers = d
                        .enumerate_driver_objects()
                        .map_err(mlua::Error::external)?;
                    let out = lua.create_table()?;
                    for (idx, driver) in drivers.iter().enumerate() {
                        out.set((idx + 1) as i64, driver_object_table(lua, driver)?)?;
                    }
                    Ok(out)
                })?,
            )?;

            ntos.set(
                "try_find_driver_object",
                scope.create_function(|lua, name: String| {
                    let needle = name.trim();
                    let full_name;
                    let short = if needle.starts_with("\\Driver\\") {
                        needle
                    } else {
                        full_name = format!("\\Driver\\{needle}");
                        full_name.as_str()
                    };
                    let d = dbg.borrow();
                    let drivers = d
                        .enumerate_driver_objects()
                        .map_err(mlua::Error::external)?;
                    for driver in &drivers {
                        if driver.name.eq_ignore_ascii_case(short) {
                            return driver_object_table(lua, driver).map(Some);
                        }
                    }
                    Ok(None)
                })?,
            )?;

            ntos.set(
                "read_struct",
                scope.create_function(|lua, (ty, addr): (String, Address)| {
                    let d = dbg.borrow();
                    let dtb = d.current_dtb();
                    let ti = d
                        .symbols
                        .find_type_across_modules(dtb, &ty)
                        .ok_or_else(|| mlua::Error::external(format!("unknown type: {}", ty)))?;
                    let mut buf = vec![0u8; ti.size];
                    d.current_process()
                        .memory()
                        .read_bytes(VirtAddr(addr.0), &mut buf)
                        .map_err(mlua::Error::external)?;
                    struct_table(lua, &ti, addr, &buf)
                })?,
            )?;

            ntos.set(
                "ps",
                scope.create_function(|lua, filter: Option<String>| {
                    let d = dbg.borrow();
                    let procs = d
                        .guest
                        .enumerate_processes()
                        .map_err(mlua::Error::external)?;
                    let filter_l = filter.as_deref().map(|s| s.to_lowercase());
                    let out = lua.create_table()?;
                    let mut i = 1i64;
                    for p in procs {
                        if let Some(ref f) = filter_l {
                            let name_l = p.name.to_lowercase();
                            if !name_l.contains(f) && !p.pid.to_string().starts_with(f) {
                                continue;
                            }
                        }
                        let row = lua.create_table()?;
                        row.set("pid", p.pid as i64)?;
                        row.set("name", p.name)?;
                        row.set("eprocess", Address(p.eprocess_va.0))?;
                        out.set(i, row)?;
                        i += 1;
                    }
                    Ok(out)
                })?,
            )?;

            ntos.set(
                "process",
                scope.create_function(|lua, target: String| {
                    let d = dbg.borrow();
                    let matches = match_processes(&d, &target).map_err(mlua::Error::external)?;
                    match matches.as_slice() {
                        [] => Err(mlua::Error::external(format!(
                            "no process matches '{}'",
                            target
                        ))),
                        [p] => process_row(lua, p),
                        many => {
                            let mut msg = String::from("ambiguous, matches:");
                            for p in many {
                                msg.push_str(&format!("\n  {}  {}", p.pid, p.name));
                            }
                            Err(mlua::Error::external(msg))
                        }
                    }
                })?,
            )?;

            ntos.set(
                "try_process",
                scope.create_function(|lua, target: String| {
                    let d = dbg.borrow();
                    let Ok(matches) = match_processes(&d, &target) else {
                        return Ok(None);
                    };
                    let [p] = matches.as_slice() else {
                        return Ok(None);
                    };
                    process_row(lua, p).map(Some)
                })?,
            )?;

            ntos.set(
                "read_byte",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    Ok(read_array::<1>(&d, addr)?[0] as i64)
                })?,
            )?;

            ntos.set(
                "read_word",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    Ok(u16::from_le_bytes(read_array::<2>(&d, addr)?) as i64)
                })?,
            )?;

            ntos.set(
                "read_dword",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    Ok(u32::from_le_bytes(read_array::<4>(&d, addr)?) as i64)
                })?,
            )?;
            ntos.set(
                "read_qword",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    Ok(Address(u64::from_le_bytes(read_array::<8>(&d, addr)?)))
                })?,
            )?;

            ntos.set(
                "read_bytes",
                scope.create_function(|lua, (addr, len): (Address, usize)| {
                    let d = dbg.borrow();
                    lua.create_string(read_vec(&d, addr, len)?)
                })?,
            )?;

            // Fault-tolerant read variants that return nil instead of raising
            ntos.set(
                "try_read_byte",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    Ok(read_array::<1>(&d, addr).ok().map(|buf| buf[0] as i64))
                })?,
            )?;
            ntos.set(
                "try_read_word",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    Ok(read_array::<2>(&d, addr)
                        .ok()
                        .map(|buf| u16::from_le_bytes(buf) as i64))
                })?,
            )?;
            ntos.set(
                "try_read_dword",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    Ok(read_array::<4>(&d, addr)
                        .ok()
                        .map(|buf| u32::from_le_bytes(buf) as i64))
                })?,
            )?;
            ntos.set(
                "try_read_qword",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    Ok(read_array::<8>(&d, addr)
                        .ok()
                        .map(|buf| Address(u64::from_le_bytes(buf))))
                })?,
            )?;
            ntos.set(
                "try_read_field_byte",
                scope.create_function(|_, (ty, field, addr): (String, String, Address)| {
                    let d = dbg.borrow();
                    let addr = field_address(&d, &ty, &field, addr)?;
                    Ok(read_array::<1>(&d, addr).ok().map(|buf| buf[0] as i64))
                })?,
            )?;
            ntos.set(
                "try_read_field_word",
                scope.create_function(|_, (ty, field, addr): (String, String, Address)| {
                    let d = dbg.borrow();
                    let addr = field_address(&d, &ty, &field, addr)?;
                    Ok(read_array::<2>(&d, addr)
                        .ok()
                        .map(|buf| u16::from_le_bytes(buf) as i64))
                })?,
            )?;
            ntos.set(
                "try_read_field_dword",
                scope.create_function(|_, (ty, field, addr): (String, String, Address)| {
                    let d = dbg.borrow();
                    let addr = field_address(&d, &ty, &field, addr)?;
                    Ok(read_array::<4>(&d, addr)
                        .ok()
                        .map(|buf| u32::from_le_bytes(buf) as i64))
                })?,
            )?;
            ntos.set(
                "try_read_field_qword",
                scope.create_function(|_, (ty, field, addr): (String, String, Address)| {
                    let d = dbg.borrow();
                    let addr = field_address(&d, &ty, &field, addr)?;
                    Ok(read_array::<8>(&d, addr)
                        .ok()
                        .map(|buf| Address(u64::from_le_bytes(buf))))
                })?,
            )?;
            ntos.set(
                "try_read_bytes",
                scope.create_function(|lua, (addr, len): (Address, usize)| {
                    let d = dbg.borrow();
                    match read_vec(&d, addr, len) {
                        Ok(buf) => lua.create_string(buf).map(Some),
                        Err(_) => Ok(None),
                    }
                })?,
            )?;
            ntos.set(
                "try_read_struct",
                scope.create_function(|lua, (ty, addr): (String, Address)| {
                    let d = dbg.borrow();
                    let dtb = d.current_dtb();
                    let ti = d
                        .symbols
                        .find_type_across_modules(dtb, &ty)
                        .ok_or_else(|| mlua::Error::external(format!("unknown type: {}", ty)))?;
                    let Ok(buf) = read_vec(&d, addr, ti.size) else {
                        return Ok(None);
                    };
                    struct_table(lua, &ti, addr, &buf).map(Some)
                })?,
            )?;

            ntos.set(
                "try_read_unicode_string",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    let ti = d
                        .symbols
                        .find_type_across_modules(d.current_dtb(), "_UNICODE_STRING");
                    let Some(ti) = ti else { return Ok(None) };
                    let Ok(len_off) = ti.field_offset("Length") else {
                        return Ok(None);
                    };
                    let Ok(buf_off) = ti.field_offset("Buffer") else {
                        return Ok(None);
                    };
                    let mem = d.current_process().memory();
                    let Ok(len) = mem.read::<u16>(VirtAddr(addr.0) + len_off) else {
                        return Ok(None);
                    };
                    if len == 0 || len as usize > 0x1000 {
                        return Ok(None);
                    }
                    let Ok(buffer) = mem.read::<VirtAddr>(VirtAddr(addr.0) + buf_off) else {
                        return Ok(None);
                    };
                    let mut bytes = vec![0u8; len as usize];
                    if mem.read_bytes(buffer, &mut bytes).is_err() {
                        return Ok(None);
                    }
                    Ok(Some(decode_utf16le_lossy(&bytes)))
                })?,
            )?;

            ntos.set(
                "search",
                scope.create_function(
                    |lua, (addr, len, pattern): (Address, usize, mlua::String)| {
                        let pattern = pattern.as_bytes();
                        let out = lua.create_table()?;
                        if pattern.is_empty() || pattern.len() > len {
                            return Ok(out);
                        }
                        let d = dbg.borrow();
                        let buf = read_vec(&d, addr, len)?;
                        let mut idx = 1i64;
                        for i in 0..=buf.len() - pattern.len() {
                            let window = &buf[i..i + pattern.len()];
                            if pattern == window {
                                out.set(idx, Address(addr.0.wrapping_add(i as u64)))?;
                                idx += 1;
                            }
                        }
                        Ok(out)
                    },
                )?,
            )?;

            ntos.set(
                "search_first",
                scope.create_function(
                    |_, (addr, len, pattern): (Address, usize, mlua::String)| {
                        let pattern = pattern.as_bytes();
                        if pattern.is_empty() || pattern.len() > len {
                            return Ok(None);
                        }
                        let d = dbg.borrow();
                        let buf = read_vec(&d, addr, len)?;
                        for i in 0..=buf.len() - pattern.len() {
                            let window = &buf[i..i + pattern.len()];
                            if pattern == window {
                                return Ok(Some(Address(addr.0.wrapping_add(i as u64))));
                            }
                        }
                        Ok(None)
                    },
                )?,
            )?;

            ntos.set(
                "can_read",
                scope.create_function(|_, (addr, len): (Address, usize)| {
                    let d = dbg.borrow();
                    let mut buf = vec![0u8; len];
                    Ok(read_memory_exact(&d, addr, &mut buf).is_ok())
                })?,
            )?;

            ntos.set(
                "write_byte",
                scope.create_function(|_, (addr, v): (Address, i64)| {
                    let d = dbg.borrow();
                    write_memory_exact(&d, addr, &[(v as u8)])
                })?,
            )?;
            ntos.set(
                "write_word",
                scope.create_function(|_, (addr, v): (Address, i64)| {
                    let d = dbg.borrow();
                    write_memory_exact(&d, addr, &(v as u16).to_le_bytes())
                })?,
            )?;
            ntos.set(
                "write_dword",
                scope.create_function(|_, (addr, v): (Address, i64)| {
                    let d = dbg.borrow();
                    write_memory_exact(&d, addr, &(v as u32).to_le_bytes())
                })?,
            )?;
            ntos.set(
                "write_qword",
                scope.create_function(|_, (addr, v): (Address, AddrOrInt)| {
                    let d = dbg.borrow();
                    write_memory_exact(&d, addr, &v.value.to_le_bytes())
                })?,
            )?;
            ntos.set(
                "write_bytes",
                scope.create_function(|_, (addr, data): (Address, mlua::String)| {
                    let d = dbg.borrow();
                    let bytes = data.as_bytes();
                    write_memory_exact(&d, addr, &bytes)
                })?,
            )?;

            ntos.set(
                "try_closest_symbol",
                scope.create_function(|lua, addr: Address| {
                    let d = dbg.borrow();
                    match d.guest.ntoskrnl.closest_symbol(VirtAddr(addr.0)) {
                        Ok((name, offset)) => {
                            let t = lua.create_table()?;
                            t.set("name", name)?;
                            t.set("offset", offset as i64)?;
                            Ok(Value::Table(t))
                        }
                        Err(_) => Ok(Value::Nil),
                    }
                })?,
            )?;

            ntos.set(
                "try_closest_symbol_any",
                scope.create_function(|lua, addr: Address| {
                    let d = dbg.borrow();
                    let dtb = d.current_dtb();
                    match d
                        .symbols
                        .find_closest_symbol_for_address(dtb, VirtAddr(addr.0))
                    {
                        Some((module, name, offset)) => {
                            let t = lua.create_table()?;
                            t.set("module", module)?;
                            t.set("name", name)?;
                            t.set("offset", offset as i64)?;
                            Ok(Value::Table(t))
                        }
                        None => Ok(Value::Nil),
                    }
                })?,
            )?;

            ntos.set(
                "format_symbol",
                scope.create_function(|_, addr: Address| {
                    let d = dbg.borrow();
                    let dtb = d.current_dtb();
                    Ok(d.symbols
                        .format_closest_symbol_for_address(dtb, VirtAddr(addr.0))
                        .unwrap_or_else(|| format!("{:#x}", addr.0)))
                })?,
            )?;

            ntos.set(
                "is_kernel_address",
                scope.create_function(|_, addr: Address| Ok(addr.0 >= 0xffff_0000_0000_0000))?,
            )?;

            ntos.set(
                "read_register",
                scope.create_function(|_, name: String| {
                    let mut cache = regs_cache.borrow_mut();
                    if cache.is_none() {
                        let mut c = cli.borrow_mut();
                        let regs = c.read_registers().map_err(mlua::Error::external)?;
                        *cache = Some(regs);
                    }
                    let regs = cache.as_ref().unwrap();
                    register_map
                        .read_u64(&name, regs)
                        .map(Address)
                        .map_err(mlua::Error::external)
                })?,
            )?;

            self.lua.globals().set("ntos", ntos)?;

            let result = (|| {
                let cb: Function = self.lua.registry_value(&entry.callback)?;
                let lua_args: Variadic<Value> = args
                    .iter()
                    .map(|s| self.lua.create_string(s).map(Value::String))
                    .collect::<mlua::Result<_>>()?;
                cb.call::<()>(lua_args)
            })();
            self.lua.globals().set("ntos", Value::Nil)?;
            result
        })
    }
}

fn scripts_dir() -> Option<PathBuf> {
    cache_root().map(|r| r.join("commands"))
}

fn is_valid_command_name(name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(char::is_whitespace)
        && !name.chars().any(char::is_control)
}

struct BuiltinScript {
    name: &'static str,
    source: &'static str,
}

const BUILTIN_SCRIPTS: &[BuiltinScript] = &[
    BuiltinScript {
        name: "callbacks.lua",
        source: include_str!("../scripts/callbacks.lua"),
    },
    BuiltinScript {
        name: "devobj.lua",
        source: include_str!("../scripts/devobj.lua"),
    },
    BuiltinScript {
        name: "drvobj.lua",
        source: include_str!("../scripts/drvobj.lua"),
    },
    BuiltinScript {
        name: "hide.lua",
        source: include_str!("../scripts/hide.lua"),
    },
    BuiltinScript {
        name: "irp.lua",
        source: include_str!("../scripts/irp.lua"),
    },
    BuiltinScript {
        name: "irps.lua",
        source: include_str!("../scripts/irps.lua"),
    },
    BuiltinScript {
        name: "lpe.lua",
        source: include_str!("../scripts/lpe.lua"),
    },
    BuiltinScript {
        name: "object.lua",
        source: include_str!("../scripts/object.lua"),
    },
    BuiltinScript {
        name: "ssdt.lua",
        source: include_str!("../scripts/ssdt.lua"),
    },
];

pub struct ScriptInstallOptions {
    pub source: Option<String>,
    pub force: bool,
    pub yes: bool,
}

pub fn install_scripts(options: ScriptInstallOptions) -> Result<()> {
    let dir = scripts_dir().ok_or(Error::StorageNotFound)?;
    fs::create_dir_all(&dir)?;

    match options.source.as_deref() {
        None => install_builtin_scripts(&dir, options.force),
        Some(source) if is_https_url(source) => {
            install_url_script(source, &dir, options.force, options.yes)
        }
        Some(source) if looks_like_url(source) => Err(Error::DebugInfo(
            "remote script URL must use HTTPS and point to a .lua file".to_string(),
        )),
        Some(source) => install_local_scripts(Path::new(source), &dir, options.force, options.yes),
    }
}

pub fn list_scripts() -> Result<()> {
    let dir = scripts_dir().ok_or(Error::StorageNotFound)?;
    println!("{}", dir.display());
    if !dir.exists() {
        return Ok(());
    }

    let mut entries: Vec<_> = fs::read_dir(&dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("lua"))
        .collect();
    entries.sort();

    for path in entries {
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            println!("  {}", name);
        }
    }
    Ok(())
}

fn install_builtin_scripts(dir: &Path, force: bool) -> Result<()> {
    for script in BUILTIN_SCRIPTS {
        write_script(dir, script.name, script.source.as_bytes(), force)?;
    }
    Ok(())
}

fn install_local_scripts(source: &Path, dir: &Path, force: bool, yes: bool) -> Result<()> {
    let files = if source.is_dir() {
        let mut files: Vec<_> = fs::read_dir(source)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("lua"))
            .collect();
        files.sort();
        files
    } else if source.extension().and_then(|s| s.to_str()) == Some("lua") {
        vec![source.to_path_buf()]
    } else {
        return Err(Error::DebugInfo(format!(
            "script source must be a .lua file or directory: {}",
            source.display()
        )));
    };

    if files.is_empty() {
        println!("no .lua scripts found in {}", source.display());
        return Ok(());
    }

    confirm_untrusted_install("local Lua scripts", yes)?;
    for file in files {
        let name = file.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
            Error::DebugInfo(format!("invalid script filename: {}", file.display()))
        })?;
        let bytes = fs::read(&file)?;
        write_script(dir, name, &bytes, force)?;
    }
    Ok(())
}

fn install_url_script(url: &str, dir: &Path, force: bool, yes: bool) -> Result<()> {
    if !url.ends_with(".lua") {
        return Err(Error::DebugInfo(
            "remote script URL must point to a .lua file".to_string(),
        ));
    }

    let response = reqwest::blocking::get(url)?.error_for_status()?;
    let final_url = response.url().clone();
    if final_url.scheme() != "https" || !final_url.path().ends_with(".lua") {
        return Err(Error::DebugInfo(
            "remote script redirects must stay on HTTPS and end in .lua".to_string(),
        ));
    }
    let bytes = response.bytes()?;
    if bytes.len() > 256 * 1024 {
        return Err(Error::DebugInfo(
            "remote script is larger than 256 KiB".to_string(),
        ));
    }

    let name = final_url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::DebugInfo("remote script URL has no filename".to_string()))?;
    let digest = Sha256::digest(&bytes);
    let dest = dir.join(name);
    println!("source: {}", final_url);
    println!("destination: {}", dest.display());
    println!("sha256: {:x}", digest);
    confirm_untrusted_install("remote Lua script", yes)?;
    write_script(dir, name, &bytes, force)
}

fn write_script(dir: &Path, name: &str, bytes: &[u8], force: bool) -> Result<()> {
    let dest = dir.join(name);
    if dest.exists() && !force {
        println!(
            "skipped {} (already exists; use --force to overwrite)",
            dest.display()
        );
        return Ok(());
    }
    fs::write(&dest, bytes)?;
    println!("installed {}", dest.display());
    Ok(())
}

fn confirm_untrusted_install(kind: &str, yes: bool) -> Result<()> {
    println!(
        "Warning: installing {}. ntoseye scripts are trusted debugger code and can inspect or modify guest memory through ntos.* APIs.",
        kind
    );
    if yes {
        return Ok(());
    }

    print!("Install? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(Error::DebugInfo(
            "script installation cancelled".to_string(),
        ))
    }
}

fn is_https_url(source: &str) -> bool {
    source.starts_with("https://")
}

fn looks_like_url(source: &str) -> bool {
    source.contains("://")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write_temp_script(source: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ntoseye-script-test-{}-{}.lua",
            std::process::id(),
            nanos
        ));
        std::fs::write(&path, source).unwrap();
        path
    }

    #[test]
    fn lua_stdlib_keeps_script_basics_but_blocks_host_access() {
        let mut host = ScriptHost::new();
        let path = write_temp_script(
            r#"
            assert(io == nil)
            assert(os == nil)
            assert(package == nil)
            local xs = { "a", "b" }
            assert(#xs == 2)
            assert(("A%s"):format("B"):lower() == "ab")
            assert(math.max(1, 2) == 2)
            register_command("demo", "help", {"process", "symbol"}, function() end)
            "#,
        );

        let loaded = host.load_one(&path, &HashSet::new(), None).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(loaded, vec!["demo"]);
        let commands = host.command_names();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].0, "demo");
        assert_eq!(commands[0].1, "help");
        assert_eq!(commands[0].2.len(), 2);
    }

    #[test]
    fn command_names_are_sorted() {
        let mut host = ScriptHost::new();
        let path = write_temp_script(
            r#"
            register_command("zeta", "z", function() end)
            register_command("alpha", "a", function() end)
            "#,
        );

        host.load_one(&path, &HashSet::new(), None).unwrap();
        let _ = std::fs::remove_file(path);

        let names: Vec<_> = host
            .command_names()
            .into_iter()
            .map(|(name, _, _)| name)
            .collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn invalid_command_names_are_rejected_and_registration_global_is_cleared() {
        let mut host = ScriptHost::new();
        let path = write_temp_script(r#"register_command("bad name", "help", function() end)"#);

        let err = host.load_one(&path, &HashSet::new(), None).unwrap_err();
        let _ = std::fs::remove_file(path);

        assert!(err.contains("name must be non-empty"));
        let register_command: Value = host.lua.globals().get("register_command").unwrap();
        assert!(matches!(register_command, Value::Nil));
    }

    #[test]
    fn address_rejects_lossy_lua_numbers() {
        let lua = Lua::new();

        assert!(Address::from_lua(Value::Number(3.5), &lua).is_err());
        assert!(Address::from_lua(Value::Number(((1u64 << 53) as f64) + 1.0), &lua).is_err());
        assert_eq!(
            Address::from_lua(Value::Number(4096.0), &lua).unwrap().0,
            4096
        );
    }

    #[test]
    fn pointer_fields_decode_as_addresses() {
        let lua = Lua::new();
        let bytes = 0x1234u64.to_le_bytes();
        let value = decode_field(
            &lua,
            &ParsedType::Pointer(Box::new(ParsedType::Primitive("void".to_string()))),
            bytes.len(),
            &bytes,
            0,
        )
        .unwrap();

        let Value::UserData(ud) = value else {
            panic!("expected address userdata");
        };
        assert_eq!(ud.borrow::<Address>().unwrap().0, 0x1234);
    }

    #[test]
    fn utf16_decoder_preserves_non_ascii_and_stops_at_nul() {
        let bytes = [
            0x44, 0x00, // D
            0x3c, 0xd8, 0x00, 0xdf, // U+1F300
            0x00, 0x00, 0x58, 0x00,
        ];

        assert_eq!(decode_utf16le_lossy(&bytes), "D🌀");
    }
}
