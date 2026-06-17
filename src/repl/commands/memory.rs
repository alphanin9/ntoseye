use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::error::Result;
use crate::expr::Expr;
use crate::symbols::{FieldValue, ParsedType};
use crate::types::{Value, VirtAddr};
use crate::ui;
use crate::unwind::{format_symbol, resolve_thread_trace_context};

use crate::repl::*;

repl_command! {
    cmd_db;
    names: ["db"],
    usage: "db <address> [length or end]",
    summary: "Display memory as bytes.",
    completion: Expression,
}

repl_command! {
    cmd_dd;
    names: ["dd"],
    usage: "dd <address> [length or end]",
    summary: "Display memory as doublewords (4 bytes).",
    completion: Expression,
}

repl_command! {
    cmd_dq;
    names: ["dq"],
    usage: "dq <address> [length or end]",
    summary: "Display memory as quadwords (8 bytes).",
    completion: Expression,
}

repl_command! {
    cmd_disasm;
    names: ["disasm", "u"],
    usage: "disasm <address> [length or end]",
    summary: "Disassemble memory at a symbol or address.",
    completion: Expression,
}

repl_command! {
    cmd_dt;
    names: ["dt"],
    usage: "dt <type> [address] [field]",
    summary: "Display type definition.",
    completion: [Type, Expression],
}

repl_command! {
    cmd_eb;
    names: ["eb"],
    usage: "eb <address> <expr>",
    summary: "Write a byte to memory.",
    completion: Expression,
}

repl_command! {
    cmd_ed;
    names: ["ed"],
    usage: "ed <address> <expr>",
    summary: "Write a doubleword (4 bytes) to memory.",
    completion: Expression,
}

repl_command! {
    cmd_eq;
    names: ["eq"],
    usage: "eq <address> <expr>",
    summary: "Write a quadword (8 bytes) to memory.",
    completion: Expression,
}

repl_command! {
    cmd_f;
    names: ["f"],
    usage: "f <address> <hex bytes> [length or end]",
    summary: "Fill memory with a repeated byte pattern.",
    details: "hex bytes: 90, 4883792000740a, or \\x90\\x90",
    completion: [Expression, None, Expression],
}

repl_command! {
    cmd_s;
    names: ["s"],
    usage: "s <address> <hex bytes> [length]",
    summary: "Search memory for a byte pattern.",
    details: "hex bytes: 4883792000740a or \\x48\\x83\\x79\\x20\\x00\\x74\\x0a",
    completion: [Expression, None, Expression],
}

impl ReplState<'_> {
    /// Read guest memory in the current process context for *display*, masking
    /// out our own breakpoint int3 bytes so listings never show them.
    fn read_for_display(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let process = self.ctx.target.current_process();
        process.memory().read_bytes(addr, buf)?;
        self.ctx
            .breakpoints
            .mask_breakpoint_bytes(addr, buf, process.dtb());
        Ok(())
    }

    fn display_memory_command(
        &self,
        invocation: &CommandInvocation<'_>,
        default_count: u64,
        item_size: u64,
        mode: MemoryDisplayMode,
    ) -> Result<()> {
        let range =
            match AddressRange::parse(invocation, &self.ctx.target, default_count, item_size) {
                Ok(r) => r,
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            };

        let mut data: Vec<u8> = vec![0u8; range.len()];
        if let Err(e) = self.read_for_display(range.start, &mut data) {
            println!("{e}\n");
            return Ok(());
        }

        display_memory(range.start, &data, &mode);

        Ok(())
    }

    fn write_scalar_command(
        &mut self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        noun: &str,
        encode: impl FnOnce(u64) -> Vec<u8>,
        display_value: impl FnOnce(u64) -> String,
    ) -> Result<()> {
        if invocation.argv.len() < 2 {
            println!("{}\n", command_help(command));
            return Ok(());
        }

        let address = match Expr::eval(invocation.arg(0).unwrap(), &self.ctx.target) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let expr_str = invocation.join_args(1);
        let value = match Expr::eval(&expr_str, &self.ctx.target) {
            Ok(v) => v.0,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let bytes = encode(value);
        let formatted_value = display_value(value);
        let mem = self.ctx.target.current_process().memory();
        if let Err(e) = mem.write_bytes(address, &bytes) {
            error!("failed to write {}: {}", noun, e);
        } else {
            println!(
                "{} {} -> {}\n",
                "wrote".green(),
                formatted_value,
                ui::addr(address.0)
            );
        }

        Ok(())
    }

    fn cmd_db(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 128, 1, MemoryDisplayMode::bytes())
    }

    fn cmd_dd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 16, 4, MemoryDisplayMode::dwords())
    }

    fn cmd_dq(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 8, 8, MemoryDisplayMode::qwords())
    }

    fn cmd_disasm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let range = match AddressRange::parse(&invocation, &self.ctx.target, 32, 1) {
            Ok(r) => r,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let start_addr = range.start;
        let mut bytes: Vec<u8> = vec![0u8; range.len()];
        if let Err(e) = self.read_for_display(start_addr, &mut bytes) {
            println!("{e}\n");
            return Ok(());
        }

        // resolve branch / rip-relative targets the same way the break/status
        // view does, so the `disasm` command's comments read identically
        let dtb = self.ctx.target.current_process().dtb();
        let trace = resolve_thread_trace_context(&self.ctx.target, dtb);
        let resolve = |target: u64| format_symbol(&self.ctx.target, &trace, target);

        // TODO dont hardcode 64-bit for WOW64 process? / support other formats?
        let mut formatter = disasm_formatter();
        let rows = decode_rows(&bytes, start_addr.0, None, &mut formatter, resolve);
        render_rows(&rows, |_| None);
        println!();

        Ok(())
    }

    fn cmd_eb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_scalar_command(
            &invocation,
            "eb",
            "byte",
            |value| vec![value as u8],
            |value| format!("{:02x}", value as u8),
        )
    }

    fn cmd_ed(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_scalar_command(
            &invocation,
            "ed",
            "dword",
            |value| (value as u32).to_le_bytes().to_vec(),
            |value| format!("{:#x}", value as u32),
        )
    }

    fn cmd_eq(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_scalar_command(
            &invocation,
            "eq",
            "qword",
            |value| value.to_le_bytes().to_vec(),
            |value| format!("{:#x}", value),
        )
    }

    fn cmd_f(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() < 2 {
            println!("{}\n", command_help("f"));
            return Ok(());
        }

        let address = match Expr::eval(invocation.arg(0).unwrap(), &self.ctx.target) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let pattern_str = invocation.arg(1).unwrap();
        let pattern = match parse_byte_pattern(pattern_str) {
            Some(pattern) => pattern,
            None => {
                error!("invalid pattern: {}", pattern_str);
                return Ok(());
            }
        };

        let length = match invocation.arg(2) {
            Some(length_arg) => match Expr::eval(length_arg, &self.ctx.target) {
                Ok(value) => match resolve_length_or_end(address, value) {
                    Some(length) => length,
                    None => {
                        error!("invalid length or end: {}", length_arg);
                        return Ok(());
                    }
                },
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            },
            None => pattern.len(),
        };

        let data = repeat_pattern(&pattern, length);
        let mem = self.ctx.target.current_process().memory();

        if let Err(e) = mem.write_bytes(address, &data) {
            error!("failed to fill memory: {}", e);
        } else {
            println!(
                "{} {:#x} bytes at {} with {}\n",
                "filled".green(),
                length,
                ui::addr(address.0),
                format!("[{}]", pattern_str).green()
            );
        }

        Ok(())
    }

    fn cmd_s(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() < 2 {
            println!("{}\n", command_help("s"));
            return Ok(());
        }

        let pattern_str = invocation.arg(1).unwrap();

        let start_addr = match Expr::eval(invocation.arg(0).unwrap(), &self.ctx.target) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let pattern = match parse_byte_pattern(pattern_str) {
            Some(pattern) => pattern,
            None => {
                error!("invalid pattern: {}", pattern_str);
                return Ok(());
            }
        };

        let length = match invocation.arg(2) {
            Some(length_arg) => match Expr::eval(length_arg, &self.ctx.target) {
                Ok(value) => match usize::try_from(value.0) {
                    Ok(length) => length,
                    Err(_) => {
                        error!("invalid length: {}", length_arg);
                        return Ok(());
                    }
                },
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            },
            None => 0x100,
        };

        // The scan itself is the shared core primitive (`Target::search`), the
        // same one the SDK and MCP `search` use; the REPL only adds the
        // per-hit symbol line and the $0..$N result slots.
        let hits = match self.ctx.target.search(start_addr, &pattern, length) {
            Ok(hits) => hits,
            Err(e) => {
                error!("failed to read memory: {}", e);
                return Ok(());
            }
        };
        for &addr in &hits {
            let sym = self
                .ctx
                .target
                .guest
                .ntoskrnl
                .closest_symbol(VirtAddr(addr))
                .map(|(s, o)| {
                    if o == 0 {
                        s.to_string()
                    } else {
                        format!("{}+{:#x}", s, o)
                    }
                })
                .unwrap_or_default();

            println!("{}  {}", ui::addr(addr), ui::symbol(&sym));
        }

        if hits.is_empty() {
            println!(
                "{} (searched {:#x} bytes at {})",
                "no matches found".bright_black(),
                length,
                ui::addr(start_addr.0)
            );
        } else {
            println!(
                "\n{} {} (in $0..${})",
                hits.len(),
                if hits.len() == 1 { "match" } else { "matches" },
                hits.len() - 1
            );
        }
        self.ctx.target.set_results(hits, self.line.clone());
        println!();

        Ok(())
    }

    fn cmd_dt(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let arg = require_arg!(invocation, 0, "dt");

        let address = match Expr::eval(invocation.arg(1).unwrap_or("0"), &self.ctx.target) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let field_name = invocation.arg(2);

        match self
            .ctx
            .target
            .symbols
            .find_type_across_modules(self.ctx.target.current_dtb(), arg)
        {
            Some(type_info) => {
                let mut builder = Builder::default();
                builder.push_record(vec![format!(
                    "{} ({} bytes)",
                    type_info.name,
                    Value(type_info.size)
                )]);

                // Decode via the shared `decode_fields` (the path `read_struct`
                // uses in the SDK/MCP) so `dt` and a struct read can't disagree.
                // One whole-struct read, rendered from the decoded leaves; the
                // offset/type columns and bitfield Y/N styling stay dt-specific.
                let decoded: std::collections::HashMap<String, FieldValue> = if address.0 != 0 {
                    // NOTE: one whole-struct read, not page-tolerant; fine for the
                    // non-paged kernel structs dt targets, but a partially-resident
                    // pageable struct with a paged-out tail would fail the read here
                    let mut buf = vec![0u8; type_info.size];
                    match self
                        .ctx
                        .target
                        .current_process()
                        .memory()
                        .read_bytes(address, &mut buf)
                    {
                        Ok(()) => type_info.decode_fields(&buf).into_iter().collect(),
                        Err(e) => {
                            error!("failed to read struct memory: {}", e);
                            return Ok(());
                        }
                    }
                } else {
                    std::collections::HashMap::new()
                };

                let mut sorted_fields: Vec<_> = type_info.fields.iter().collect();
                sorted_fields.sort_by_key(|(_, info)| {
                    let bitfield_pos = match &info.type_data {
                        ParsedType::Bitfield { pos, .. } => *pos,
                        _ => 0,
                    };
                    (info.offset, bitfield_pos)
                });

                for (name, info) in sorted_fields {
                    let value = match decoded.get(name) {
                        // A len-1 bitfield renders as a Y/N flag (the value is
                        // already masked/shifted by decode_fields); wider
                        // bitfields show the decimal value.
                        Some(FieldValue::Bitfield(val)) => {
                            let single_bit = matches!(
                                &info.type_data,
                                ParsedType::Bitfield { len, .. } if *len == 1
                            );
                            if single_bit {
                                if *val == 1 {
                                    format!(" = {}", "Y".green())
                                } else {
                                    format!(" = {}", "N".red())
                                }
                            } else {
                                format!(" = {}", Value(*val))
                            }
                        }
                        Some(FieldValue::Int(val)) | Some(FieldValue::Pointer(val)) => {
                            format!(" = {:#x}", Value(*val))
                        }
                        // Aggregates (Bytes) and fields decode_fields skips
                        // (nested structs / past the buffer) show no inline value.
                        Some(FieldValue::Bytes(_)) | None => String::new(),
                    };

                    if field_name.is_none_or(|field| field == name.as_str()) {
                        builder.push_record(vec![
                            format!(
                                "  {} {:-12}",
                                format!("+ {:#06x}", info.offset).bright_black(),
                                name
                            ),
                            format!("  : {}", info.type_data.green()),
                            format!("  {}", value),
                        ]);
                    }
                }

                print_plain_table(builder);
            }
            None => {
                // Not a struct/union; it may be an enum (enums aren't in the
                // struct type index, so find_type misses them).
                match self
                    .ctx
                    .target
                    .symbols
                    .find_enum_across_modules(self.ctx.target.current_dtb(), arg)
                {
                    Some(variants) => {
                        // Header as its own line; a one-cell header row in the
                        // table would stretch the value column. The value/name
                        // table then sizes both columns to content.
                        println!("enum {} ({} values)", arg, variants.len());
                        let mut builder = Builder::default();
                        for (name, value) in &variants {
                            builder.push_record(vec![format!("  {:#x}  ", value), name.clone()]);
                        }
                        print_plain_table(builder);
                        println!();
                    }
                    None => {
                        error!("failed to get type information: type `{}` not found\n", arg);
                    }
                }
            }
        }

        Ok(())
    }
}
