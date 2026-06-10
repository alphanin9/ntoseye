use strum::EnumMessage;
use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Panel};

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::expr::Expr;
use crate::ui;

use crate::repl::*;

impl ReplState<'_> {
    pub fn cmd_pte(&mut self, parts: &[&str]) -> Result<()> {
        let address = match Expr::eval(parts.get(1).copied().unwrap_or(""), self.debugger) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        match self.debugger.pte_traverse(address) {
            Ok(result) => {
                let mut levels = vec![result.pxe, result.ppe];

                if let Some(x) = result.pde {
                    levels.push(x);
                }

                if let Some(x) = result.pte {
                    levels.push(x);
                }

                let header = format!("VA {}", ui::addr(result.address.0));
                let mut builder = Builder::default();

                let row_strings: Vec<String> = levels.iter().map(|l| l.to_string()).collect();
                builder.push_record(row_strings);

                let mut table = builder.build();
                table
                    .with(Panel::header(header))
                    .with(Modify::new(Rows::first()).with(Alignment::center()))
                    .with(tabled::settings::Style::empty());

                println!("{}\n", table);
            }
            Err(e) => {
                error!("{}\n", e);
            }
        }

        Ok(())
    }

    pub fn cmd_pool(&mut self, parts: &[&str]) -> Result<()> {
        let Some(expr) = parts.get(1).copied() else {
            println!(
                "{}\n",
                ReplCommand::Pool.get_message().unwrap_or("invalid usage")
            );
            return Ok(());
        };

        let target = match Expr::eval(expr, self.debugger) {
            Ok(target) => target,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let layout = match pool_layout(self.debugger) {
            Ok(l) => l,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        if target.0 & (POOL_PAGE_SIZE - 1) == 0
            && let Some(big) = find_big_pool(self.debugger, &layout, target)
        {
            print_big_pool(target, &big);
            return Ok(());
        }

        let region = classify_pool_region(self.debugger, target);
        let (blocks, idx, base) = locate_pool_block_in_page(self.debugger, &layout, target);
        println!("pool page {}", ui::addr(base.0));
        println!("  target        : {}", ui::addr(target.0));
        if let Some((name, start, end)) = region {
            println!(
                "  region        : {} [{} - {}]",
                name,
                ui::addr(start.0),
                ui::addr(end.0)
            );
        }
        if let Some(idx) = idx {
            println!(
                "  blocks in run : {} (target is #{})",
                blocks.len(),
                idx + 1
            );
        }
        println!();
        print_pool_page_listing(&blocks, idx, target);

        if idx.is_none() {
            if let Some(big) = find_big_pool(self.debugger, &layout, target) {
                println!();
                print_big_pool(target, &big);
                return Ok(());
            }
            println!("  address does not lie inside a recognizable _POOL_HEADER block.");
            println!("  it may be segment heap, special pool, a mapped view, or image/stack.");
            if let Some(hint) = segment_heap_hint(self.debugger) {
                println!("  hint          : {}", hint);
            }
            if let Some(near) = annotate_near_symbol(self.debugger, target) {
                println!("  near symbol   : {}", near);
            }
        }

        Ok(())
    }

    pub fn cmd_registers(&mut self, _parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        if let Err(e) = self.client.set_current_thread(&self.current_thread) {
            error!("failed to select execution context: {:?}", e);
            return Ok(());
        }

        let regs = match self.client.read_registers() {
            Ok(r) => r,
            Err(e) => {
                error!("failed to read registers: {:?}", e);
                return Ok(());
            }
        };

        self.debugger.registers = Some(self.register_map.to_hashmap(&regs));
        print_registers(&self.register_map, &regs, false);

        // Control registers match the GP-register cluster's
        // styling; segment selectors are 16-bit, so render
        // them as 4 digits rather than padding to 64-bit
        let read_cr = |name: &str| -> String {
            self.register_map
                .read_u64(name, &regs)
                .map(ui::addr)
                .unwrap_or_else(|_| "N/A".to_string())
        };
        let read_seg = |name: &str| -> String {
            self.register_map
                .read_u64(name, &regs)
                .map(|v| format!("{:04x}", v).bright_white().bold().to_string())
                .unwrap_or_else(|_| "N/A".to_string())
        };

        println!();
        println!(
            "  cr0 {}   cr2 {}   cr3 {}",
            read_cr("cr0"),
            read_cr("cr2"),
            read_cr("cr3")
        );
        println!("  cr4 {}   cr8 {}", read_cr("cr4"), read_cr("cr8"));
        println!();

        println!(
            "  cs  {}   ds  {}   es  {}",
            read_seg("cs"),
            read_seg("ds"),
            read_seg("es")
        );
        println!(
            "  fs  {}   gs  {}   ss  {}",
            read_seg("fs"),
            read_seg("gs"),
            read_seg("ss")
        );
        println!();

        Ok(())
    }

    pub fn cmd_k(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let frame_limit: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(64);

        if let Err(e) = self.client.set_current_thread(&self.current_thread) {
            error!("failed to select execution context: {:?}", e);
            return Ok(());
        }

        let regs = match self.client.read_registers() {
            Ok(r) => r,
            Err(e) => {
                error!("failed to read registers: {:?}", e);
                return Ok(());
            }
        };

        print_stacktrace(
            self.debugger,
            &self.register_map,
            &regs,
            frame_limit,
            frame_limit,
            false,
        );
        println!();

        Ok(())
    }

    pub fn cmd_status(&mut self, _parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            println!("VM is running\n");
        } else {
            if let Err(e) = self.client.set_current_thread(&self.current_thread) {
                error!("failed to select execution context: {:?}", e);
                return Ok(());
            }
            print_break_context(
                &mut *self.client,
                &self.register_map,
                self.debugger,
                &self.breakpoints,
                &self.current_thread,
            );
        }

        Ok(())
    }

    pub fn cmd_capabilities(&mut self, _parts: &[&str]) -> Result<()> {
        print_backend_capabilities(&self.client.capabilities());

        Ok(())
    }
}
