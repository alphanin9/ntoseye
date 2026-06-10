use strum::EnumMessage;

use crate::debugger::UserVar;
use crate::error::Result;
use crate::expr::Expr;
use crate::symbols::format_symbol_with_offset;
use crate::ui;

use crate::repl::*;

impl ReplState<'_> {
    pub fn cmd_x(&mut self, parts: &[&str]) -> Result<()> {
        let Some(query) = parts.get(1) else {
            error!("usage: x <query>  (or x <module>!<query>)");
            return Ok(());
        };
        // bounded purely for terminal-output sanity (resolution
        // is O(1) now); a huge match set just floods the screen
        const X_LIMIT: usize = 4096;
        let dtb = self.debugger.current_dtb();
        // `module!query` scopes the search to one module; a bare
        // query fuzzy-matches across the cached merged index
        let (module_filter, names) = match query.split_once('!') {
            Some((module, q)) => (
                Some(module),
                self.debugger
                    .symbols
                    .search_symbols_in_module(dtb, module, q, X_LIMIT),
            ),
            None => (
                None,
                self.caches.symbols.read().unwrap().search(query, X_LIMIT),
            ),
        };
        let truncated = names.len() >= X_LIMIT;
        let mut hits: Vec<u64> = Vec::new();
        for name in &names {
            // resolve within the requested module when scoped,
            // so a name present in several modules isn't hijacked
            let lookup = match module_filter {
                Some(m) => format!("{}!{}", m, name),
                None => name.clone(),
            };
            if let Some((addr, module)) =
                self.debugger.symbols.find_symbol_with_module(dtb, &lookup)
            {
                println!(
                    "{}  {}",
                    ui::addr(addr.0),
                    ui::symbol(&format!("{}!{}", module, name))
                );
                hits.push(addr.0);
            }
        }
        if hits.is_empty() {
            println!("no symbols match '{}'", query);
        } else {
            println!(
                "\n{} {}{} (in $0..${})",
                hits.len(),
                if hits.len() == 1 { "symbol" } else { "symbols" },
                if truncated {
                    ", truncated; refine query"
                } else {
                    ""
                },
                hits.len() - 1
            );
        }
        self.debugger.set_results(hits, self.line.clone());
        println!();

        Ok(())
    }

    pub fn cmd_ln(&mut self, parts: &[&str]) -> Result<()> {
        let Some(arg) = parts.get(1) else {
            error!("usage: ln <address>");
            return Ok(());
        };
        let addr = match Expr::eval(arg, self.debugger) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        match self
            .debugger
            .symbols
            .find_closest_symbol_for_address(self.debugger.current_dtb(), addr)
        {
            Some((module, sym, offset)) => {
                let label = format_symbol_with_offset(&module, &sym, offset);
                println!("{}  {}\n", ui::addr(addr.0), ui::symbol(&label));
                // $0 = the symbol's base address (the resolved target)
                self.debugger
                    .set_results(vec![(addr - offset as u64).0], self.line.clone());
            }
            None => {
                println!("no symbol found for {}\n", ui::addr(addr.0));
            }
        }

        Ok(())
    }

    pub fn cmd_ev(&mut self, parts: &[&str]) -> Result<()> {
        if parts.is_empty() {
            println!(
                "{}\n",
                ReplCommand::Ev.get_message().unwrap_or("invalid usage")
            );
            return Ok(());
        }

        let expr_str = if parts.len() > 2 {
            parts[1..].join(" ")
        } else {
            parts[1].to_string()
        };

        match Expr::eval(&expr_str, self.debugger) {
            Ok(addr) => {
                self.debugger.set_results(vec![addr.0], self.line.clone());
                println!("{}", ui::addr(addr.0));
            }
            Err(e) => error!("{}", e),
        }

        Ok(())
    }

    pub fn cmd_set(&mut self, parts: &[&str]) -> Result<()> {
        // set $<name> <expression>
        let rest = parts[1..].join(" ");
        let Some((lhs, rhs)) = rest.split_once(char::is_whitespace) else {
            error!("usage: set $<name> <expression>");
            return Ok(());
        };
        let name = lhs.trim().strip_prefix('$').unwrap_or(lhs.trim()).trim();
        // names must start with a letter or '_'; this reserves
        // $<digits> (and digit-leading names) for the $0..$N
        // result slots, avoiding any collision
        let valid = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            error!(
                "invalid variable name '${}' (must start with a letter or '_'; $<digits> are reserved for result slots)",
                name
            );
            return Ok(());
        }
        let source = rhs.trim().to_string();
        match Expr::eval(&source, self.debugger) {
            Ok(v) => {
                self.debugger
                    .user_vars
                    .insert(name.to_string(), UserVar { value: v.0, source });
                println!("${} = {}\n", name, ui::addr(v.0));
            }
            Err(e) => error!("{}", e),
        }

        Ok(())
    }

    pub fn cmd_vars(&mut self, _parts: &[&str]) -> Result<()> {
        let builtins = self.debugger.builtin_variables();
        if self.debugger.user_vars.is_empty()
            && self.debugger.results.is_empty()
            && builtins.is_empty()
        {
            println!("no variables defined\n");
            return Ok(());
        }
        let mut names: Vec<&String> = self.debugger.user_vars.keys().collect();
        names.sort();
        if !names.is_empty() {
            println!("{}", ui::label("user:"));
            for name in names {
                let var = &self.debugger.user_vars[name];
                println!(
                    "  ${:<16} {}   {}",
                    name,
                    ui::addr(var.value),
                    ui::muted(&var.source)
                );
            }
        }
        if !self.debugger.results.is_empty() {
            if !self.debugger.user_vars.is_empty() {
                println!();
            }
            let origin = self
                .debugger
                .results_origin
                .as_deref()
                .map(|cmd| format!("from: {}", cmd))
                .unwrap_or_default();
            println!(
                "  {}   {}",
                ui::muted(&format!("$0..${}", self.debugger.results.len() - 1)),
                ui::muted(&origin)
            );
        }
        if !builtins.is_empty() {
            if !self.debugger.user_vars.is_empty() || !self.debugger.results.is_empty() {
                println!();
            }
            println!("{}", ui::label("builtins:"));
            for var in builtins {
                println!(
                    "  ${:<16} {}   {}",
                    var.name,
                    ui::addr(var.value),
                    ui::muted(var.source)
                );
            }
        }
        println!();

        Ok(())
    }

    pub fn cmd_unset(&mut self, parts: &[&str]) -> Result<()> {
        let Some(arg) = parts.get(1) else {
            error!("usage: unset $<name>");
            return Ok(());
        };
        let name = arg.strip_prefix('$').unwrap_or(arg);
        if self.debugger.user_vars.remove(name).is_some() {
            println!("unset ${}\n", name);
        } else {
            error!("no such variable: ${}", name);
        }

        Ok(())
    }
}
