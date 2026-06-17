use tabled::builder::Builder;
use tabled::settings::Padding;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::expr::Expr;
use crate::session::split_condition_operator;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_bp;
    names: ["bp"],
    usage: "bp <address> [<expr>]",
    summary: "Set a breakpoint.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_bl();
    names: ["bl"],
    usage: "bl",
    summary: "List all breakpoints.",
}

repl_command! {
    cmd_bc;
    names: ["bc"],
    usage: "bc <id>",
    summary: "Clear a breakpoint by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_bd;
    names: ["bd"],
    usage: "bd <id>",
    summary: "Disable a breakpoint by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_be;
    names: ["be"],
    usage: "be <id>",
    summary: "Enable a breakpoint by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

fn breakpoint_condition(
    invocation: &CommandInvocation<'_>,
) -> Result<Option<String>> {
    if invocation.argv.len() <= 1 {
        return Ok(None);
    }
    let condition = invocation.join_args(1);
    validate_breakpoint_condition(&condition)?;
    Ok(Some(condition))
}

fn validate_breakpoint_condition(condition: &str) -> Result<()> {
    if let Some((left, _op, right)) = split_condition_operator(condition) {
        Expr::parse(left)?;
        Expr::parse(right)?;
    } else {
        Expr::parse(condition)?;
    }
    Ok(())
}

impl ReplState<'_> {
    fn breakpoint_id_arg(invocation: &CommandInvocation<'_>, command: &str) -> Option<u32> {
        let Some(id_str) = invocation.arg(0) else {
            println!("{}\n", command_help(command));
            return None;
        };

        match id_str.parse() {
            Ok(id) => Some(id),
            Err(_) => {
                error!("invalid breakpoint ID: {}", id_str);
                None
            }
        }
    }

    fn cmd_bp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        // Process-scope BP support is per-backend; the
        // manager returns `Error::NotSupported` for
        // backends that can't honour them.

        let addr_str = require_arg!(invocation, 0, "bp");
        let condition = match breakpoint_condition(&invocation) {
            Ok(condition) => condition,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let address = match Expr::eval(addr_str, &self.ctx.target) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let symbol = self
            .ctx
            .target
            .symbols
            .format_closest_symbol_for_address(self.ctx.target.current_dtb(), address);

        match self.ctx.breakpoints.add(
            &mut *self.ctx.backend,
            &self.ctx.target,
            address,
            symbol.clone(),
            condition.clone(),
        ) {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                let condition_label = condition
                    .as_ref()
                    .map(|condition| format!(" if {condition}"))
                    .unwrap_or_default();
                println!(
                    "breakpoint {} set at {}{}{}{}\n",
                    ui::bp_id(id),
                    ui::addr(address.0),
                    symbol
                        .map(|s| format!(" ({})", s))
                        .unwrap_or_default()
                        .green(),
                    condition_label.bright_black(),
                    format!(
                        " ({})",
                        self.ctx
                            .breakpoints
                            .list()
                            .into_iter()
                            .find(|bp| bp.id == id)
                            .map(|bp| bp.scope.label())
                            .unwrap_or_else(|| "global".to_string())
                    )
                    .bright_black()
                );
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_bl(&mut self) -> Result<()> {
        let bps = self.ctx.breakpoints.list();
        if bps.is_empty() {
            println!("no breakpoints set\n");
        } else {
            let mut builder = Builder::default();
            builder.push_record(vec![
                "ID".to_string(),
                "Status".to_string(),
                "Address".to_string(),
                "Symbol".to_string(),
                "Condition".to_string(),
                "Scope".to_string(),
            ]);

            for bp in bps {
                let status = if bp.enabled { "enabled" } else { "disabled" };
                let scope = bp.scope.label();

                builder.push_record(vec![
                    bp.id.to_string(),
                    status.to_string(),
                    ui::addr(bp.address.0),
                    bp.symbol.as_deref().unwrap_or("-").to_string(),
                    bp.condition.as_deref().unwrap_or("-").to_string(),
                    scope,
                ]);
            }

            let mut table = builder.build();
            table
                .with(tabled::settings::Style::empty())
                .with(Padding::new(0, 2, 0, 0));
            println!("{table}\n");
        }

        Ok(())
    }

    fn cmd_bc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bc") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .remove(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} cleared\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_bd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bd") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .disable(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} disabled\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_be(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "be") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .enable(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} enabled\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    fn bp_invocation<'a>(argv: &'a [&'a str]) -> CommandInvocation<'a> {
        CommandInvocation {
            name: "bp",
            argv: argv.iter().copied().map(Cow::Borrowed).collect(),
            raw_tail: "",
        }
    }

    #[test]
    fn breakpoint_condition_accepts_comparison_tail() {
        let invocation = bp_invocation(&["nt!Foo", "$rax", "==", "1"]);

        assert_eq!(
            breakpoint_condition(&invocation).unwrap().as_deref(),
            Some("$rax == 1")
        );
    }

    #[test]
    fn breakpoint_condition_rejects_malformed_tail() {
        let invocation = bp_invocation(&["nt!Foo", "$rax", "=="]);

        assert!(breakpoint_condition(&invocation).is_err());
    }
}
