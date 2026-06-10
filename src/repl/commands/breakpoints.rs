use strum::EnumMessage;
use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::expr::Expr;
use crate::ui;

use crate::repl::*;

impl ReplState<'_> {
    fn parse_breakpoint_condition(parts: &[&str]) -> Option<Option<String>> {
        match parts {
            [_cmd, _addr] => Some(None),
            // legacy "if" prefix still accepted
            [_cmd, _addr, "if", rest @ ..] if !rest.is_empty() => Some(Some(rest.join(" "))),
            [_cmd, _addr, rest @ ..] if !rest.is_empty() && rest != ["if"] => {
                Some(Some(rest.join(" ")))
            }
            _ => {
                println!(
                    "{}\n",
                    ReplCommand::Bp.get_message().unwrap_or("invalid usage")
                );
                None
            }
        }
    }

    fn breakpoint_id_arg(parts: &[&str], command: ReplCommand) -> Option<u32> {
        let Some(id_str) = parts.get(1).copied() else {
            println!("{}\n", command.get_message().unwrap_or("invalid usage"));
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

    pub fn cmd_bp(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        // Process-scope BP support is per-backend; the
        // manager returns `Error::NotSupported` for
        // backends that can't honour them.

        let addr_str = require_arg!(parts, 1, ReplCommand::Bp);
        let Some(condition) = Self::parse_breakpoint_condition(parts) else {
            return Ok(());
        };
        let address = match Expr::eval(addr_str, self.debugger) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let symbol = self
            .debugger
            .symbols
            .format_closest_symbol_for_address(self.debugger.current_dtb(), address);

        match self.breakpoints.add(
            &mut *self.client,
            self.debugger,
            address,
            symbol.clone(),
            condition.clone(),
        ) {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.breakpoints);
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
                        self.breakpoints
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

    pub fn cmd_bl(&mut self, _parts: &[&str]) -> Result<()> {
        let bps = self.breakpoints.list();
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
                    format!("{}   ", bp.id),
                    format!("{}  ", status),
                    format!("{}  ", ui::addr(bp.address.0)),
                    format!("{}  ", bp.symbol.as_deref().unwrap_or("-")),
                    format!("{}  ", bp.condition.as_deref().unwrap_or("-")),
                    scope,
                ]);
            }

            print_plain_table(builder);
        }

        Ok(())
    }

    pub fn cmd_bc(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let Some(id) = Self::breakpoint_id_arg(parts, ReplCommand::Bc) else {
            return Ok(());
        };

        match self
            .breakpoints
            .remove(&mut *self.client, self.debugger, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.breakpoints);
                println!("breakpoint {} cleared\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    pub fn cmd_bd(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let Some(id) = Self::breakpoint_id_arg(parts, ReplCommand::Bd) else {
            return Ok(());
        };

        match self
            .breakpoints
            .disable(&mut *self.client, self.debugger, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.breakpoints);
                println!("breakpoint {} disabled\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    pub fn cmd_be(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let Some(id) = Self::breakpoint_id_arg(parts, ReplCommand::Be) else {
            return Ok(());
        };

        match self
            .breakpoints
            .enable(&mut *self.client, self.debugger, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.breakpoints);
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
    use super::ReplState;

    #[test]
    fn breakpoint_condition_parser_keeps_simple_form() {
        assert_eq!(
            ReplState::parse_breakpoint_condition(&["bp", "nt!KeBugCheck"]).unwrap(),
            None
        );
        assert_eq!(
            ReplState::parse_breakpoint_condition(&["bp", "nt!KeBugCheck", "$rax", "==", "1"])
                .unwrap()
                .as_deref(),
            Some("$rax == 1")
        );
        assert_eq!(
            ReplState::parse_breakpoint_condition(&[
                "bp",
                "nt!KeBugCheck",
                "if",
                "$rax",
                "==",
                "1"
            ])
            .unwrap()
            .as_deref(),
            Some("$rax == 1")
        );
        assert!(ReplState::parse_breakpoint_condition(&["bp", "addr", "if"]).is_none());
    }
}
