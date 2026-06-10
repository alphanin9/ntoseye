use std::str::FromStr;

use crate::repl::*;

mod breakpoints;
mod exec;
mod inspect;
mod memory;
mod meta;
mod process;
mod symbols;

impl ReplState<'_> {
    pub fn dispatch(&mut self, parts: &[&str]) -> Result<Flow> {
        let cmd_str = parts[0];
        match ReplCommand::from_str(cmd_str) {
            Ok(ReplCommand::Quit) => return Ok(Flow::Quit),
            Ok(ReplCommand::Pte) => self.cmd_pte(parts)?,
            Ok(ReplCommand::Pool) => self.cmd_pool(parts)?,
            Ok(ReplCommand::Vmmap) => self.cmd_vmmap(parts)?,
            Ok(ReplCommand::Db) => self.cmd_db(parts)?,
            Ok(ReplCommand::Dd) => self.cmd_dd(parts)?,
            Ok(ReplCommand::Dq) => self.cmd_dq(parts)?,
            Ok(ReplCommand::Disasm) => self.cmd_disasm(parts)?,
            Ok(ReplCommand::Eb) => self.cmd_eb(parts)?,
            Ok(ReplCommand::Ed) => self.cmd_ed(parts)?,
            Ok(ReplCommand::Eq) => self.cmd_eq(parts)?,
            Ok(ReplCommand::F) => self.cmd_f(parts)?,
            Ok(ReplCommand::S) => self.cmd_s(parts)?,
            Ok(ReplCommand::X) => self.cmd_x(parts)?,
            Ok(ReplCommand::Ln) => self.cmd_ln(parts)?,
            Ok(ReplCommand::Ev) => self.cmd_ev(parts)?,
            Ok(ReplCommand::Set) => self.cmd_set(parts)?,
            Ok(ReplCommand::Vars) => self.cmd_vars(parts)?,
            Ok(ReplCommand::Unset) => self.cmd_unset(parts)?,
            Ok(ReplCommand::Vcpus) => self.cmd_vcpus(parts)?,
            Ok(ReplCommand::Threads) => self.cmd_threads(parts)?,
            Ok(ReplCommand::Thread) => self.cmd_thread(parts)?,
            Ok(ReplCommand::Continue) => self.cmd_continue(parts)?,
            Ok(ReplCommand::Break) => self.cmd_break(parts)?,
            Ok(ReplCommand::Dt) => self.cmd_dt(parts)?,
            Ok(ReplCommand::Ps) => self.cmd_ps(parts)?,
            Ok(ReplCommand::Drivers) => self.cmd_drivers(parts)?,
            Ok(ReplCommand::Lm) => self.cmd_lm(parts)?,
            Ok(ReplCommand::Attach) => self.cmd_attach(parts)?,
            Ok(ReplCommand::Reload) => self.cmd_reload(parts)?,
            Ok(ReplCommand::Detach) => self.cmd_detach(parts)?,
            Ok(ReplCommand::Registers) => self.cmd_registers(parts)?,
            Ok(ReplCommand::Si) => self.cmd_si(parts)?,
            Ok(ReplCommand::P) => self.cmd_p(parts)?,
            Ok(ReplCommand::Gu) => self.cmd_gu(parts)?,
            Ok(ReplCommand::Vcpu) => self.cmd_vcpu(parts)?,
            Ok(ReplCommand::Bp) => self.cmd_bp(parts)?,
            Ok(ReplCommand::Bl) => self.cmd_bl(parts)?,
            Ok(ReplCommand::Bc) => self.cmd_bc(parts)?,
            Ok(ReplCommand::Bd) => self.cmd_bd(parts)?,
            Ok(ReplCommand::Be) => self.cmd_be(parts)?,
            Ok(ReplCommand::K) => self.cmd_k(parts)?,
            Ok(ReplCommand::Status) => self.cmd_status(parts)?,
            Ok(ReplCommand::Capabilities) => self.cmd_capabilities(parts)?,
            Err(_) => self.cmd_user(cmd_str, parts)?,
        }
        Ok(Flow::Continue)
    }
}
