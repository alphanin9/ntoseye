use crate::error::Result;

use crate::repl::*;

impl ReplState<'_> {
    pub fn cmd_reload(&mut self, _parts: &[&str]) -> Result<()> {
        self.script_host.reset();
        let report = self
            .script_host
            .load_all(&self.builtin_names, Some(self.debugger));
        print_script_load_report(&report, false);
        *self.caches.user_commands.write().unwrap() = self.script_host.command_names();

        Ok(())
    }

    pub fn cmd_user(&mut self, cmd_str: &str, parts: &[&str]) -> Result<()> {
        if self.script_host.has(cmd_str) {
            let args: Vec<&str> = parts.iter().skip(1).copied().collect();
            if let Err(e) = self.script_host.dispatch(
                cmd_str,
                &args,
                self.debugger,
                &mut *self.client,
                &self.register_map,
            ) {
                error!("{}: {}", cmd_str, e);
            }
        } else {
            println!(
                "unknown command: '{}' (try pressing tab to see available commands)\n",
                cmd_str
            );
        }

        Ok(())
    }
}
