use crate::error::Result;
#[cfg(feature = "python")]
use crate::python::embed;

use crate::repl::*;

impl ReplState<'_> {
    #[cfg_attr(not(feature = "python"), allow(unused_variables, unused_mut))]
    pub fn cmd_reload(&mut self, _parts: &[&str]) -> Result<()> {
        #[cfg(feature = "python")]
        {
            let py_report = embed::load_commands_dir();
            embed::print_script_load_report(&py_report, false);
            *self.caches.user_commands.write().unwrap() = initial_user_commands();
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "python"), allow(unused_variables))]
    pub fn cmd_user(&mut self, cmd_str: &str, parts: &[&str]) -> Result<()> {
        #[cfg(feature = "python")]
        if embed::has_command(cmd_str) {
            let args: Vec<&str> = parts.iter().skip(1).copied().collect();
            if let Err(e) = embed::dispatch(cmd_str, &args, self.ctx) {
                error!("{}: {}", cmd_str, e);
            }
            return Ok(());
        }

        println!(
            "unknown command: '{}' (try pressing tab to see available commands)\n",
            cmd_str
        );

        Ok(())
    }
}
