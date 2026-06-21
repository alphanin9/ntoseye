use crate::repl::*;

const ALIAS_RECURSION_LIMIT: usize = 16;

mod breakpoints;
mod exec;
mod inspect;
mod memory;
mod meta;
mod process;
mod symbols;

impl ReplState<'_> {
    pub fn dispatch_line(&mut self, line: &str) -> Result<Flow> {
        self.dispatch_line_inner(line, 0)
    }

    fn dispatch_line_inner(&mut self, line: &str, depth: usize) -> Result<Flow> {
        let commands = match split_command_list(line) {
            Ok(commands) => commands,
            Err(err) => {
                report_command_parse_error(line, err);
                return Ok(Flow::Continue);
            }
        };

        for command in commands {
            match self.dispatch_one(command, depth)? {
                Flow::Quit => return Ok(Flow::Quit),
                Flow::Continue => {}
            }
            self.caches.refresh_expression_context(&self.ctx.target);
        }
        Ok(Flow::Continue)
    }

    fn dispatch_one(&mut self, line: &str, depth: usize) -> Result<Flow> {
        let parsed = match parse_command(line) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Ok(Flow::Continue),
            Err(err) => {
                report_command_parse_error(line, err);
                return Ok(Flow::Continue);
            }
        };

        if let Some(spec) = command_registry().get(parsed.name) {
            if !check_run_state(self, spec) {
                return Ok(Flow::Continue);
            }
            match spec.handler {
                CommandHandler::NoArgs(handler) => {
                    if !parsed.raw_tail.trim().is_empty() {
                        println!("{}\n", command_help(parsed.name));
                        return Ok(Flow::Continue);
                    }
                    handler(self)?;
                }
                CommandHandler::Args(handler) => {
                    let invocation = match parsed.invocation(spec.style) {
                        Ok(invocation) => invocation,
                        Err(err) => {
                            report_command_parse_error(line, err);
                            return Ok(Flow::Continue);
                        }
                    };
                    handler(self, invocation)?;
                }
            }
            return Ok(spec.flow);
        }

        let invocation = match parsed.invocation(CommandStyle::StructuredArgs) {
            Ok(invocation) => invocation,
            Err(err) => {
                report_command_parse_error(line, err);
                return Ok(Flow::Continue);
            }
        };

        match self.aliases.expand(invocation.name, &invocation.argv) {
            Ok(Some(expanded)) => {
                if depth >= ALIAS_RECURSION_LIMIT {
                    error!("alias expansion limit reached");
                    return Ok(Flow::Continue);
                }
                return self.dispatch_line_inner(&expanded, depth + 1);
            }
            Ok(None) => {}
            Err(err) => {
                error!("{}", err);
                return Ok(Flow::Continue);
            }
        }

        self.cmd_user(invocation)?;
        Ok(Flow::Continue)
    }
}
