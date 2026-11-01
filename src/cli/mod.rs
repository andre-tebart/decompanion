//! The command line: argument parsing (args.rs), the commands (commands.rs: each refreshes or builds the target,
//! then prints what the core returns), and the glue every command shares (glue.rs: opening the project, the rule
//! refresh, the build). Output contract: one record per line, key=value tokens, addresses 0x%08x, intervals lo..hi
//! (hi exclusive), sorted by address, counts before lists; --json gives the same records as JSON lines.
//!
//! `run` is the whole command in this process; the daemon calls it per request with writers that stream the output
//! back to the client.

pub mod args;
pub(crate) mod commands;
mod glue;
#[cfg(test)]
mod tests;

use crate::error::Error;
use clap::Parser;
use std::io::Write;

/// The two output streams of a command.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

impl Io<'_> {
    /// A line on stdout.
    pub fn say(&mut self, line: &str) {
        let _ = writeln!(self.out, "{line}");
    }

    /// A line on stderr.
    pub fn warn(&mut self, line: &str) {
        let _ = writeln!(self.err, "{line}");
    }

    /// Print a command's lines, its error to stderr as `dcp CMD: error`; the exit code.
    pub fn report(&mut self, cmd: &str, lines: &[String], error: Option<&str>, code: i32) -> i32 {
        for l in lines {
            self.say(l);
        }
        if let Some(e) = error.filter(|e| !e.is_empty()) {
            self.warn(&format!("dcp {cmd}: {e}"));
        }
        code
    }
}

/// Run one command line (argv[0] is the program) in this process: the exit code.
pub fn run(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    crate::timing::reset();
    crate::fsmemo::new_epoch();
    let mut io = Io { out, err };
    let code = match args::Cli::try_parse_from(argv) {
        Err(e) => {
            let text = e.render().to_string();
            if e.use_stderr() {
                let _ = write!(io.err, "{text}");
            } else {
                let _ = write!(io.out, "{text}");
            }
            e.exit_code()
        }
        Ok(cli) => match commands::dispatch(&mut io, cli) {
            Ok(code) => code,
            Err(Error::Config(m)) | Err(Error::Rule(m)) => {
                io.warn(&format!("dcp: {m}"));
                2
            }
            Err(e) => {
                io.warn(&format!("dcp: {e}"));
                1
            }
        },
    };
    crate::fsmemo::flush();
    if let Some(t) = crate::timing::report() {
        io.warn(&t);
    }
    let _ = io.out.flush();
    let _ = io.err.flush();
    code
}
