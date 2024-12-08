use std::io::Write;

use colog::format::CologStyle;
use colored::Colorize;
use env_logger::Builder;
use log::{Level, LevelFilter};

struct LogFormatter;

impl CologStyle for LogFormatter {
    fn format(
        &self,
        buf: &mut env_logger::fmt::Formatter,
        record: &log::Record<'_>,
    ) -> Result<(), std::io::Error> {
        let sep = self.line_separator();
        let prefix = self.prefix_token(&record.level());

        match record.level() {
            Level::Trace => {
                for (idx, line) in record.args().to_string().split('\n').enumerate() {
                    if idx == 0 {
                        write!(buf, "{prefix} ")?;
                    } else {
                        write!(buf, "\n{}", sep)?;
                    }

                    write!(buf, "{}", line.dimmed())?;
                }

                writeln!(buf)?;

                Ok(())
            }
            Level::Error | Level::Info | Level::Warn | Level::Debug => {
                writeln!(
                    buf,
                    "{} {}",
                    prefix,
                    record.args().to_string().replace("\n", &format!("\n{sep}"))
                )
            }
        }
    }

    fn level_token(&self, level: &Level) -> &str {
        match *level {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    fn line_separator(&self) -> String {
        format!("{} ", "   |   ".white().bold())
    }
}

pub fn init(level: u8) {
    Builder::new()
        .format(colog::formatter(LogFormatter))
        .filter(
            Some(&env!("CARGO_PKG_NAME").replace("-", "_")),
            if level > 1 {
                LevelFilter::Trace
            } else if level > 0 {
                LevelFilter::Debug
            } else {
                LevelFilter::Info
            },
        )
        .init();
}

pub fn hexdump(data: &[u8], size: usize, highlights: Vec<(usize, usize)>) {
    if !matches!(log::max_level(), LevelFilter::Trace) {
        return;
    }

    let codes = data
        .iter()
        .map(|c| format!("{c:02x}"))
        .collect::<Vec<String>>();
    let chars = data
        .iter()
        .map(|num| {
            if *num >= 32 && *num <= 126 {
                (*num as char).to_string()
            } else {
                '.'.to_string()
            }
        })
        .collect::<Vec<_>>();

    let mut prefix = "DATA".to_string();
    let codes = codes.chunks(size);
    let chars = chars.chunks(size);

    for (index, (line_codes, line_chars)) in Iterator::zip(codes, chars).enumerate() {
        let mut colored_codes = vec![];
        let offset = index * size;

        for (index, code) in line_codes.iter().enumerate() {
            let mut code = code.white();

            for (start, end) in &highlights {
                let code_index = index + offset;
                if code_index >= *start && code_index < *end {
                    code = code.yellow().bold();
                }
            }

            colored_codes.push(format!("{code}"));
        }

        print!(
            "{}{}{} ",
            "[".blue().bold(),
            prefix.purple().bold(),
            "]".blue().bold()
        );
        print!("{}", colored_codes.join(" "));
        print!("{}", " ".repeat((size - colored_codes.len()) * 3));
        print!(" {} ", "|".dimmed());
        println!("{}", line_chars.join(" ").blue());

        prefix = format!("0x{:02x}", size * (index + 1));
    }
}
