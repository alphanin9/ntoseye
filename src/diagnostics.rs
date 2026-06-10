use std::fmt::Display;

use owo_colors::OwoColorize;

pub fn print_error(message: impl Display) {
    print_labeled_stderr(
        "error:",
        &"error:".bright_red().bold().to_string(),
        &message.to_string(),
    );
}

pub fn print_warning(message: impl Display) {
    print_labeled_stdout(
        "warning:",
        &"warning:".bright_magenta().bold().to_string(),
        &message.to_string(),
    );
}

pub fn eprint_warning(message: impl Display) {
    print_labeled_stderr(
        "warning:",
        &"warning:".bright_magenta().bold().to_string(),
        &message.to_string(),
    );
}

fn print_labeled_stdout(label: &str, styled_label: &str, message: &str) {
    for line in labeled_lines(label, styled_label, message) {
        println!("{line}");
    }
}

fn print_labeled_stderr(label: &str, styled_label: &str, message: &str) {
    for line in labeled_lines(label, styled_label, message) {
        eprintln!("{line}");
    }
}

fn labeled_lines(label: &str, styled_label: &str, message: &str) -> Vec<String> {
    let mut lines = message.lines();
    let Some(first) = lines.next() else {
        return vec![styled_label.to_string()];
    };

    let indent = " ".repeat(label.len() + 1);
    let mut out = vec![format!("{styled_label} {first}")];
    out.extend(lines.map(|line| format!("{indent}{line}")));
    out
}
