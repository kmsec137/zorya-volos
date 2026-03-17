use std::io::{self, Write};

/// Defines whether the output stays on the current line or moves to a new one.
pub enum ShellMode {
    InPlace,
    NewLine,
}

pub struct ShellPrint {
    tag: String,
}

impl ShellPrint {
    /// Creates a new logger instance with a specific context tag.
    pub fn new(tag: &str) -> Self {
        Self {
            tag: format!("\x1b[1m[{}]\x1b[0m ", tag), // Bold tag for better visibility
        }
    }

    /// Parses custom <color> tags into ANSI escape sequences.
    fn parse_style(&self, input: &str) -> String {
        input
            .replace("<red>", "\x1b[31m")
            .replace("<green>", "\x1b[32m")
            .replace("<blue>", "\x1b[34m")
            .replace("<yellow>", "\x1b[33m")
            .replace("<cyan>", "\x1b[36m")
            .replace("<mag>", "\x1b[35m")
            .replace("</red>", "\x1b[0m")
            .replace("</green>", "\x1b[0m")
            .replace("</blue>", "\x1b[0m")
            .replace("</yellow>", "\x1b[0m")
            .replace("</cyan>", "\x1b[0m")
            .replace("</mag>", "\x1b[0m")
    }

    /// The core printing method.
    pub fn shell_print(&self, message: &str, mode: ShellMode) {
        let content = self.parse_style(message);
        
        match mode {
            ShellMode::InPlace => {
                // \r: Return to start
                // \x1b[K: Clear from cursor to end of line (prevents ghosting)
                print!("\r{}{}\x1b[K", self.tag, content);
            }
            ShellMode::NewLine => {
                println!("{}{}", self.tag, content);
            }
        }
        // Force output to terminal immediately
        let _ = io::stdout().flush();
    }
}

fn print_table(rows: Vec<Vec<String>>) {
    if rows.is_empty() { return; }

    // 1. Determine the maximum number of columns across all rows
    let col_count = rows.iter().map(|row| row.len()).max().unwrap_or(0);
    
    // 2. Calculate the maximum width for each column index
    let mut col_widths = vec![0; col_count];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > col_widths[i] {
                col_widths[i] = cell.len();
            }
        }
    }

    // 3. Print the rows with dynamic padding per column
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            // We use the pre-calculated width for this specific column index
            // Adding a small constant (like 3) creates a gutter between columns
            let width = col_widths[i] + 3;
            print!("{:<width$}", cell, width = width);
        }
        println!(); // Move to the next line after finishing a row
    }
}
