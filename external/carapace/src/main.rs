use std::io::{self, Write};

/// Defines whether the output stays on the current line or moves to a new one.
pub enum ShellMode {
    InPlace,
    NewLine,
}

pub struct Carapace {
    tag: String,
}

impl Carapace {
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
    pub fn shield(&self, message: &str, mode: ShellMode) {
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

fn main() {
    let logger = Carapace::new("CARAPACE-CORE");

    // Static log
    logger.shield("Initializing <mag>Shell Protocol</mag>...", ShellMode::NewLine);

    // In-place update loop
    for i in 0..=50 {
        let status = if i < 25 { "<red>Hardening</red>" } else { "<cyan>Finalizing</cyan>" };
        logger.shield(
            &format!("Layer integrity: {}% | Status: {}", i * 2, status),
            ShellMode::InPlace
        );
        
        std::thread::sleep(std::time::Duration::from_millis(40));
    }

    // Wrap up
    logger.shield("\n<green>System fully armored.</green>", ShellMode::NewLine);
}


