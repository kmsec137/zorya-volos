use std::io::{self, Write};
use std::thread;
use std::time::Duration;
//use rand::Rng; 

mod console_carapace {
    use std::io::{self, Write};

    pub struct ConsoleCarapace {
        memory_stats: Vec<u64>,
        chunks: usize,
    }

    impl ConsoleCarapace{
        pub fn new(lines: usize) -> Self {
            Self {
                memory_stats: vec![0; lines],
                chunks: lines,
            }
        }

        pub fn record_interaction(&mut self, address: u32) {
            // Use u64 to prevent overflow when calculating 4GB range
            let total_range = (u32::MAX as u64) + 1;
            let chunk_size = total_range / self.chunks as u64;
            let index = (address as u64 / chunk_size) as usize;
            
            if index < self.chunks {
                self.memory_stats[index] += 1;
            }
        }

        pub fn render(&self, hex_addr: u32, hex_data: &[u8], event: &str) {
            // ANSI: \x1b[2J clears screen, \x1b[H moves cursor to top-left
            print!("\x1b[2J\x1b[H");

            println!("\x1b[1;36m ZORYA-VOLOS | 4GB PROCESS MEMORY MAP\x1b[0m");
            println!("{}", "━".repeat(70));

            for i in 0..self.chunks {
                let total_range = (u32::MAX as u64) + 1;
                let start_addr = i as u64 * (total_range / self.chunks as u64);
                
                let hits = self.memory_stats[i];
                let (glyph, color) = match hits {
                    0 => ("░", "\x1b[2m"),       // Dim
                    1..=5 => ("▒", "\x1b[34m"),   // Blue
                    6..=15 => ("▓", "\x1b[33m"),  // Yellow
                    _ => ("█", "\x1b[31m"),       // Red
                };

                let mut line = format!("0x{:08X} [{}{}{}\x1b[0m]", start_addr, color, glyph, color);

                // UI Logic for the Right Pane
                match i {
                    2 => line.push_str("   \x1b[1;33m[ LIVE DATA FEED ]\x1b[0m"),
                    3 => {
                        let hex_row: String = hex_data.iter().map(|b| format!("{:02X} ", b)).collect();
                        line.push_str(&format!("   0x{:08X}: {}", hex_addr, hex_row));
                    },
                    4 => {
                        // is_ascii_graphic() checks if a byte is a printable character
                        let ascii: String = hex_data.iter()
                            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                            .collect();
                        line.push_str(&format!("                | {} |", ascii));
                    },
                    7 => line.push_str(&format!("   \x1b[1mLAST EVENT:\x1b[0m \x1b[32m{}\x1b[0m", event)),
                    8 if hits > 15 => line.push_str("   \x1b[5;31m!! HIGH LOAD DETECTED !!\x1b[0m"),
                    _ => {}
                }

                println!("{}", line);
            }
            let _ = io::stdout().flush();
        }
    }
}
fn main() {
    let mut monitor = console_carapace::ConsoleCarapace::new(25);
    let mut iteration: u32 = 0;

    // Hide cursor
    print!("\x1b[?25l"); 
    let _ = io::stdout().flush();

    loop {
        let hot_zone: u32 = 0x40000000; 
        
        for _ in 0..10 {
            // FIX: Using the direct function instead of the method
            // This avoids the 'gen' keyword conflict entirely
            let addr: u32 = rand::random(); 
            monitor.record_interaction(addr);
        }
        
        // Bias some hits to the hot zone
        monitor.record_interaction(hot_zone.wrapping_add(iteration % 0xFFFF));

        // Generate fake hex data
        let mut fake_hex = [0u8; 8];
        // FIX: Using the direct fill function
        rand::fill(&mut fake_hex);

        let events = ["READ", "WRITE", "EXEC", "SYSCALL"];
        let current_event = events[(iteration as usize) % events.len()];

        monitor.render(0xDEADC0DE_u32.wrapping_add(iteration), &fake_hex, current_event);

        iteration = iteration.wrapping_add(1);
        thread::sleep(Duration::from_millis(150));

        if iteration > 500 { break; } 
    }

    print!("\x1b[?25h"); // Show cursor again
    println!("\nMonitor session ended.");
}
