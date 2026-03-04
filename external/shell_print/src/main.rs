use shell_print::{ShellPrint, ShellMode};

fn main() {
    let logger = ShellPrint::new("CARAPACE-CORE");

    // Static log
    logger.shell_print("Initializing <mag>Shell Protocol</mag>...", ShellMode::NewLine);

    // In-place update loop
    for i in 0..=50 {
        let status = if i < 25 { "<red>Hardening</red>" } else { "<cyan>Finalizing</cyan>" };
        logger.shell_print(
            &format!("Layer integrity: {}% | Status: {}", i * 2, status),
            ShellMode::InPlace
        );
        
        std::thread::sleep(std::time::Duration::from_millis(40));
    }

    // Wrap up
    logger.shell_print("\n<green>System fully armored.</green>", ShellMode::NewLine);
}


