use std::env;
use std::process;
use zorya::fuzzer::{FuzzerConfig, FuzzerRunner};

fn print_usage() {
    println!("ZORYA FUZZER - Automated Concolic Execution Test Campaign");
    println!();
    println!("Usage:");
    println!("  zorya-fuzzer-main <config.json>          Run fuzzer with configuration file");
    println!("  zorya-fuzzer-main --create-example <path> Create example configuration file");
    println!("  zorya-fuzzer-main --help                  Show this help message");
    println!();
    println!("Configuration File Format:");
    println!("  The JSON configuration file should contain:");
    println!("    - global: Global settings (language, compiler, binary path, etc.)");
    println!("    - tests: Array of test configurations with start addresses and arguments");
    println!();
    println!("Example:");
    println!("  zorya-fuzzer-main fuzzer_config.json");
    println!("  zorya-fuzzer-main --create-example example_config.json");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Error: Missing configuration file argument");
        println!();
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "--help" | "-h" => {
            print_usage();
            process::exit(0);
        }
        "--create-example" => {
            if args.len() < 3 {
                eprintln!("Error: Missing output path for example configuration");
                process::exit(1);
            }
            let output_path = &args[2];
            match FuzzerConfig::create_example(output_path) {
                Ok(_) => {
                    println!("[OK] Example configuration created: {}", output_path);
                    println!("  Edit this file with your binary path and test configurations");
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Error creating example configuration: {}", e);
                    process::exit(1);
                }
            }
        }
        config_path => {
            // Load and validate configuration
            let config = match FuzzerConfig::from_file(config_path) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!("Error loading configuration file: {}", e);
                    process::exit(1);
                }
            };

            if let Err(e) = config.validate() {
                eprintln!("Configuration validation failed: {}", e);
                process::exit(1);
            }

            println!("[OK] Configuration loaded and validated");
            println!();

            // Create and run fuzzer
            let runner = match FuzzerRunner::new(config) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error creating fuzzer runner: {}", e);
                    process::exit(1);
                }
            };

            let results = match runner.run_all() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error during fuzzer execution: {}", e);
                    process::exit(1);
                }
            };

            // Write summary report
            if let Err(e) = runner.write_summary_report(&results) {
                eprintln!("Warning: Failed to write summary report: {}", e);
            }

            // Exit with appropriate code
            let all_successful = results.iter().all(|r| r.success);
            if all_successful {
                println!("[OK] All tests completed successfully");
                process::exit(0);
            } else {
                println!("[WARNING] Some tests failed or timed out");
                process::exit(1);
            }
        }
    }
}

