mod fulldump_patch;

use std::path::PathBuf;
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: Drag and drop RobloxStudioBeta.exe onto this executable, or run:");
        eprintln!("  {} <path_to_RobloxStudioBeta.exe>", args[0]);
        std::process::exit(1);
    }

    let input_path = PathBuf::from(&args[1]);

    if !input_path.exists() {
        eprintln!("Error: File not found at {}", input_path.display());
        std::process::exit(1);
    }

    let mut output_path = input_path.clone();
    let stem = input_path.file_stem()
        .expect("Invalid filename")
        .to_string_lossy()
        .to_string();
    let extension = input_path.extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    
    output_path.set_file_name(format!("{}_FULLDUMP{}", stem, extension));

    println!("Input:  {}", input_path.display());
    println!("Output: {}", output_path.display());

    let input_data = fs::read(&input_path).expect("Failed to read input file");

    match fulldump_patch::patch_full_dump(input_data, &output_path) {
        Ok(_) => println!(
            "\nSuccess! Test with: \"{}\" fullapi Full-API-Dump.json",
            output_path.display()
        ),
        Err(e) => {
            eprintln!("\nPatch failed: {}", e);
            std::process::exit(1);
        }
    }
}