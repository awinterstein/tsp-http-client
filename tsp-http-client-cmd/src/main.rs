use clap::{Parser, Subcommand};
use std::io::prelude::*;
use std::path::Path;
use std::thread::sleep;
use std::{fs::File, time::Duration};
use walkdir::{DirEntry, WalkDir};

///Simple HTTP client for requesting timestamps from a timestamp authority (TSA) using the RFC 3161 standard.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// URI of the timestamp authority (TSA) to use.
    #[arg(long, default_value = "http://timestamp.sectigo.com/qualified")]
    tsa: String,

    /// Disables console output
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Request timestamp for the given SHA digest.
    Digest {
        /// The SHA digest of the data to be timestamped, represented as a hexadecimal string.
        digest: String,

        /// The output file where the timestamp will be written in ASN.1 DER format.
        #[arg(short, long)]
        output: String,
    },

    /// Request timestamp for the given file.
    File {
        /// The filename of the data that should be timestamped.
        filename: String,

        /// The output file where the timestamp will be written in ASN.1 DER format.
        #[arg(short, long)]
        output: String,
    },

    /// Request timestamp for all files in the given directory.
    Batch {
        /// Timestamps are requested for all files in this directory and its sub-directories.
        directory: String,

        /// How many milliseconds two wait before requesting the next timestamp. Needed according to the terms of some timestamp authorities.
        #[arg(short, long)]
        delay: Option<u64>,

        /// Whether the output files should be created as hidden files (prefixed with '.')
        #[arg(long)]
        hidden: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Digest { digest, output } => {
            let timestamp = tsp_http_client::request_timestamp_for_digest(&cli.tsa, digest)
                .or_else(|e| Err(format!("{}", e)))?;

            // Write the timestamp bytes to the specified output file
            File::create(output)?.write_all(&timestamp.as_der_encoded())?;
        }

        Commands::File { filename, output } => {
            let timestamp = tsp_http_client::request_timestamp_for_file(&cli.tsa, filename)
                .or_else(|e| Err(format!("{}", e)))?;

            // Write the timestamp bytes to the specified output file
            File::create(output)?.write_all(&timestamp.as_der_encoded())?;
        }

        Commands::Batch {
            directory,
            delay,
            hidden,
        } => {
            fn is_tsr(entry: &DirEntry) -> bool {
                entry
                    .file_name()
                    .to_str()
                    .map(|s| s.ends_with(".tsr"))
                    .unwrap_or(false)
            }

            // File names need to be prefixed with '.' if files are supposed to be hidden
            let prefix = if *hidden { "." } else { "" };

            // Define once iterator with no content (for not doing a sleep once)
            let mut no_delay_once = core::iter::once(None::<()>);

            for entry in WalkDir::new(directory)
                .into_iter()
                .filter_entry(|e| !is_tsr(e))
            {
                let entry = entry?;
                let timestamp_path = format!(
                    "{}{}{}{}{}",
                    entry.path().parent().unwrap().display(),
                    "/",
                    prefix,
                    entry.path().file_stem().unwrap().display(),
                    ".tsr"
                );

                if entry.file_type().is_file() && !Path::new(&timestamp_path).exists() {
                    // Do a sleep if the iterator is exhausted (one time without sleep was already)
                    no_delay_once.next().unwrap_or(Some(())).inspect(|_| {
                        delay.inspect(|delay| sleep(Duration::from_millis(*delay)));
                    });

                    let timestamp = tsp_http_client::request_timestamp_for_file(
                        &cli.tsa,
                        &entry.path().to_str().unwrap(),
                    )
                    .or_else(|e| Err(format!("{}", e)))?;

                    // Write the timestamp bytes to the corresponding output file
                    File::create(timestamp_path)?.write_all(&timestamp.as_der_encoded())?;

                    if !cli.quiet {
                        let signed_time =
                            timestamp.datetime().or_else(|e| Err(format!("{}", e)))?;
                        println!(
                            "File '{}' was signed at: {:?}",
                            entry.path().display(),
                            signed_time
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
