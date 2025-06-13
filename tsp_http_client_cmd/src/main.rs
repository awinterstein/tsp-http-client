use clap::{ArgGroup, Parser};
use std::fs::File;
use std::io::prelude::*;

///Simple HTTP client for requesting timestamps from a timestamp authority (TSA) using the RFC 3161 standard.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, group(
    ArgGroup::new("input_group")
        .args(&["file", "digest"])
        .required(true)
))]
struct Args {
    /// The filename of the data that should be timestamped. Either this or --digest is needed.
    #[arg(short, long)]
    file: Option<String>,

    /// The SHA digest of the data to be timestamped, represented as a hexadecimal string. Either this or --file is needed.
    #[arg(short, long)]
    digest: Option<String>,

    /// The output file where the timestamp will be written in ASN.1 DER format.
    #[arg(short, long)]
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse(); // Parse the command line arguments
    let tsa_uri = "http://timestamp.sectigo.com/qualified";

    // Request a timestamp for the given digest or given file (one parameter must be set as defined in clap)
    let timestamp = match args.digest {
        Some(_) => tsp_http_client::request_timestamp_for_digest(tsa_uri, &args.digest.unwrap()),
        None => tsp_http_client::request_timestamp_for_file(tsa_uri, &args.file.unwrap()),
    }
    .or_else(|e| Err(format!("{}", e)))?;

    // Write the timestamp bytes to the specified output file
    File::create(args.output)?.write_all(&timestamp.as_der_encoded())?;

    let signed_time = timestamp.datetime().or_else(|e| Err(format!("{}", e)))?;
    print!("Data was signed at: {:?}", signed_time);

    Ok(())
}
