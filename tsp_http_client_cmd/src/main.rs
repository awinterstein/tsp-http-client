use clap::Parser;
use std::fs::File;
use std::io::prelude::*;

///Simple HTTP client for requesting timestamps from a timestamp authority (TSA) using the RFC 3161 standard.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The SHA digest of the data to be timestamped, represented as a hexadecimal string.
    #[arg(short, long)]
    digest: String,

    /// The output file where the timestamp will be written in ASN.1 DER format.
    #[arg(short, long)]
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse(); // Parse the command line arguments

    // Request a timestamp for the given digest
    let timestamp =
        tsp_http_client::request_timestamp("http://timestamp.sectigo.com/qualified", &args.digest)
            .or_else(|e| Err(format!("{}", e)))?;

    // Write the timestamp bytes to the specified output file
    File::create(args.output)?.write_all(&timestamp.as_der_encoded())?;

    let signed_time = timestamp.datetime().or_else(|e| Err(format!("{}", e)))?;
    print!("Data was signed at: {:?}", signed_time);

    Ok(())
}
