//! A simple HTTP client for requesting timestamps from a timestamp authority (TSA) using the [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) standard.
//!
//! # Examples
//!
//! The following code can be used, if you already have a SHA digest of the data you want to timestamp:
//!
//! ```rust
//! use tsp_http_client::request_timestamp_for_digest;
//! # use std::fs::File;
//! # use std::io::prelude::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The URI of a timestamp authority (TSA) that supports RFC 3161 timestamps.
//! let tsa_uri = "http://timestamp.sectigo.com/qualified";
//!
//! // The SHA-256 digest of the data to be timestamped (can also be different SHA lengths like SHA-512).
//! let digest = "00e3261a6e0d79c329445acd540fb2b07187a0dcf6017065c8814010283ac67f";
//!
//! // Request a timestamp for the given digest from the TSA (retrieving a TimeStampResponse object).
//! let timestamp = request_timestamp_for_digest(tsa_uri, digest)?;
//!
//! // The content of the timestamp response can be written to a file then for example.
//! File::create("timestamp-response.tsr")?.write_all(&timestamp.as_der_encoded())?;
//!
//! // Or the date and time of the timestamp can be accessed.
//! println!("Timestamped date and time: {}", timestamp.datetime()?);
//! # Ok(())
//! # }
//! ```
//!
//! Alternatively, the crate can calculate the digest on the content of a file:
//!
//! ```rust
//! use tsp_http_client::request_timestamp_for_file;
//! # use std::fs::File;
//! # use std::io::prelude::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The URI of a timestamp authority (TSA) that supports RFC 3161 timestamps.
//! let tsa_uri = "http://timestamp.sectigo.com/qualified";
//!
//! // The file that should be timestamped.
//! let filename = "README.md";
//!
//! // Request a timestamp for the given digest from the TSA (retrieving a TimeStampResponse object).
//! let timestamp = request_timestamp_for_file(tsa_uri, filename)?;
//!
//! // The content of the timestamp response can be written to a file then for example.
//! File::create("timestamp-response.tsr")?.write_all(&timestamp.as_der_encoded())?;
//!
//! // Or the date and time of the timestamp can be accessed.
//! println!("Timestamped date and time: {}", timestamp.datetime()?);
//! # Ok(())
//! # }
//! ```
//!
//! # Verification with OpenSSL
//! Signature verification is not (yet) included in this crate. You can, however, verify the timestamp response using
//! OpenSSL if you wrote its DER encoding into a file, as shown in the example above.
//!
//! ```bash
//! openssl ts -verify -digest 00e3261a6e0d79c329445acd540fb2b07187a0dcf6017065c8814010283ac67f -in timestamp-response.tsr -CAfile tsa-cert.pem
//! ```
//! The `tsa-cert.pem` file must contain the full certificate chain of the timestamp authority (TSA) that issued the
//! timestamp.

mod tsp;

use sha2::{self, Digest};
use std::{fs::File, io::Read};
use tsp::TimeStampRequest;
pub use tsp::TimeStampResponse;

/// Specific error values of the TSP HTTP client.
#[derive(Debug)]
pub enum Error {
    /// The provided digest is none of SHA-224, SHA-256, SHA-384, or SHA-512.
    InvalidDigest,

    /// The timestamp request was not accepted by the server.
    RequestNotAccepted(Option<String>),

    /// The response from the server is not as expected according to the RFC 3161 standard.
    InvalidServerResponse,

    /// The timestamped digest does not match the provided digest.
    DigestMismatch,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidDigest => write!(
                f,
                "The provided digest is none of SHA-224, SHA-256, SHA-384, or SHA-512"
            ),
            Error::RequestNotAccepted(details) => {
                // If details are provided, add them to the generic error message; otherwise, use an empty string.
                let details = details
                    .clone()
                    .map_or(String::from(""), |s| format!(": {}", s));
                write!(
                    f,
                    "Timestamp request was not accepted by the server{}",
                    details
                )
            }
            Error::InvalidServerResponse => write!(
                f,
                "The response from the server is not as expected according to the RFC 3161 standard."
            ),
            Error::DigestMismatch => write!(
                f,
                "The timestamped digest does not match the provided digest"
            ),
        }
    }
}

/// Requests a timestamp for the given digest from the specified URI of a timestamp authority (TSA).
///
/// * `tsa_uri`: The URI of the timestamp authority.
/// * `digest`: The SHA-224, SHA-256, SHA-384, or SHA-512 digest of the data to be timestamped, represented as a hexadecimal string.
pub fn request_timestamp_for_digest(
    tsa_uri: &str,
    digest: &str,
) -> Result<TimeStampResponse, Box<dyn std::error::Error>> {
    // Create a timestamp request for the given digest.
    let data = hex::decode(digest).or(Err(Error::InvalidDigest))?;
    request_timestamp(tsa_uri, data)
}

/// Requests a timestamp for the given file from the specified URI of a timestamp authority (TSA).
///
/// A SHA-256 digest is calculated on the file content and the timestamp is then requested for this digest.
///
/// * `tsa_uri`: The URI of the timestamp authority.
/// * `filename`: The filename (including relative or absolute path) for which the timestamp should be requested.
pub fn request_timestamp_for_file(
    tsa_uri: &str,
    filename: &str,
) -> Result<TimeStampResponse, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut file_content = vec![];
    file.read_to_end(&mut file_content)?;

    let digest = sha2::Sha256::digest(file_content);
    request_timestamp(tsa_uri, digest.to_vec())
}

/// Internal helper function that does the actual requesting of a timestamp based on a digest.
///
/// It contains the common code for the two external functions to request a timestamp for a digest or for a file.
///
/// * `tsa_uri`: The URI of the timestamp authority.
/// * `digest`: The SHA-224, SHA-256, SHA-384, or SHA-512 digest of the data to be timestamped, represented as an array of bytes.
fn request_timestamp(
    tsa_uri: &str,
    digest: Vec<u8>,
) -> Result<TimeStampResponse, Box<dyn std::error::Error>> {
    let timestamp_request = TimeStampRequest::new(digest)?;

    let body = ureq::post(tsa_uri)
        .header("Content-Type", "application/timestamp-query")
        .send(timestamp_request.to_der()?)?
        .body_mut()
        .read_to_vec()?;

    let timestamp = TimeStampResponse::new(body);
    timestamp.verify(&timestamp_request)?;

    Ok(timestamp)
}
