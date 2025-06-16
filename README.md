# Time Stamping Protocol (TSP) HTTP Client

A simple HTTP client for requesting timestamps from a timestamp authority (TSA) using the [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) standard.

## Examples

The following code can be used, if you already have a SHA digest of the data you want to timestamp:

```rust
use tsp_http_client::request_timestamp_for_digest;

// The URI of a timestamp authority (TSA) that supports RFC 3161 timestamps.
let tsa_uri = "http://timestamp.digicert.com";

// The SHA-256 digest of the data to be timestamped (can also be different SHA lengths like SHA-512).
let digest = "00e3261a6e0d79c329445acd540fb2b07187a0dcf6017065c8814010283ac67f";

// Request a timestamp for the given digest from the TSA (retrieving a TimeStampResponse object).
let timestamp = request_timestamp_for_digest(tsa_uri, digest)?;

// The content of the timestamp response can be written to a file then for example.
File::create("/tmp/timestamp-response.tsr")?.write_all(&timestamp.as_der_encoded())?;

// Or the date and time of the timestamp can be accessed.
println!("Timestamped date and time: {}", timestamp.datetime()?);
```

Alternatively, the crate can calculate the digest on the content of a file:

```rust
use tsp_http_client::request_timestamp_for_file;

// The URI of a timestamp authority (TSA) that supports RFC 3161 timestamps.
let tsa_uri = "http://timestamp.digicert.com";

// The file that should be timestamped.
let filename = "README.md";

// Request a timestamp for the given digest from the TSA (retrieving a TimeStampResponse object).
let timestamp = request_timestamp_for_file(tsa_uri, filename)?;

// The content of the timestamp response can be written to a file then for example.
File::create("/tmp/timestamp-response.tsr")?.write_all(&timestamp.as_der_encoded())?;

// Or the date and time of the timestamp can be accessed.
println!("Timestamped date and time: {}", timestamp.datetime()?);
```

## Verification with OpenSSL
Signature verification is not (yet) included in this crate. You can, however, verify the timestamp response using
OpenSSL if you wrote its DER encoding into a file, as shown in the example above.

```bash
openssl ts -verify -digest 00e3261a6e0d79c329445acd540fb2b07187a0dcf6017065c8814010283ac67f -in timestamp-response.tsr -CAfile tsa-cert.pem
```
The `tsa-cert.pem` file must contain the full certificate chain of the timestamp authority (TSA) that issued the
timestamp.

## Command Line Application

This repository also contains a command line application for requesting timestamps from a timestamp authority. It supports the following parameters:

```
Simple HTTP client for requesting timestamps from a timestamp authority (TSA) using the RFC 3161 standard

Usage: tsp-http-client-cmd [OPTIONS] <COMMAND>

Commands:
  digest  Request timestamp for the given SHA digest
  file    Request timestamp for the given file
  batch   Request timestamp for all files in the given directory
  help    Print this message or the help of the given subcommand(s)

Options:
      --tsa <TSA>  URI of the timestamp authority (TSA) to use [default: http://timestamp.sectigo.com/qualified]
  -q, --quiet      Disables console output
  -h, --help       Print help
  -V, --version    Print version
