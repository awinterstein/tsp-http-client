# Time Stamping Protocol (TSP) HTTP Client

A simple HTTP client for requesting timestamps from a timestamp authority (TSA) using the [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) standard.

## Examples

The following code can be used, if you already have a SHA digest of the data you want to timestamp:

```rust
use tsp_http_client::request_timestamp_for_digest;

// The URI of a timestamp authority (TSA) that supports RFC 3161 timestamps.
let tsa_uri = "http://timestamp.sectigo.com/qualified";

// The SHA-256 digest of the data to be timestamped (can also be different SHA lengths like SHA-512).
let digest = "00e3261a6e0d79c329445acd540fb2b07187a0dcf6017065c8814010283ac67f";

// Request a timestamp for the given digest from the TSA (retrieving a TimeStampResponse object).
let timestamp = request_timestamp_for_digest(tsa_uri, digest)?;

// The content of the timestamp response can be written to a file then for example.
File::create("timestamp-response.tsr")?.write_all(&timestamp.as_der_encoded())?;

// Or the date and time of the timestamp can be accessed.
println!("Timestamped date and time: {}", timestamp.datetime()?);
```

Alternatively, the crate can calculate the digest on the content of a file:

```rust
use tsp_http_client::request_timestamp_for_file;

// The URI of a timestamp authority (TSA) that supports RFC 3161 timestamps.
let tsa_uri = "http://timestamp.sectigo.com/qualified";

// The file that should be timestamped.
let filename = "README.md";

// Request a timestamp for the given digest from the TSA (retrieving a TimeStampResponse object).
let timestamp = request_timestamp_for_file(tsa_uri, filename)?;

// The content of the timestamp response can be written to a file then for example.
File::create("timestamp-response.tsr")?.write_all(&timestamp.as_der_encoded())?;

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
