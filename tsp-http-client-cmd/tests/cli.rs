use assert_cmd::prelude::*; // add methods on commands
use predicates::prelude::*; // used for writing assertions
use std::fs::File;
use std::io::prelude::*;
use std::{path::PathBuf, process::Command}; // run programs
use tempfile::tempdir;

#[test]
fn usage_help_when_no_parameters() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("tsp-http-client-cmd")?;

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage: "));

    Ok(())
}

#[test]
fn request_timestamp_with_digest() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let output_path = temp_dir.path().join("output.tsr");
    let digest = "63db35d3befcbbbb00d740c3128ec5a6bb279b8af00fde6dadb8c9ba75abb8d5".to_owned();

    assert!(!output_path.exists()); // output file must not exist yet

    let mut cmd = Command::cargo_bin("tsp-http-client-cmd")?;
    cmd.arg("--tsa")
        .arg("http://timestamp.sectigo.com/qualified")
        .arg("digest")
        .arg("--output")
        .arg(&output_path)
        .arg(&digest);

    cmd.assert().success();

    assert!(output_path.exists()); // output file must exist after the command was run

    // cryptographically verify the timestamp
    verify_timestamp(&output_path, &digest);

    // ensure that the verify function would actually fail on a different digest
    assert!(
        std::panic::catch_unwind(|| verify_timestamp(&output_path, &digest.replacen("0", "1", 1)))
            .is_err()
    );

    Ok(())
}

#[test]
fn request_timestamp_with_invalid_digest() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("tsp-http-client-cmd")?;
    cmd.arg("digest")
        .arg("--output")
        .arg("output.tsr")
        .arg("to_short_digest");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("The provided digest is none of"));

    Ok(())
}

#[test]
fn request_timestamp_for_file() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let input_path = temp_dir.path().join("input.txt");
    let output_path = temp_dir.path().join("output.tsr");

    let mut file = File::create(&input_path)?;
    file.write_all(b"Hello, world!")?;
    let digest = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"; // SHA-256 sum of that file

    assert!(!output_path.exists()); // output file must not exist yet

    let mut cmd = Command::cargo_bin("tsp-http-client-cmd")?;
    cmd.arg("--tsa")
        .arg("http://timestamp.sectigo.com/qualified")
        .arg("file")
        .arg("--output")
        .arg(&output_path)
        .arg(&input_path);

    cmd.assert().success();

    assert!(output_path.exists()); // output file must exist after the command was run

    verify_timestamp(&output_path, digest);

    Ok(())
}

/// Verifiy given timestamp file with OpenSSL.
fn verify_timestamp(timestamp_file: &PathBuf, digest: &str) {
    let mut cmd = Command::new("openssl");
    cmd.arg("ts")
        .arg("-verify")
        .arg("-digest")
        .arg(digest)
        .arg("-in")
        .arg(&timestamp_file)
        .arg("-CAfile")
        .arg("../tsp-http-client/certs/tsa-sectico.pem");

    cmd.assert().success();
}

#[test]
fn timestamp_batch_requesting() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;

    let input_path_1 = temp_dir.path().join("file_1.txt");
    let output_path_1 = temp_dir.path().join(".file_1.tsr");

    let mut file_1 = File::create(&input_path_1)?;
    file_1.write_all(b"Hello, world!")?;
    let digest_1 = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"; // SHA-256 sum of that file
    drop(file_1);

    let input_path_2 = temp_dir.path().join("file_2.txt");
    let output_path_2 = temp_dir.path().join(".file_2.tsr");

    let mut file_2 = File::create(&input_path_2)?;
    file_2.write_all(b"Another hello!")?;
    let digest_2 = "5507cba739bf1028a55b237aba3eb6351fd006daa6bae32f384d47d534c9528e"; // SHA-256 sum of that file
    drop(file_2);

    let mut cmd = Command::cargo_bin("tsp-http-client-cmd")?;
    cmd.arg("--tsa")
        .arg("http://timestamp.sectigo.com/qualified")
        .arg("batch")
        .arg("--hidden")
        .arg(&temp_dir.path());

    cmd.assert().success();

    verify_timestamp(&output_path_1, digest_1);
    verify_timestamp(&output_path_2, digest_2);

    Ok(())
}
