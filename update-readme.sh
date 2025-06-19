#!/bin/bash -e

cd "$(dirname "$0")" # Make sure to be in the main directory of the repository

# Install the cargo readme plugin if it is not yet installed
if ! cargo --list | grep -q readme; then cargo install cargo-readme; fi

# Generate README from the crate documentation
pushd "tsp-http-client" >/dev/null
cargo readme > README.md
cp README.md ../README.md
popd >/dev/null


## Add documentation for the command line application to the README
cat << 'EOF' >> README.md

## Command Line Application

This repository also contains a command line application for requesting timestamps from a timestamp authority. It supports the following parameters:

```
EOF

cargo run -- --help >> README.md
