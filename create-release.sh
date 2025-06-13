#!/bin/bash -e

cd "$(dirname "$0")" # Make sure to be in the directory where the script is located

# Ask for the version number of the release
echo -n "Version: "
read -r VERSION

# Install the cargo release plugin if it is not yet installed
if ! cargo --list | grep -q release; then cargo install cargo-release; fi

# Do the release with the "cargo release" command
cargo release -p tsp-http-client --sign "$@" "$VERSION"