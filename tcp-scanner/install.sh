#!/usr/env bash
set -e
APP_NAME="tcp-scanner"
INSTALL_DIR="/usr/local/bin"
echo "Building the project..."
cargo build --release
echo "Copying to target..."
sudo cp target/release/$APP_NAME $INSTALL_DIR/$APP_NAME
echo "Success! now try running it: tcp-scanner"
