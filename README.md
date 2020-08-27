# Tezos dissector

## Build

### Debug

$ cargo build

### Release

$ cargo build --release

## Install

Copy `libtezos_dissector.so` from the directory `target/debug/` or 
`target/release/` into the directory where Wireshark searches for its plugins.

On Linux, Wireshark 3.2 expects its plugins to be in 
`~/.local/lib/wireshark/plugins/3.2/epan/`. See 
https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html 
for more details.

The script `install.rs` copies the plugin into the proper directory on Linux.
To be able to run it, install `cargo-script`

$ cargo install cargo-script

And so: `./install.rs debug` or `sudo ./install.rs release`.

## Run

In order to see decrypted messages, specify the identity file 
`wireshark -o tezos.identity_json_file:path/to/identity.json` or 
`tshark -o tezos.identity_json_file:path/to/identity.json`

## Debug

The debug version of wireshark is in the `target/out/` directory,
its sources are in the `wireshark/` directory.
In order to capture traffic with the debug version, you need to
run `setcap` on executable `target/out/bin/dumpcap`.
See `setcap.sh` script for details.

The log will be in `target/log.txt`.

## Test

The directory `tests/` contains some shell scripts that perform tests.
They should run from the root directory of the workspace,
`./tests/basic_connection_message.sh`.
