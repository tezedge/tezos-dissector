# Tezos dissector

## Build

### Debug

$ cargo build

### Release

$ cargo build --release

## Install

Copy `libtezos_dissector.so` from directory `target/debug/` or 
`target/release/` into directory where Wireshark searching its plugins.

On Linux Wireshark 3.2 expecting its plugins in 
`~/.local/lib/wireshark/plugins/3.2/epan/`. See 
https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html 
for more details.

The script `install.rs` copy plugin into proper directory on Linux.
To be able to run it, install `cargo-script`

$ cargo install cargo-script

And so: `./install.rs debug` or `./install.rs release`.

## Run

In order to see decrypted messages, specify identity file 
`wireshark -o tezos.identity_json_file:path/to/identity.json` or 
`tshark -o tezos.identity_json_file:path/to/identity.json`

## Debug

The debug version of wireshark is in `target/out/` directory,
its sources are in `wireshark/` directory.

Log: `target/log.txt`

## Test

Directory `tests/` contains some shell scripts that do tests.
They should run from the root of the workspace,
`./tests/basic_connection_message.sh`.
