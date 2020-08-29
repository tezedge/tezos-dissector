# Tezos dissector

## Build on ubuntu

#### Rust nightly

```
$ sudo apt install curl
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup install nightly-2020-07-12 && rustup default nightly-2020-07-12
```

#### Wireshark

Wireshark version 3.2 required. If you run Ubuntu 19.10 or older, most likely the version is lower, so you need to add wireshark repository manually.

```
$ sudo apt install software-properties-common
$ sudo add-apt-repository ppa:wireshark-dev/stable
$ sudo apt update
```

And then install the packages:

```
$ sudo apt install wireshark wireshark-dev termshark
```

Check the version: `wireshark -v`.

#### Release build dependencies

```
$ sudo apt install pkg-config clang make
```

#### Debug build dependencies

Additionally to previous

```
$ sudo apt install git cmake flex bison libgcrypt-dev qttools5-dev qtmultimedia5-dev libqt5svg5-dev
```

## Build on macOS

#### Release

Install Homebrew if it is not installed:

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

Install nightly Rust and termshark.

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup install nightly-2020-07-12 && rustup default nightly-2020-07-12
$ brew install termshark
```

Make sure the termshark has version 3.2: `tshark -v`

Also download and install the wireshark 3.2 from its download page https://www.wireshark.org/download/osx/.

#### Debug

Additionally install

```
$ brew install cmake qt5
```

## Release build
```
$ cargo build --release
```

## Debug build
```
$ cargo build
```

Note: for debug purposes it builds wireshark in the project directory and install it in `target/out/`.

## Install

Copy `libtezos_dissector.so` from the directory `target/debug/` or `target/release/` into the directory where Wireshark searches for its plugins.

On Linux, Wireshark 3.2 expects its plugins to be in `~/.local/lib/wireshark/plugins/3.2/epan/`. See https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html for more details.

The script will install release version of plugin of Wireshark 3.2 on linux:

```
$ ./install-3.2-linux.sh
```

On macOS:

```
$ ./install-3.2-macos.sh
```

## Run

In order to see decrypted messages, specify the identity file 

```
wireshark -o tezos.identity_json_file:path/to/identity.json
```

or

```
tshark -o tezos.identity_json_file:path/to/identity.json
```

## Debug

The debug version of wireshark is in the `target/out/` directory, its sources are in the `wireshark/` directory. In order to capture traffic with the debug version, you need to run `setcap` on executable `target/out/bin/dumpcap`. See `setcap.sh` script for details.

The log will be in `target/log.txt`.

## Test

The directory `tests/` contains some shell scripts that perform tests. They should run from the root directory of the workspace, `./tests/basic_connection_message.sh`.
