# Tezos dissector

## Build and install on Ubuntu

Install Rust nightly:

```
$ sudo apt install curl
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup install nightly-2020-07-12 && rustup default nightly-2020-07-12
```

Wireshark version 3.2 required. If you run Ubuntu 19.10 or older, most likely the version is lower, so you need to add wireshark repository manually.

```
$ sudo apt install software-properties-common
$ sudo add-apt-repository ppa:wireshark-dev/stable
$ sudo apt update
```

And then install wireshark and other build dependencies:

```
$ sudo apt install pkg-config clang make wireshark wireshark-dev termshark
```

Check the version  `wireshark -v`, it should be 3.2, and run the command in tezos-dissector directory:

```
$ cargo build --release
```

It will produce `target/debug/libtezos_dissector.so`. 

In order to install it, run the script:

```
$ ./install-3.2-linux.sh
```

It not require super user permissions and just create directory `~/.local/lib/wireshark/plugins/3.2/epan/` and copy the `libtezos_dissector.so` in it. You can do it manually.

## On macOS

Install Rust nightly:

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup install nightly-2020-07-12 && rustup default nightly-2020-07-12
```

Install Homebrew if it is not installed:

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

Install termshark:

```
$ brew install termshark
```

Make sure the termshark has version 3.2: `tshark -v`. Also check if wireshark accessible for pkg-config: `pkg-config --cflags wireshark` it should print some clang flags. If it does not, check `brew link wireshark` maybe you need to force it with `brew link --overwrite wireshark`. In such case, see what is installed via brew `brew leaves` and try to delete unnecessary packages and fix you environment.

The wireshark installed by brew is dependency of termshark, but it just provides headers for building. To be able to run wireshark UI, install .dmg file from its download page https://www.wireshark.org/download/osx/.

Build the tezos-dissector by running the command in tezos-dissector directory:

```
$ cargo build --release
```

It will produce `target/debug/libtezos_dissector.dylib`. 

In order to install it, run the script:

```
$ ./install-3.2-macos.sh
```

Or manually copy the file `libtezos_dissector.dylib` in `/Applications/Wireshark.app/Contents/PlugIns/wireshark/3-2/epan/` and rename it to be `.so`.

## Running

The plugin is useless if the identity file is not provided, specify the file when run the wireshark:

```
wireshark -o tezos.identity_json_file:path/to/identity.json
```

Or you can specify the identity file when wireshark is running. In menu File -> Preferences -> Advanced -> tezos.
