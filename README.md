# Tezos dissector

## Build and install

### Preparation

#### Update Wireshark

Minimal required version of the Wireshark is `3.0`. Check the version `wireshark -v`. Update the Wireshark if needed.

On Ubuntu update the Wireshark running the commands:

```
sudo apt install software-properties-common
sudo add-apt-repository ppa:wireshark-dev/stable
sudo apt update
sudo apt install wireshark termshark
```

On macOS download dmg file from https://www.wireshark.org/download/osx/ and install.

#### Install Rust

Curl is required for this step. Most likely you already have it. On Ubuntu run `sudo apt install curl` to install it.

Run the following to install the proper version of Rust.

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install nightly-2020-07-12 && rustup default nightly-2020-07-12
source ~/.cargo/env
```

#### Get the source code

Git is required for this step, on Ubuntu run `sudo apt install git` to install it.

Clone the repository in the directory where you want.

```
git clone https://github.com/simplestaking/tezos-dissector.git
cd tezos-dissector
```

Now the shell is in directory where the sources are. Ready to build and install. If you, for some reason, close this terminal and open again, make sure you are change dir in tezos-dissector directory `cd tezos-dissector`.

### Install

There are three alternative methods to install the plugin. Only any one of them needed.

* Build from sources. It will give the latest plugin. But it might be problematic for the beginner user. This readme has instruction for Ubuntu 20.04 and macOS. If you use another platform and are not sure, consider to use another method.
* Build in docker. It requires docker to be installed and running. This method not available on macOS.
* Install previously built binary. Simplest method.

### Build from sources and install on Ubuntu 20.04

Install build dependencies:

```
sudo apt install pkg-config clang make wireshark-dev
```

Try `pkg-config --cflags wireshark` to check if wireshark headers are accessible. It should print some flags: `-I/.../include/wireshark ...`.

Build and install:

```
cargo build --release
cargo run -p wireshark-epan-adapter --bin install --release
```

### Build from sources and install on macOS

Install Homebrew if it is not installed:

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

Install termshark:

```
$ brew install termshark
```

Check if wireshark accessible for pkg-config: `pkg-config --cflags wireshark` it should print some clang flags. If it does not, check `brew link wireshark` maybe you need to force it with `brew link --overwrite wireshark`. In such case, see what is installed via brew `brew leaves` and try to delete unnecessary packages and fix your environment.

Check the version: `wireshark -v`, and `tshark -v` the major and minor versions should match, the micro version and git commit might not match it is ok.

Build the tezos-dissector and install it by running the commands in tezos-dissector directory:

```
$ cargo build --release
$ cargo run -p wireshark-epan-adapter --bin install --release
```

### Build plugin in docker and install

Just run this:

```
$ cargo run -p prebuilt --release -- -d
```

### Install prebuilt plugin

This command will determine your OS and Wireshark version, and install prebuilt plugin binary:

```
$ cargo run -p prebuilt --release
```

## Running

### Important rules

* Provide the `identity.json` file before start capturing session.
* Start capturing session before the tezos node run. 
* Do not restart node during capturing session. If you need to restart node, stop the capturing session -> restart the node -> start new capturing.

*Warning:* they are very important, the plugin will not able to decrypt the traffic if any of this rule violated.

#### Checking

Check if the plugin works, go to menu View -> Internals -> Supported Protocols, search 'tezos' it should be in list.

![s0](doc/Screenshot_0.png "Check")

#### Identity

The plugin is useless if the identity file is not provided, specify the file when run the wireshark:

```
wireshark -o tezos.identity_json_file:path/to/identity.json
```

Or you can specify the identity file in UI when wireshark is running. In menu Edit -> Preferences -> Advanced -> tezos.

![s1](doc/Screenshot_1.png "Identity")

#### Capturing session

In Ubuntu run the following to get ability to capture traffic.

```
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER
```
