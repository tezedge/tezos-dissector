# Tezos dissector

For a developer who is working directly with a blockchain node, it is very useful to be able to view the traffic of data that moves through the network. However, as a blockchain network is cryptographically secured, we had to develop a method for the interception and analysis of the encrypted communication. For this purpose, we’ve chosen to create a so-calleddissector for Wireshark.

Wireshark is a utility that intercepts packets (messages) that arrive via the network card. It uses special plugins known as dissectors to analyze the intercepted packets. 

This readme file is a guide on how to build, install and use the Tezos dissector.

## Build and install

### Preparation

#### Update Wireshark

The minimum required version of Wireshark is `3.0`. Check the version by typing and entering `wireshark -v`. Update Wireshark if needed.

On Ubuntu, update the Wireshark by running these commands:

```
sudo apt install software-properties-common
sudo add-apt-repository ppa:wireshark-dev/stable
sudo apt update
sudo apt install wireshark termshark
```

On MacOS, download the dmg file from https://www.wireshark.org/download/osx/ and install.

#### Install Rust

Curl is required for this step. Install unless you already have it. On Ubuntu, run `sudo apt install curl` to install it.

Run the following to install the proper version of Rust.

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install nightly-2020-07-12 && rustup default nightly-2020-07-12
source ~/.cargo/env
```

#### Get the source code

Git is required for this step. On Ubuntu, run `sudo apt install git` to install it.

Clone the repository in the directory where you want it.

```
git clone https://github.com/simplestaking/tezos-dissector.git
cd tezos-dissector
```

Now that the shell is in the directory where the sources are, you are ready to build and install. If you, for some reason, close this terminal and open it again, make sure you change the dir in tezos-dissector directory `cd tezos-dissector`.

### Install

You can choose one of three methods for building and installing the Tezos Wireshark dissector: 

* Build from sources. This will give the latest plugin, but it might be too complicated for a beginner user. This readme has instructions for Ubuntu 20.04 and MacOS. If you use another platform and are not sure, consider using another method.
* Build in Docker. It requires docker to be installed and running. This method is not available on MacOS.
* Install from previously built binary. This is the easiest method.

### Build from sources and install on Ubuntu 20.04

Install build dependencies:

```
sudo apt install pkg-config clang make wireshark-dev
```

Try `pkg-config --cflags wireshark` to check if Wireshark headers are accessible. It should print some flags: `-I/.../include/wireshark ...`.

Build and install:

```
cargo build --release
cargo run -p wireshark-epan-adapter --bin install --release
```

### Build from sources and install on macOS

Install Homebrew (if it is not installed already):

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

Install Termshark:

```
$ brew install termshark
```

Check if wireshark is accessible for pkg-config: `pkg-config --cflags wireshark` it should print some clang flags. If it does not, check `brew link wireshark`, it is possible that you need to force it with `brew link --overwrite wireshark`. In this case, see what is installed via brew `brew leaves` and try to delete unnecessary packages and fix your environment.

Check the version: `wireshark -v`, and `tshark -v` the major and minor versions should match, the micro version and git commit might not match, but that is not a problem.

Build the tezos-dissector and install it by running these commands in the tezos-dissector directory:

```
$ cargo build --release
$ cargo run -p wireshark-epan-adapter --bin install --release
```

### Build a plugin in Docker and install

Run the following:

```
$ cargo run -p prebuilt --release -- -d
```

### Install prebuilt plugin

This command will determine your OS and Wireshark version, and install a prebuilt plugin binary:

```
$ cargo run -p prebuilt --release
```

## Running

### Important rules

* Provide the `identity.json` file before you start a capturing session.
* Start a capturing session before the Tezos node is running. 
* Do not restart the node during the capturing session. If you need to restart node, stop the capturing session -> restart the node -> start a new capturing session.

*Warning:* they are very important, the plugin will not be able to decrypt the traffic if any of these rules are violated.

#### Checking

Check if the plugin works, go to the menu, View -> Internals -> Supported Protocols, search for 'tezos', it should be in the list.

![s0](doc/Screenshot_0.png "Check")

#### Identity

The plugin is useless if the identity file is not provided. Specify the file when running Wireshark:

```
wireshark -o tezos.identity_json_file:path/to/identity.json
```

Alternatively, you can specify the identity file in the UI when wireshark is running. Go to the menu Edit -> Preferences -> Advanced -> tezos.

![s1](doc/Screenshot_1.png "Identity")

#### Capturing session

In Ubuntu, run the following to get the ability to capture traffic.

```
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER
```



