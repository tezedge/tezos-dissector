# Tezos dissector  

This readme file is a guide on how to build, install and use the Tezos dissector.

As we wanted to expand Wireshark’s functionalities for the Tezos protocol, we had to develop a new dissector.  

A dissector is a module used to analyze a particular protocol. Each dissector decodes its part of the protocol and then hands off decoding to subsequent dissectors for an encapsulated protocol.

We have created the wireshark-epan-adapter, a small abstraction layer that wraps the unsafe C-like API for plugins in a safe Rust API. This library connects Wireshark with the tezos-dissector and enables us to write a dissector in Rust. The tezos-dissector is compiled as a dynamic library. Wireshark loads this library when it is launched. 

## Architecture overview

As a Tezos network is cryptographically secured, we had to design a mechanism with which the Tezos dissector could analyze the encrypted communication.

Since we’re attempting to read messages sent across an encrypted network, we must find a way to decrypt this communication. This is done by intercepting the initial ‘handshake’ message that nodes sent each other when initiating communication. The handshake message contains a nonce, which is a random incrementing number, and a pair of keys (private and public). You can read more about this process in our past article about the Tezos P2P layer. 

Due to the nature of this mechanism, **it is crucial to run Wireshark before launching the Tezos node.** Otherwise, the handshake message cannot be intercepted, making it impossible to decrypt the communication.

The Tezos dissector operates by extracting the nonce and the public key from the intercepted handshake message and then using them to decrypt subsequent messages.  Once decrypted, they are stored in memory. When a user clicks on a particular packet (row in the UI), the corresponding message is deserialized and then displayed in the Wireshark UI.


## Prerequisites

#### 1. Update Wireshark

The minimum required version of Wireshark is `3.0`. Check the version by typing and entering `wireshark -v`. Update Wireshark if needed.

On Ubuntu, update the Wireshark by running these commands:

```
sudo apt install software-properties-common
sudo add-apt-repository ppa:wireshark-dev/stable
sudo apt update
sudo apt install wireshark termshark
```

On MacOS, download the dmg file from https://www.wireshark.org/download/osx/ and install.

#### 2. Install Rust

Curl is required for this step. Install unless you already have it. On Ubuntu, run `sudo apt install curl` to install it.

Run the following to install the proper version of Rust.

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install nightly-2020-07-12 && rustup default nightly-2020-07-12
source ~/.cargo/env
```

#### 3. Get the source code

Git is required for this step. On Ubuntu, run `sudo apt install git` to install it.

Clone the repository in the directory where you want it.

```
git clone https://github.com/simplestaking/tezos-dissector.git
cd tezos-dissector
```

Now that the shell is in the directory where the sources are, you are ready to build and install. If you, for some reason, close this terminal and open it again, make sure you change the dir in tezos-dissector directory `cd tezos-dissector`.

## Build and install

You can choose one of two methods for building and installing the Tezos Wireshark dissector: 

* Install from Pre-built Binaries. This is the easiest method.
* Build from sources. This readme has instructions for Ubuntu 20.04 and MacOS. 

### Install from Pre-built Binaries

This command will determine your OS and Wireshark version, and install a prebuilt plugin binary:

```
cargo run -p prebuilt --release
```

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

### Build from sources and install on MacOS

Install Homebrew (if it is not installed already):

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

Install Termshark:

```
brew install termshark
```

Check if wireshark is accessible for pkg-config: `pkg-config --cflags wireshark` it should print some clang flags. If it does not, check `brew link wireshark`, it is possible that you need to force it with `brew link --overwrite wireshark`. In this case, see what is installed via brew `brew leaves` and try to delete unnecessary packages and fix your environment.

Check the version: `wireshark -v`, and `tshark -v` the major and minor versions should match, the micro version and git commit might not match, but that is not a problem.

Build the tezos-dissector and install it by running these commands in the tezos-dissector directory:

```
cargo build --release
cargo run -p wireshark-epan-adapter --bin install --release
```


## Running

### Important rules

* Provide the `identity.json` file before you start a capturing session.
* Start a capturing session before the Tezos node is running. 
* Do not restart the node during the capturing session. If you need to restart node, stop the node -> restart the capturing session -> start the node.

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



