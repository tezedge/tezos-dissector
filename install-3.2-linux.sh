#!/usr/bin/env bash

mkdir -p ~/.local/lib/wireshark/plugins/3.2/epan/
cp target/release/libtezos_dissector.so ~/.local/lib/wireshark/plugins/3.2/epan/
